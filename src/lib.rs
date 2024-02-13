mod error;

use crate::error::Error::{Http, Keyring, Shell, TokenRequest, Unauthenticated};
use crate::error::Result;
use keyring::Entry;
use log::{error, info, warn};
use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, CsrfToken, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use regex::Regex;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::multipart::{Form, Part};
use reqwest::{header, Client};
use serde::{Deserialize, Serialize};
use tauri::async_runtime::Mutex;
use tauri::{
    api::shell::open,
    plugin::{Builder, TauriPlugin},
    AppHandle, Manager, Runtime,
};

#[derive(Debug)]
struct ActiveRequestState {
    pkce_challenge: PkceCodeChallenge,
    pkce_verifier: Option<PkceCodeVerifier>,
    csrf_token: CsrfToken,
}

impl ActiveRequestState {
    pub fn new() -> ActiveRequestState {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        ActiveRequestState {
            pkce_challenge,
            pkce_verifier: Some(pkce_verifier),
            csrf_token: CsrfToken::new_random(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserState {
    pub name: String,
    pub profile_id: Option<u64>,
    pub steam_id: u64,
}

#[derive(Debug)]
struct PluginState {
    oauth_client: BasicClient,
    access_token: Entry,
    request: Mutex<Option<ActiveRequestState>>,
    http_client: Mutex<Option<Client>>,
    user: Mutex<Option<UserState>>,
}

impl PluginState {
    pub fn new(client_id: String, redirect_uri: String) -> Result<PluginState> {
        let oauth_client = BasicClient::new(
            ClientId::new(client_id),
            None,
            AuthUrl::new("https://cohdb.com/oauth/authorize".to_string()).unwrap(),
            Some(TokenUrl::new("https://cohdb.com/oauth/token".to_string()).unwrap()),
        )
        .set_redirect_uri(RedirectUrl::new(redirect_uri).unwrap());
        let access_token = Entry::new("cohdb", "access_token").map_err(Keyring)?;
        let http_client = if let Ok(token) = access_token.get_password() {
            info!("found token in keyring, creating client");
            Some(build_client(&token)?)
        } else {
            info!("no token found in keyring, user not connected to cohdb");
            None
        };

        Ok(PluginState {
            oauth_client,
            access_token,
            request: Mutex::new(None),
            http_client: Mutex::new(http_client),
            user: Mutex::new(None),
        })
    }
}

#[tauri::command]
async fn authenticate<R: Runtime>(handle: AppHandle<R>) -> Result<()> {
    let state = handle.state::<PluginState>();
    let request = ActiveRequestState::new();

    let (auth_url, _) = state
        .oauth_client
        .authorize_url(|| request.csrf_token.clone())
        .add_scope(Scope::new("read".to_string()))
        .add_scope(Scope::new("write".to_string()))
        .set_pkce_challenge(request.pkce_challenge.clone())
        .url();

    *state.request.lock().await = Some(request);

    info!("redirecting to auth URL: {auth_url}");
    open(&handle.shell_scope(), auth_url, None).map_err(Shell)
}

pub async fn retrieve_token<R: Runtime>(request: &str, handle: &AppHandle<R>) -> Result<()> {
    let state = handle.state::<PluginState>();
    let re =
        Regex::new(r"coh3stats://cohdb.com/oauth/authorize\?code=(?<code>.+)&state=(?<state>.+)")
            .unwrap();
    let Some(caps) = re.captures(request) else {
        warn!("got invalid deeplink: {request}");
        set_focus(handle);
        return Ok(());
    };

    if let Some(mut request_state) = handle.state::<PluginState>().request.lock().await.take() {
        set_focus(handle);

        let token = handle
            .state::<PluginState>()
            .oauth_client
            .exchange_code(AuthorizationCode::new(caps["code"].to_string()))
            .set_pkce_verifier(request_state.pkce_verifier.take().unwrap())
            .request_async(async_http_client)
            .await
            .map_err(|err| TokenRequest(format!("{err}")))?;

        state.access_token.delete_password().ok();
        state
            .access_token
            .set_password(token.access_token().secret())
            .map_err(Keyring)?;

        let client = build_client(token.access_token().secret())?;

        let user = client
            .get("https://cohdb.com/api/v1/users/me")
            .send()
            .await
            .map_err(Http)?
            .json::<UserState>()
            .await
            .map_err(Http)?;

        info!("retrieved user: {:?}", user);

        *state.http_client.lock().await = Some(client);
        *state.user.lock().await = Some(user.clone());

        handle.emit_all("cohdb:connection", user).unwrap();
    }

    Ok(())
}

pub async fn is_connected<R: Runtime>(handle: AppHandle<R>) -> Option<UserState> {
    let state = handle.state::<PluginState>();
    let user_option = state.user.lock().await;
    user_option.clone()
}

#[tauri::command]
async fn connected<R: Runtime>(handle: AppHandle<R>) -> Result<Option<UserState>> {
    Ok(is_connected(handle).await)
}

#[tauri::command]
async fn disconnect<R: Runtime>(handle: AppHandle<R>) -> Result<()> {
    let state = handle.state::<PluginState>();
    match state.access_token.delete_password() {
        Ok(_) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(err) => Err(Keyring(err)),
    }?;

    *state.http_client.lock().await = None;
    *state.user.lock().await = None;

    handle
        .emit_all("cohdb:connection", None::<UserState>)
        .unwrap();

    Ok(())
}

pub async fn upload<R: Runtime>(
    data: Vec<u8>,
    file_name: String,
    handle: AppHandle<R>,
) -> Result<()> {
    let state = handle.state::<PluginState>();
    let client_option = state.http_client.lock().await;
    let client = client_option.as_ref().ok_or(Unauthenticated)?;

    let form = Form::new()
        .text("replay[public]", "false")
        .part("replay[file]", Part::bytes(data).file_name(file_name));
    let _response = client
        .post("https://cohdb.com/api/v1/replays/upload")
        .multipart(form)
        .send()
        .await
        .map_err(Http)?;
    Ok(())
}

pub fn init<R: Runtime>(client_id: String, redirect_uri: String) -> TauriPlugin<R> {
    Builder::new("cohdb")
        .invoke_handler(tauri::generate_handler![
            authenticate,
            connected,
            disconnect,
        ])
        .setup(|app| {
            match PluginState::new(client_id, redirect_uri) {
                Ok(state) => {
                    app.manage(state);

                    let app_ = app.clone();
                    tauri::async_runtime::spawn(async move {
                        let state = app_.state::<PluginState>();
                        let client_option = state.http_client.lock().await;
                        if let Some(client) = client_option.as_ref() {
                            let user = client
                                .get("https://cohdb.com/api/v1/users/me")
                                .send()
                                .await
                                .unwrap()
                                .json::<UserState>()
                                .await
                                .unwrap();

                            info!("got user on init: {:?}", user);

                            *state.user.lock().await = Some(user);
                        } else {
                            info!("not connected, skipping user query");
                        }
                    });
                }
                Err(err) => {
                    error!("failed to init state: {err}");
                }
            }

            Ok(())
        })
        .build()
}

fn set_focus<R: Runtime>(handle: &AppHandle<R>) {
    for (_, val) in handle.windows().iter() {
        val.set_focus().ok();
    }
}

fn build_client(secret: &String) -> Result<Client> {
    let mut headers = HeaderMap::new();
    let mut auth = HeaderValue::try_from(format!("Bearer {}", secret)).unwrap();
    auth.set_sensitive(true);
    headers.insert(header::AUTHORIZATION, auth);

    Client::builder()
        .default_headers(headers)
        .build()
        .map_err(Http)
}
