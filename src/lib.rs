mod error;

use crate::error::Error::{Http, Keyring, Shell, TokenRequest};
use crate::error::Result;
use futures::lock::Mutex;
use keyring::Entry;
use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, CsrfToken, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use regex::Regex;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{header, Client};
use serde::{Deserialize, Serialize};
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

#[derive(Debug, Deserialize)]
struct UserState {
    name: String,
    profile_id: u64,
    steam_id: u64,
}

#[derive(Debug)]
struct PluginState {
    oauth_client: BasicClient,
    request: Mutex<Option<ActiveRequestState>>,
    http_client: Mutex<Option<Client>>,
    user: Mutex<Option<UserState>>,
}

#[derive(Clone, Serialize)]
struct ConnectionEventPayload {
    connected: bool,
}

impl PluginState {
    pub fn new(client_id: String, redirect_uri: String) -> PluginState {
        let oauth_client = BasicClient::new(
            ClientId::new(client_id),
            None,
            AuthUrl::new("http://localhost:3000/oauth/authorize".to_string()).unwrap(),
            Some(TokenUrl::new("http://localhost:3000/oauth/token".to_string()).unwrap()),
        )
        .set_redirect_uri(RedirectUrl::new(redirect_uri).unwrap());

        PluginState {
            oauth_client,
            request: Mutex::new(None),
            http_client: Mutex::new(None),
            user: Mutex::new(None),
        }
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

    open(&handle.shell_scope(), auth_url, None).map_err(Shell)
}

pub async fn retrieve_token<R: Runtime>(request: &str, handle: &AppHandle<R>) -> Result<()> {
    let state = handle.state::<PluginState>();
    let re =
        Regex::new(r"coh3stats://cohdb.com/oauth/authorize\?code=(?<code>.+)&state=(?<state>.+)")
            .unwrap();
    let Some(caps) = re.captures(request) else {
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

        let access_token = Entry::new("cohdb", "access_token").map_err(Keyring)?;
        access_token.delete_password().ok();
        access_token
            .set_password(token.access_token().secret())
            .map_err(Keyring)?;

        let mut headers = HeaderMap::new();
        let mut auth =
            HeaderValue::try_from(format!("Bearer {}", token.access_token().secret())).unwrap();
        auth.set_sensitive(true);
        headers.insert(header::AUTHORIZATION, auth);

        let client = Client::builder().default_headers(headers).build().unwrap();

        let user = client
            .get("http://localhost:3000/api/v1/users/me")
            .send()
            .await
            .map_err(Http)?
            .json::<UserState>()
            .await
            .map_err(Http)?;

        *state.http_client.lock().await = Some(client);
        *state.user.lock().await = Some(user);

        handle
            .emit_all(
                "cohdb:connection",
                ConnectionEventPayload { connected: true },
            )
            .unwrap();
    }

    Ok(())
}

#[tauri::command]
fn connected() -> Result<bool> {
    let access_token = Entry::new("cohdb", "access_token").map_err(Keyring)?;
    match access_token.get_password() {
        Ok(_) => Ok(true),
        Err(keyring::Error::NoEntry) => Ok(false),
        Err(err) => Err(Keyring(err)),
    }
}

#[tauri::command]
async fn disconnect<R: Runtime>(handle: AppHandle<R>) -> Result<()> {
    let state = handle.state::<PluginState>();
    let access_token = Entry::new("cohdb", "access_token").map_err(Keyring)?;
    match access_token.delete_password() {
        Ok(_) => {
            *state.http_client.lock().await = None;
            *state.user.lock().await = None;

            handle
                .emit_all(
                    "cohdb:connection",
                    ConnectionEventPayload { connected: false },
                )
                .unwrap();
            Ok(())
        }
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(err) => Err(Keyring(err)),
    }
}

pub fn init<R: Runtime>(client_id: String, redirect_uri: String) -> TauriPlugin<R> {
    Builder::new("cohdb")
        .invoke_handler(tauri::generate_handler![
            authenticate,
            connected,
            disconnect
        ])
        .setup(|app| {
            app.manage(PluginState::new(client_id, redirect_uri));
            Ok(())
        })
        .build()
}

fn set_focus<R: Runtime>(handle: &AppHandle<R>) {
    for (_, val) in handle.windows().iter() {
        val.set_focus().ok();
    }
}
