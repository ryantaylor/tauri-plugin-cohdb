mod error;

use crate::error::Error::{Keyring, Shell, TokenRequest};
use crate::error::Result;
use keyring::Entry;
use oauth2::basic::BasicClient;
use oauth2::reqwest::http_client;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, CsrfToken, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use regex::Regex;
use serde::Serialize;
use std::sync::Mutex;
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

#[derive(Debug)]
struct PluginState {
    client: BasicClient,
    request: Mutex<Option<ActiveRequestState>>,
}

#[derive(Clone, Serialize)]
struct ConnectionEventPayload {
    connected: bool,
}

impl PluginState {
    pub fn new(client_id: String, redirect_uri: String) -> PluginState {
        let client = BasicClient::new(
            ClientId::new(client_id),
            None,
            AuthUrl::new("http://localhost:3000/oauth/authorize".to_string()).unwrap(),
            Some(TokenUrl::new("http://localhost:3000/oauth/token".to_string()).unwrap()),
        )
        .set_redirect_uri(RedirectUrl::new(redirect_uri).unwrap());

        PluginState {
            client,
            request: Mutex::new(None),
        }
    }
}

#[tauri::command]
fn authenticate<R: Runtime>(handle: AppHandle<R>) -> Result<()> {
    let state = handle.state::<PluginState>();
    let request = ActiveRequestState::new();

    let (auth_url, _) = state
        .client
        .authorize_url(|| request.csrf_token.clone())
        .add_scope(Scope::new("read".to_string()))
        .add_scope(Scope::new("write".to_string()))
        .set_pkce_challenge(request.pkce_challenge.clone())
        .url();

    *state.request.lock().unwrap() = Some(request);

    open(&handle.shell_scope(), auth_url, None).map_err(Shell)
}

pub fn retrieve_token<R: Runtime>(request: &str, handle: &AppHandle<R>) -> Result<()> {
    let re =
        Regex::new(r"coh3stats://cohdb.com/oauth/authorize\?code=(?<code>.+)&state=(?<state>.+)")
            .unwrap();
    let Some(caps) = re.captures(request) else {
        set_focus(handle);
        return Ok(());
    };

    if let Some(mut request_state) = handle.state::<PluginState>().request.lock().unwrap().take() {
        set_focus(handle);

        let token = handle
            .state::<PluginState>()
            .client
            .exchange_code(AuthorizationCode::new(caps["code"].to_string()))
            .set_pkce_verifier(request_state.pkce_verifier.take().unwrap())
            .request(http_client)
            .map_err(|err| TokenRequest(format!("{err}")))?;

        let access_token = Entry::new("cohdb", "access_token").map_err(Keyring)?;
        access_token.delete_password().ok();
        access_token
            .set_password(token.access_token().secret())
            .map_err(Keyring)?;

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
fn disconnect<R: Runtime>(handle: AppHandle<R>) -> Result<()> {
    let access_token = Entry::new("cohdb", "access_token").map_err(Keyring)?;
    match access_token.delete_password() {
        Ok(_) => {
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
