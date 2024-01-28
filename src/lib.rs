use keyring::Entry;
use oauth2::basic::BasicClient;
use oauth2::reqwest::http_client;
use oauth2::TokenResponse;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, CsrfToken, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, Scope, TokenUrl,
};
use regex::Regex;
use std::sync::Mutex;
use tauri::api::shell::open;
use tauri::{
    plugin::{Builder, TauriPlugin},
    AppHandle, Manager, Runtime,
};

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

struct PluginState {
    client: BasicClient,
    request: Mutex<Option<ActiveRequestState>>,
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
fn authenticate<R: Runtime>(handle: AppHandle<R>) {
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

    open(&handle.shell_scope(), auth_url, None).unwrap();
}

pub fn retrieve_token<R: Runtime>(request: &str, handle: &AppHandle<R>) {
    if let Some(mut request_state) = handle.state::<PluginState>().request.lock().unwrap().take() {
        let re = Regex::new(
            r"coh3stats://cohdb.com/oauth/authorize\?code=(?<code>.+)&state=(?<state>.+)",
        )
        .unwrap();
        let Some(caps) = re.captures(request) else {
            println!("invalid OAuth query!");
            set_focus(handle);
            return;
        };

        set_focus(handle);

        let token = handle
            .state::<PluginState>()
            .client
            .exchange_code(AuthorizationCode::new(caps["code"].to_string()))
            .set_pkce_verifier(request_state.pkce_verifier.take().unwrap())
            .request(http_client)
            .unwrap();

        let access_token = Entry::new("cohdb", "access_token").unwrap();
        access_token
            .set_password(token.access_token().secret())
            .unwrap();
    }
}

#[tauri::command]
fn connected() -> bool {
    let access_token = Entry::new("cohdb", "access_token").unwrap();
    access_token.get_password().is_ok()
}

#[tauri::command]
fn disconnect() {
    let access_token = Entry::new("cohdb", "access_token").unwrap();
    access_token.delete_password().ok();
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
