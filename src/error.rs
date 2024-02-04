#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("There was an error opening your browser")]
    Shell(#[from] tauri::api::Error),
    #[error("There was an error retrieving your token")]
    TokenRequest(String),
    #[error("There was an error accessing your keyring")]
    Keyring(#[from] keyring::Error),
    #[error("There was an error with the cohdb API")]
    Http(#[from] reqwest::Error),
    #[error("Please connect your cohdb account first")]
    Unauthenticated,
}

impl serde::Serialize for Error {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(self.to_string().as_ref())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
