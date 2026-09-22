use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("authentication required: {0}")]
    AuthenticationRequired(String),
    #[error("operation refused: {0}")]
    Refused(String),
    #[error("security backend error: {0}")]
    Security(String),
    #[error("invalid or unsupported data: {0}")]
    InvalidData(String),
    #[error("Apple service error: {0}")]
    Apple(String),
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("property-list error: {0}")]
    Plist(#[from] plist::Error),
    #[error("URL error: {0}")]
    Url(#[from] url::ParseError),
}

impl Error {
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
