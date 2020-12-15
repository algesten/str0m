use openssl::error::ErrorStack as OpenSslCtxError;
use openssl::ssl::Error as OpenSslError;
use serde::Serialize;
use serde_json::Error as JsonError;

macro_rules! err {
    ($kind:expr, $($arg:tt)*) => {{
        let res = std::fmt::format(format_args!($($arg)*));
        Error::new($kind, res)
    }}
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
pub enum ErrorKind {
    JsonParse,
    SdpParse,
    SdpApply,
    SslCtx,
    Dtls,
    Ssl,
}

impl ErrorKind {
    fn is_retryable(&self) -> bool {
        match self {
            ErrorKind::JsonParse => false,
            ErrorKind::SdpParse => false,
            ErrorKind::SdpApply => false,
            ErrorKind::SslCtx => false,
            ErrorKind::Dtls => false,
            ErrorKind::Ssl => false,
        }
    }

    pub fn make(self, message: impl Into<String>) -> Error {
        Error::new(self, message.into())
    }
}

#[derive(Debug, Serialize, Clone)]
pub struct Error {
    pub kind: ErrorKind,
    pub retryable: bool,
    pub message: String,
}

impl Error {
    pub fn new(kind: ErrorKind, message: String) -> Self {
        Error {
            kind,
            retryable: kind.is_retryable(),
            message,
        }
    }
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Error {:?}: {}", self.kind, self.message)
    }
}

impl From<JsonError> for Error {
    fn from(e: JsonError) -> Self {
        Error::new(ErrorKind::JsonParse, e.to_string())
    }
}

impl From<OpenSslCtxError> for Error {
    fn from(e: OpenSslCtxError) -> Self {
        Error::new(ErrorKind::SslCtx, e.to_string())
    }
}

impl From<OpenSslError> for Error {
    fn from(e: OpenSslError) -> Self {
        Error::new(ErrorKind::Ssl, e.to_string())
    }
}

impl<T> From<Error> for Result<T, Error> {
    fn from(e: Error) -> Self {
        Err(e)
    }
}
