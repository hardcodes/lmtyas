/// Combines all error types in one enum to ease
/// error propagation. A finger exercise in trying
/// to avoid anyhow (nothing bad about it).
#[derive(Debug)]
pub enum LmtyasError {
    /// [`Error`](std::io::Error) for I/O operations of the [`Read`](std::io::Read), [`Write`](std::io::Write), [`Seek`](std::io::Seek), and
    /// associated traits.
    FromIoError(std::io::Error),
    /// Possible [`FromUtf8Error`](std::string::FromUtf8Error)s when converting a `String` from a UTF-8 byte vector.
    FromStringUtf8Error(std::string::FromUtf8Error),
    /// [`Utf8Error`](std::str::Utf8Error)s which can occur when attempting to interpret a sequence of [`u8`]
    /// as a string.
    FromStrUtf8Error(std::str::Utf8Error),
    /// Plaintext error messages as [`String`]
    FromStringError(std::string::String),
    /// All errors from the hacaoi crate
    FromHacaoiError(hacaoi::error::HacaoiError),
    FromRegexError(regex::Error),
    FromBoxedStdError(Box<dyn std::error::Error>),
    FromSerdeJsonError(serde_json::Error),
    FromOpenidReqwestError(openidconnect::reqwest::Error)
}

impl std::fmt::Display for LmtyasError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LmtyasError::FromIoError(e) => write!(f, "{}", e),
            LmtyasError::FromStringUtf8Error(e) => write!(f, "{}", e),
            LmtyasError::FromStrUtf8Error(e) => write!(f, "{}", e),
            LmtyasError::FromStringError(e) => write!(f, "{}", e),
            LmtyasError::FromHacaoiError(e) => write!(f, "{}", e),
            LmtyasError::FromRegexError(e) => write!(f, "{}", e),
            LmtyasError::FromBoxedStdError(e) => write!(f, "{}", e),
            LmtyasError::FromSerdeJsonError(e) => write!(f, "{}", e),
            LmtyasError::FromOpenidReqwestError(e) => write!(f, "{}", e),
        }
    }
}

// Make it an error!
impl std::error::Error for LmtyasError {}

impl From<std::io::Error> for LmtyasError {
    fn from(err: std::io::Error) -> Self {
        LmtyasError::FromIoError(err)
    }
}

impl From<std::string::FromUtf8Error> for LmtyasError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        LmtyasError::FromStringUtf8Error(err)
    }
}

impl From<std::str::Utf8Error> for LmtyasError {
    fn from(err: std::str::Utf8Error) -> Self {
        LmtyasError::FromStrUtf8Error(err)
    }
}

impl From<std::string::String> for LmtyasError {
    fn from(err: std::string::String) -> Self {
        LmtyasError::FromStringError(err)
    }
}

impl From<hacaoi::error::HacaoiError> for LmtyasError {
    fn from(err: hacaoi::error::HacaoiError) -> Self {
        LmtyasError::FromHacaoiError(err)
    }
}

impl From<regex::Error> for LmtyasError {
    fn from(err: regex::Error) -> Self {
        LmtyasError::FromRegexError(err)
    }
}

impl From<Box<dyn std::error::Error>> for LmtyasError {
    fn from(err: Box<dyn std::error::Error>) -> Self {
        LmtyasError::FromBoxedStdError(err)
    }
}

impl From<serde_json::Error> for LmtyasError {
    fn from(err: serde_json::Error) -> Self {
        LmtyasError::FromSerdeJsonError(err)
    }
}

impl From<openidconnect::reqwest::Error> for LmtyasError {
    fn from(err: openidconnect::reqwest::Error) -> Self {
        LmtyasError::FromOpenidReqwestError(err)
    }
}
