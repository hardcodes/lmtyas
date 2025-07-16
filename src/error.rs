/// Combines all error types in one enum to ease
/// error propagation. A finger exercise in trying
/// to avoid anyhow (nothing bad about it).
#[derive(Debug)]
pub enum LmtyasError {
    /// [`Error`](std::io::Error) for I/O operations of the [`Read`](std::io::Read), [`Write`](std::io::Write), [`Seek`](std::io::Seek), and
    /// associated traits.
    IoError(std::io::Error),
    /// Possible [`FromUtf8Error`](std::string::FromUtf8Error)s when converting a `String` from a UTF-8 byte vector.
    FromUtf8Error(std::string::FromUtf8Error),
    /// [`Utf8Error`](std::str::Utf8Error)s which can occur when attempting to interpret a sequence of [`u8`]
    /// as a string.
    Utf8Error(std::str::Utf8Error),
    /// Plaintext error messages as [`String`]
    StringError(std::string::String),
    /// All errors from the hacaoi crate
    HacaoiError(hacaoi::error::HacaoiError),
    RegexError(regex::Error),
    FromBoxedStdError(Box<dyn std::error::Error>),
    FromSerdeJsonError(serde_json::Error),
}

impl std::fmt::Display for LmtyasError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LmtyasError::IoError(e) => write!(f, "{}", e),
            LmtyasError::FromUtf8Error(e) => write!(f, "{}", e),
            LmtyasError::Utf8Error(e) => write!(f, "{}", e),
            LmtyasError::StringError(e) => write!(f, "{}", e),
            LmtyasError::HacaoiError(e) => write!(f, "{}", e),
            LmtyasError::RegexError(e) => write!(f, "{}", e),
            LmtyasError::FromBoxedStdError(e) => write!(f, "{}", e),
            LmtyasError::FromSerdeJsonError(e) => write!(f, "{}", e),
        }
    }
}

// Make it an error!
impl std::error::Error for LmtyasError {}

impl From<std::io::Error> for LmtyasError {
    fn from(err: std::io::Error) -> Self {
        LmtyasError::IoError(err)
    }
}

impl From<std::string::FromUtf8Error> for LmtyasError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        LmtyasError::FromUtf8Error(err)
    }
}

impl From<std::str::Utf8Error> for LmtyasError {
    fn from(err: std::str::Utf8Error) -> Self {
        LmtyasError::Utf8Error(err)
    }
}

impl From<std::string::String> for LmtyasError {
    fn from(err: std::string::String) -> Self {
        LmtyasError::StringError(err)
    }
}

impl From<hacaoi::error::HacaoiError> for LmtyasError {
    fn from(err: hacaoi::error::HacaoiError) -> Self {
        LmtyasError::HacaoiError(err)
    }
}

impl From<regex::Error> for LmtyasError {
    fn from(err: regex::Error) -> Self {
        LmtyasError::RegexError(err)
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
