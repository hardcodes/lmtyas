use crate::base64_trait::Base64VecU8Conversions;
use openssl::error::ErrorStack;
use openssl::symm::{decrypt, Cipher};
use std::error::Error;
use std::fmt;

/// custom error type to carry on the OpenSSL `ErrorStack`
#[derive(Debug, Clone)]
pub struct AesEncryptionError {
    details: String,
}

impl AesEncryptionError {
    fn new<S>(msg: S) -> Self
    where
        S: Into<String>,
    {
        Self {
            details: msg.into(),
        }
    }
}

impl fmt::Display for AesEncryptionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.details)
    }
}

impl Error for AesEncryptionError {
    fn description(&self) -> &str {
        &self.details
    }
}

/// Use Debug output of OpenSSL `ErrorStack` for our custom Error type.
impl From<ErrorStack> for AesEncryptionError {
    fn from(err: ErrorStack) -> Self {
        AesEncryptionError::new(format!("{:?}", err))
    }
}

/// This trait is used to AES decrypt a `String`
pub trait DecryptAes {
    fn decrypt_b64_aes(&self, key_base64: &str, iv_base64: &str) -> Result<String, Box<dyn Error>>;
}

impl DecryptAes for String {
    /// Decrypt a AES encoded `String`.
    ///
    /// # Arguments
    ///
    /// - key_base64 - base64 encoded key that was used to encrypt the data
    /// - iv_base64 - base64 encoded iv that was used to encrypt the data
    ///
    /// # Returns
    ///
    /// - `String` - plaintext
    fn decrypt_b64_aes(&self, key_base64: &str, iv_base64: &str) -> Result<String, Box<dyn Error>> {
        let encrypted_data = Vec::from_base64_urlsafe_encoded(self.trim_matches(char::from(0)))?;
        let iv = Vec::from_base64_urlsafe_encoded(iv_base64.trim_matches(char::from(0)))?;
        let key = Vec::from_base64_urlsafe_encoded(key_base64.trim_matches(char::from(0)))?;
        let cipher = Cipher::aes_256_cbc();
        let plaintext = decrypt(cipher, &key, Some(&iv), &encrypted_data)?;
        let p: String = String::from_utf8(plaintext)?;
        Ok(p)
    }
}
