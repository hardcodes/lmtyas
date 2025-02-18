use hacaoi::base64_trait::Base64VecU8Conversions;
use hacaoi::error::HacaoiError;

#[cfg(feature = "hacaoi-openssl")]
type SecretAes256Cbc = hacaoi::aes::Aes256Cbc<hacaoi::aes::AesOpenSslScope>;
#[cfg(feature = "hacaoi-rust-crypto")]
type SecretAes256Cbc = hacaoi::aes::Aes256Cbc<hacaoi::aes::AesRustCryptoScope>;
use hacaoi::aes::Aes256CbcFunctions;

/// This trait is used to AES decrypt a `String`.
pub trait DecryptAes {
    fn decrypt_b64_aes(&self, key_base64: &str, iv_base64: &str) -> Result<String, HacaoiError>;
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
    fn decrypt_b64_aes(&self, key_base64: &str, iv_base64: &str) -> Result<String, HacaoiError> {
        let mut iv = Vec::from_base64_urlsafe_encoded(iv_base64.trim_matches(char::from(0)))?;
        let mut aes_key_iv =
            Vec::from_base64_urlsafe_encoded(key_base64.trim_matches(char::from(0)))?;
        aes_key_iv.append(&mut iv);
        let aes = SecretAes256Cbc::from_vec(aes_key_iv)?;
        aes.decrypt_b64_to_string(self)
    }
}
