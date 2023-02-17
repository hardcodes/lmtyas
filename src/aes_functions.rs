use log::info;
use openssl::rand::rand_bytes;
use openssl::symm::{decrypt, encrypt, Cipher};
use std::error::Error;
use crate::base64_trait::Base64VecU8Conversions;

const KEY_LENGTH: usize = 32;
const IV_LENGTH: usize = 16;

/// Used to return AES encrypted data
pub struct AesEncryptionData {
    pub encrypted_data: String,
    pub encryption_key: String,
    pub encryption_iv: String,
}

/// This trait is used to AES encrypt a `String`
pub trait EncryptAes {
    fn to_aes_enrypted_b64(&self) -> Result<AesEncryptionData, &'static str>;
}

impl EncryptAes for String {
    /// AES encrypt a `String`with randomly chosen key and iv.
    ///
    /// The encryted `String`, key and iv are returned as base64 encoded values
    ///
    /// # Returns
    ///
    /// - `AesEncryptionData`
    fn to_aes_enrypted_b64(&self) -> Result<AesEncryptionData, &'static str> {
        let cipher = Cipher::aes_256_cbc();
        let mut key_buf = [0; KEY_LENGTH];
        rand_bytes(&mut key_buf).unwrap();
        let mut iv_buf = [0; IV_LENGTH];
        rand_bytes(&mut iv_buf).unwrap();
        match encrypt(cipher, &key_buf, Some(&iv_buf), self.as_bytes()) {
            Err(e) => {
                info!("could not aes encrypt data: {:?}", &e);
                Err("could not aes encrypt data!")
            }
            Ok(encrypted_data) => {
                let base64_config = base64::Config::new(base64::CharacterSet::UrlSafe, true);
                let base64_encrypted_data = base64::encode_config(encrypted_data, base64_config);
                let base64_key = base64::encode_config(key_buf, base64_config);
                let base64_iv = base64::encode_config(iv_buf, base64_config);
                let aes_encryption_result = AesEncryptionData {
                    encrypted_data: base64_encrypted_data,
                    encryption_key: base64_key,
                    encryption_iv: base64_iv,
                };
                Ok(aes_encryption_result)
            }
        }
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
