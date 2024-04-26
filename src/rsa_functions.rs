use crate::base64_trait::{Base64StringConversions, Base64VecU8Conversions};
use crate::unsecure_string::SecureStringToUnsecureString;
use log::{debug, info, warn};
use openssl::rand::rand_bytes;
use openssl::rsa::{Padding, Rsa};
use openssl::symm::{decrypt, encrypt, Cipher};
use secstr::SecStr;
use serde::Deserialize;
use std::error::Error;
use std::path::Path;
use zeroize::Zeroize;

// min bit size of the modulus (modulus * 8 = rsa key bits)
const MIN_RSA_MODULUS_SIZE: u32 = 256;
/// Holds the RSA private and public for
/// encryption and decryption
pub struct RsaKeys {
    // Option<> to construct empty values
    pub rsa_private_key: Option<Rsa<openssl::pkey::Private>>,
    // Option<> to construct empty values
    pub rsa_public_key: Option<Rsa<openssl::pkey::Public>>,
}

impl Default for RsaKeys {
    fn default() -> Self {
        Self::new()
    }
}

impl RsaKeys {
    /// Constructs data struct with
    /// None<> to be able to put it into a
    /// arc<RwLock<Rsakeys>>
    ///
    /// # Returns
    ///
    /// - RsaKeys{rsa_private_key: None, rsa_public_key: None,}
    pub fn new() -> RsaKeys {
        RsaKeys {
            rsa_private_key: None,
            rsa_public_key: None,
        }
    }
    /// Loads RSA private and public key from the given paths.
    /// To load the RSA privte key, the passphrase is needed.
    ///
    /// # Arguments
    ///
    /// - rsa_private_key_path: Path
    /// - rsa_public_key_path:  Path
    /// - secure_passphrase:    SecStr
    ///
    /// # Returns
    ///
    /// - Result<RsaKeys, Box<dyn Error>>
    pub fn read_from_files<P: AsRef<Path>>(
        &mut self,
        rsa_private_key_path: P,
        rsa_public_key_path: P,
        secure_passphrase: &SecStr,
    ) -> Result<(), Box<dyn Error>> {
        let rsa_private_key_file = std::fs::read_to_string(rsa_private_key_path)?;
        let mut unsecure_passphrase = secure_passphrase.to_unsecure_string();
        let rsa_private_key = match Rsa::private_key_from_pem_passphrase(
            rsa_private_key_file.as_bytes(),
            unsecure_passphrase.as_bytes(),
        ) {
            Ok(p) => p,
            Err(e) => {
                unsecure_passphrase.zeroize();
                warn!("cannot load rsa private key: {}", e);
                const RSA_CANNOT_LOAD_KEY: &str = "Cannot load rsa keys!";
                let boxed_error = Box::<dyn Error + Send + Sync>::from(RSA_CANNOT_LOAD_KEY);
                return Err(boxed_error);
            }
        };
        unsecure_passphrase.zeroize();
        let rsa_public_key_file = std::fs::read_to_string(rsa_public_key_path)?;
        let rsa_public_key = Rsa::public_key_from_pem(rsa_public_key_file.as_bytes())?;
        debug!("rsa_public_key.size() = {}", &rsa_public_key.size());
        if rsa_public_key.size() < MIN_RSA_MODULUS_SIZE {
            warn!("modulus is < {} bytes", MIN_RSA_MODULUS_SIZE);
            const RSA_MIN_MODULUS_ERR: &str = "RSA key size too small";
            let boxed_error = Box::<dyn Error + Send + Sync>::from(RSA_MIN_MODULUS_ERR);
            return Err(boxed_error);
        }
        self.rsa_private_key = Some(rsa_private_key);
        self.rsa_public_key = Some(rsa_public_key);
        Ok(())
    }

    /// Encrypt a String slice with stored RSA public key
    /// and return it as base64 encoded String.
    ///
    /// # Arguments
    ///
    /// - `plaintext_data`: a String slice with data to encrypt
    pub fn rsa_encrypt_str(&self, plaintext_data: &str) -> Result<String, Box<dyn Error>> {
        if self.rsa_public_key.is_none() {
            let box_err: Box<dyn Error> = "RSA public key is not set!".to_string().into();
            return Err(box_err);
        }
        let public_key = self.rsa_public_key.as_ref().unwrap();
        let mut buf: Vec<u8> = vec![0; public_key.size() as usize];
        match public_key.public_encrypt(plaintext_data.as_bytes(), &mut buf, Padding::PKCS1) {
            Err(e) => {
                info!("Could not rsa encrypt given value: {}", &e);
                let box_err: Box<dyn Error> =
                    "Could not rsa encrypt given value".to_string().into();
                Err(box_err)
            }
            Ok(_) => {
                let base64_encrypted = buf.to_base64_encoded();
                Ok(base64_encrypted)
            }
        }
    }

    /// Encrypt a String slice with stored RSA public key. The encryption is
    /// done in a hybrid mode, meaning, that the payload itself is encrypted
    /// using AES256 with a generated key, which is in turn encrypted using the
    /// RSA key.
    ///
    /// # Arguments
    ///
    /// - `plaintext_data`: a String slice with data to encrypt
    pub fn hybrid_encrypt_str(&self, plaintext_data: &str) -> Result<String, Box<dyn Error>> {
        if self.rsa_public_key.is_none() {
            let box_err: Box<dyn Error> = "RSA public key is not set!".to_string().into();
            return Err(box_err);
        }

        // AES Keys to encrypt the payload - the keysize of 256bit can be
        // encrypted using a 2048 RSA key. A smaller key size makes no sense and
        // this will result in a panic
        let mut aes_key = [0; 32];
        let mut aes_iv = [0; 16];
        let mut aes_key_iv = Vec::new();
        rand_bytes(&mut aes_key).unwrap();
        rand_bytes(&mut aes_iv).unwrap();

        let public_key = self.rsa_public_key.as_ref().unwrap();
        let mut buf: Vec<u8> = vec![0; public_key.size() as usize];

        aes_key_iv.extend_from_slice(&aes_key);
        aes_key_iv.extend_from_slice(&aes_iv);

        public_key
            .public_encrypt(&aes_key_iv, &mut buf, Padding::PKCS1)
            .unwrap();

        let base64_encrypted_key_iv = buf.to_base64_encoded();

        let cipher = Cipher::aes_256_cbc();

        let ciphertext =
            encrypt(cipher, &aes_key, Some(&aes_iv), plaintext_data.as_bytes()).unwrap();

        let payload = ciphertext.to_base64_encoded();

        return Ok(format_args!("v1.{base64_encrypted_key_iv}.{payload}").to_string());
    }

    /// Decrypt a string encrypted using the RSA keypair with the
    /// hybrid_encrypt_str function.
    ///
    /// # Arguments
    ///
    /// - `encrypted_data`: a String slice with data to decrypt
    pub fn hybrid_decrypt_str(&self, encrypted_data: &str) -> Result<String, Box<dyn Error>> {
        if self.rsa_private_key.is_none() {
            let box_err: Box<dyn Error> = "RSA private key is not set!".to_string().into();
            return Err(box_err);
        }

        let elements: Vec<&str> = encrypted_data.split('.').collect();

        if elements.len() != 3 {
            let box_err: Box<dyn Error> =
                format_args!("Expected {} parts, but found  {}", 3, elements.len())
                    .to_string()
                    .into();
            return Err(box_err);
        }
        // we can access the elements since we checked the length first.
        let encryption_scheme = elements.first().unwrap();
        if "v1" != *encryption_scheme {
            let box_err: Box<dyn Error> =
                format_args!("Unsupported encryption scheme: {}", encryption_scheme)
                    .to_string()
                    .into();
            return Err(box_err);
        }

        let encrypted_key_iv = Vec::from_base64_encoded(elements.get(1).unwrap())?;
        let encrypted_payload = Vec::from_base64_encoded(elements.get(2).unwrap())?;

        let public_key = self.rsa_public_key.as_ref().unwrap();

        let private_key = self.rsa_private_key.as_ref().unwrap();
        let mut aes_key_iv: Vec<u8> = vec![0; public_key.size() as usize];
        private_key.private_decrypt(&encrypted_key_iv, &mut aes_key_iv, Padding::PKCS1)?;

        let cipher = Cipher::aes_256_cbc();

        let payload = decrypt(
            cipher,
            &aes_key_iv.as_slice()[0..32],
            Some(&aes_key_iv.as_slice()[32..48]),
            &encrypted_payload,
        )?;

        return Ok(String::from_utf8(payload)?
            .trim_matches(char::from(0))
            .to_string());
    }

    /// Decrypt a base64 encoded String slice with stored RSA private key
    /// and return it as plaintext String.
    ///
    /// # Arguments
    ///
    /// - `encrypted_data`: a String slice with data to decrypt
    pub fn rsa_decrypt_str(&self, encrypted_data: &str) -> Result<String, Box<dyn Error>> {
        if self.rsa_private_key.is_none() {
            return Err("RSA private key is not set!".into());
        }
        let raw_data = match Vec::from_base64_encoded(encrypted_data) {
            Ok(b) => b,
            Err(e) => {
                warn!(
                    "decrypt_str() => could not base64 decode given value: {}",
                    &e
                );
                let box_err: Box<dyn Error> =
                    "Could not base64 decode given value".to_string().into();
                return Err(box_err);
            }
        };

        let private_key = self.rsa_private_key.as_ref().unwrap();
        let mut buf: Vec<u8> = vec![0; private_key.size() as usize];
        match private_key.private_decrypt(&raw_data, &mut buf, Padding::PKCS1) {
            Err(e) => {
                info!("Could not rsa decrypt given value: {}", &e);
                Err("Could not rsa decrypt given value".into())
            }
            Ok(_) => {
                let decrypted_data = match String::from_utf8(buf) {
                    Ok(s) => s,
                    Err(e) => {
                        info!("Could not convert decrypted data to utf8: {}", &e);
                        return Err("Could not convert decrypted data to utf8".into());
                    }
                };
                Ok(decrypted_data.trim_matches(char::from(0)).to_string())
            }
        }
    }

    /// Convenience function that decrypts a base64
    /// encoded String slice either with the stored
    /// RSA private key or decrypts the stored AES
    /// key and IV to decrypt the rest of the string.
    ///
    /// # Arguments
    ///
    /// - `encrypted_data`: a String slice with data to decrypt
    #[inline]
    pub fn decrypt_str(&self, encrypted_data: &str) -> Result<String, Box<dyn Error>> {
        if encrypted_data.find('.').is_none() {
            self.rsa_decrypt_str(encrypted_data)
        } else {
            self.hybrid_decrypt_str(encrypted_data)
        }
    }
}

/// Holds the password for the RSA private key
/// that encrypts secrets and links.
#[derive(Clone, Deserialize, Debug)]
pub struct RsaPrivateKeyPassword {
    pub rsa_private_key_password: Option<SecStr>,
}
