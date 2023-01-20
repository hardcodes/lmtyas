use crate::unsecure_string::SecureStringToUnsecureString;
use log::{debug, warn};
use openssl::rsa::{Padding, Rsa};
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
        &self,
        rsa_private_key_path: P,
        rsa_public_key_path: P,
        secure_passphrase: &SecStr,
    ) -> Result<Self, Box<dyn Error>> {
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
        if rsa_public_key.size() < MIN_RSA_MODULUS_SIZE{
            warn!("modulus is < {} bytes", MIN_RSA_MODULUS_SIZE);
            const RSA_MIN_MODULUS_ERR: &str = "RSA key size too small";
            let boxed_error = Box::<dyn Error + Send + Sync>::from(RSA_MIN_MODULUS_ERR);
            return Err(boxed_error);
        }
        Ok(RsaKeys {
            rsa_private_key: Some(rsa_private_key),
            rsa_public_key: Some(rsa_public_key),
        })
    }

    /// Encrypt a String slice with stored RSA public key
    /// and return it as base64 encoded String.
    ///
    /// # Arguments
    ///
    /// - `plaintext_data`: a String slice with data to encrypt
    ///
    pub fn encrypt_str(&self, plaintext_data: &str) -> Result<String, &'static str> {
        match &self.rsa_public_key {
            Some(rsa) => {
                let mut buf: Vec<u8> = vec![0; rsa.size() as usize];
                let _ = rsa
                    .public_encrypt(plaintext_data.as_bytes(), &mut buf, Padding::PKCS1)
                    .unwrap();
                let base64_encrypted = base64::encode(&buf);
                Ok(base64_encrypted)
            }
            None => Err("RSA public key is not set!"),
        }
    }

    /// Decrypt a base64 encoded String slice with stored RSA private key
    /// and return it as plaintext String.
    ///
    /// # Arguments
    ///
    /// - `encrypted_data`: a String slice with data to decrypt
    pub fn decrypt_str(&self, encrypted_data: &str) -> Result<String, &'static str> {
        match &self.rsa_private_key {
            Some(rsa) => match base64::decode(encrypted_data) {
                Err(_) => Err("Could not base64 decode given value"),
                Ok(raw_data) => {
                    let mut buf: Vec<u8> = vec![0; rsa.size() as usize];
                    match rsa.private_decrypt(&raw_data, &mut buf, Padding::PKCS1) {
                        Err(_) => Err("Could not rsa decrypt given value"),
                        Ok(_) => {
                            let decrypted_data =
                                String::from_utf8(buf).unwrap_or_else(|_| -> String {
                                    String::from("could not convert decrypt data to utf8!")
                                });
                            Ok(decrypted_data.trim_matches(char::from(0)).to_string())
                        }
                    }
                }
            },
            None => Err("RSA private key is not set!"),
        }
    }
}

/// Holds the password for the RSA private key
/// that encrypts secrets and links.
#[derive(Clone, Deserialize, Debug)]
pub struct RsaPrivateKeyPassword {
    pub rsa_private_key_password: Option<SecStr>,
}
