use crate::base64_trait::{Base64StringConversions, Base64VecU8Conversions};
use log::{debug, info, warn};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rand::rand_bytes;
use openssl::rsa::{Padding, Rsa};
use openssl::sign::Verifier;
use openssl::symm::{decrypt, encrypt, Cipher};
use std::error::Error;
use std::path::Path;

// min bit size of the modulus (modulus * 8 = rsa key bits)
const MIN_RSA_MODULUS_SIZE: u32 = 256;
// bits used to generate a random RSA key pair
const RSA_KEY_BITS: u32 = 4096;
// error messge is often used
const RSA_PRIVATE_NOT_SET: &str = "RSA public key is not set!";

/// Holds the RSA private and public key for
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
    /// Build a new RSA key pair with a random password for the
    /// private key. Used for cookie encryption
    pub fn generate_random_rsa_keys() -> Result<RsaKeys, Box<dyn Error>> {
        let rsa = Rsa::generate(RSA_KEY_BITS)?;
        let rsa_public_key = Rsa::public_key_from_pem(&rsa.public_key_to_pem()?)?;
        let rsa_private_key = Rsa::private_key_from_pem(&rsa.private_key_to_pem()?)?;
        Ok(RsaKeys {
            rsa_private_key: Some(rsa_private_key),
            rsa_public_key: Some(rsa_public_key),
        })
    }
    /// Loads RSA private key from the given path. To load the
    /// RSA privte key, the passphrase is needed.
    /// The RSA public key is derived from the RSA private key.
    ///
    /// # Arguments
    ///
    /// - rsa_private_key_path: Path
    /// - secure_passphrase:    SecStr
    ///
    /// # Returns
    ///
    /// - Result<RsaKeys, Box<dyn Error>>
    #[inline(always)]
    pub fn read_from_files<P: AsRef<Path>>(
        &mut self,
        rsa_private_key_path: P,
        rsa_private_key_password: &str,
    ) -> Result<(), Box<dyn Error>> {
        let rsa_private_key_file = std::fs::read_to_string(rsa_private_key_path)?;
        let rsa_private_key = match Rsa::private_key_from_pem_passphrase(
            rsa_private_key_file.as_bytes(),
            rsa_private_key_password.as_bytes(),
        ) {
            Ok(p) => p,
            Err(e) => {
                warn!("cannot load rsa private key: {}", e);
                return Err("Cannot load rsa keys!".into());
            }
        };
        let rsa_public_key_pem = rsa_private_key.public_key_to_pem()?;
        let rsa_public_key = Rsa::public_key_from_pem(&rsa_public_key_pem)?;
        debug!("rsa_public_key.size() = {}", &rsa_public_key.size());
        if rsa_public_key.size() < MIN_RSA_MODULUS_SIZE {
            warn!("modulus is < {} bytes", MIN_RSA_MODULUS_SIZE);
            return Err("RSA key size too small".into());
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
    pub fn rsa_public_key_encrypt_str(
        &self,
        plaintext_data: &str,
    ) -> Result<String, Box<dyn Error>> {
        if self.rsa_public_key.is_none() {
            return Err(RSA_PRIVATE_NOT_SET.into());
        }
        let public_key = self.rsa_public_key.as_ref().unwrap();
        let mut buf: Vec<u8> = vec![0; public_key.size() as usize];
        match public_key.public_encrypt(plaintext_data.as_bytes(), &mut buf, Padding::PKCS1) {
            Err(e) => {
                info!("Could not rsa encrypt (public key) given value: {}", &e);
                Err("Could not rsa encrypt given value".into())
            }
            Ok(_) => {
                let base64_encrypted = buf.to_base64_encoded();
                Ok(base64_encrypted)
            }
        }
    }

    /// Validate a signature that was created using the
    /// corresponding rsa private key.
    ///
    /// # Arguments
    ///
    /// - `signed_data`: a String slice with data that was signed
    /// - `signature_b64`:  a String slice with the base64 encoded signature
    pub fn rsa_public_key_validate_sha512_signature(
        &self,
        signed_data: &str,
        signature_b64: &str,
    ) -> Result<(), Box<dyn Error>> {
        if self.rsa_public_key.is_none() {
            return Err(RSA_PRIVATE_NOT_SET.into());
        }
        let signature_bytes = match Vec::from_base64_encoded(signature_b64) {
            Ok(bytes) => bytes,
            Err(e) => {
                return Err(format!("Could not base64 decode signature: {}", &e).into());
            }
        };
        let public_key = self.rsa_public_key.as_ref().unwrap();
        let pkey = match PKey::from_rsa(public_key.clone()) {
            Ok(pkey) => pkey,
            Err(e) => {
                return Err(format!("Could not build pkey: {}", &e).into());
            }
        };
        let mut verifier = match Verifier::new(MessageDigest::sha512(), &pkey) {
            Ok(verifier) => verifier,
            Err(e) => {
                return Err(format!("Could not build verifier: {}", &e).into());
            }
        };
        let update_result = verifier.update(signed_data.as_bytes());
        if update_result.is_err() {
            return Err(format!(
                "Could not add signed data to verifier: {}",
                &update_result.unwrap_err()
            )
            .into());
        }
        let validation_result = match verifier.verify(&signature_bytes) {
            Ok(validation_result) => validation_result,
            Err(e) => {
                return Err(format!("Could not verify signature: {}", &e).into());
            }
        };
        if validation_result {
            return Ok(());
        }
        Err("invalid signature".into())
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
            return Err(RSA_PRIVATE_NOT_SET.into());
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
            return Err(RSA_PRIVATE_NOT_SET.into());
        }

        let elements: Vec<&str> = encrypted_data.split('.').collect();

        if elements.len() != 3 {
            return Err(format!("Expected {} parts, but found  {}", 3, elements.len()).into());
        }
        // we can access the elements since we checked the length first.
        let encryption_scheme = elements.first().unwrap();
        if "v1" != *encryption_scheme {
            return Err(format!("Unsupported encryption scheme: {}", encryption_scheme).into());
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
    pub fn rsa_private_key_decrypt_str(
        &self,
        encrypted_data: &str,
    ) -> Result<String, Box<dyn Error>> {
        if self.rsa_private_key.is_none() {
            return Err(RSA_PRIVATE_NOT_SET.into());
        }
        let raw_data = match Vec::from_base64_encoded(encrypted_data) {
            Ok(b) => b,
            Err(e) => {
                warn!(
                    "decrypt_str() => could not base64 decode given value: {}",
                    &e
                );
                return Err("Could not base64 decode given value".into());
            }
        };

        let private_key = self.rsa_private_key.as_ref().unwrap();
        let mut buf: Vec<u8> = vec![0; private_key.size() as usize];
        match private_key.private_decrypt(&raw_data, &mut buf, Padding::PKCS1) {
            Err(e) => {
                info!("Could not rsa decrypt given value: {}", &e);
                Err("Could not rsa decrypt (private key) given value".into())
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
            self.rsa_private_key_decrypt_str(encrypted_data)
        } else {
            self.hybrid_decrypt_str(encrypted_data)
        }
    }
}
