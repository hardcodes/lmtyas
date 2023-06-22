use crate::rsa_functions::RsaKeys;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs::File;
use std::path::Path;
use uuid::v1::{Context, Timestamp};
use uuid::Uuid;

/// Used to build unique uuids, created with `openssl rand -hex 6`
const SECRET_ID: &[u8; 6] = &[0x99, 0xa8, 0xdb, 0x5c, 0x43, 0x85];

pub struct SharedSecretData {
    /// used by the uuid crate to build unique uuids across threads
    pub uuid_context: Context,
}

impl Default for SharedSecretData {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedSecretData {
    /// Create a new instance by setting the
    /// context for creating unique uuids.
    pub fn new() -> SharedSecretData {
        SharedSecretData {
            uuid_context: Context::new(1),
        }
    }

    /// Create a new uuid
    ///
    /// # Arguments
    ///
    /// - none
    ///
    /// # Returns
    ///
    /// - `uuid::Uuid`: UUid that is used as file name to store the secret data
    pub fn create_uuid(&mut self) -> uuid::Uuid {
        let time_stamp = Utc::now();
        let unix_timestamp_seconds = time_stamp.timestamp() as u64;
        let unix_timestamp_subsec_nanos = time_stamp.timestamp_subsec_nanos();
        let ts = Timestamp::from_unix(
            &self.uuid_context,
            unix_timestamp_seconds,
            unix_timestamp_subsec_nanos,
        );
        Uuid::new_v1(ts, SECRET_ID)
    }
}

/// Holds the a secret and its meta data
#[derive(Deserialize, Serialize, Debug)]
pub struct Secret {
    #[serde(rename = "FromEmail")]
    pub from_email: String,
    #[serde(rename = "FromDisplayName")]
    pub from_display_name: String,
    #[serde(rename = "ToEmail")]
    pub to_email: String,
    #[serde(rename = "ToDisplayName")]
    pub to_display_name: String,
    #[serde(rename = "Context")]
    pub context: String,
    #[serde(rename = "Secret")]
    pub secret: String,
}

impl Secret {
    /// Writes secret data to disk
    ///
    /// # Arguments
    ///
    /// - `path`: Path and filename, expected to be in the form of
    ///           /path/<uuid>
    ///
    /// # Returns
    ///
    /// - `Result<(), Box<dyn Error>>`: empty Ok() result on success or boxed error.
    pub async fn write_to_disk<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn Error>> {
        let file = File::create(&path)?;
        serde_json::to_writer(file, self)?;
        Ok(())
    }

    /// reads secret data to disk
    ///
    /// # Arguments
    ///
    /// - `path`: Path and filename, expected to be in the form of
    ///           /path/<uuid>
    ///
    /// # Returns
    ///
    /// - `Result<(), Box<dyn Error>>`: empty Ok() result on success or boxed error.
    pub async fn read_from_disk<P: AsRef<Path>>(path: P) -> Result<Secret, Box<dyn Error>> {
        let content = std::fs::read_to_string(&path)?;
        let secret: Secret = serde_json::from_str(&content)?;
        Ok(secret)
    }

    /// Creates a new instance of `Secret` with
    /// encrypted data.
    pub fn to_encrypted(&self, rsa_keys: &RsaKeys) -> Result<Secret, Box<dyn Error>> {
        let encrypted_from_email = rsa_keys.hybrid_encrypt_str(&self.from_email)?;
        let encrypted_from_display_name = rsa_keys.hybrid_encrypt_str(&self.from_display_name)?;
        let encrypted_to_email = rsa_keys.hybrid_encrypt_str(&self.to_email)?;
        let encrypted_to_display_name = rsa_keys.hybrid_encrypt_str(&self.to_display_name)?;
        let encrypted_context = rsa_keys.hybrid_encrypt_str(&self.context)?;
        let encrypted_secret = rsa_keys.hybrid_encrypt_str(&self.secret)?;
        let secret = Secret {
            from_email: encrypted_from_email,
            from_display_name: encrypted_from_display_name,
            to_email: encrypted_to_email,
            to_display_name: encrypted_to_display_name,
            context: encrypted_context,
            secret: encrypted_secret,
        };
        Ok(secret)
    }

    /// Creates a new instance of `Secret` with
    /// decrypted data.
    pub fn to_decrypted(&self, rsa_keys: &RsaKeys) -> Result<Secret, Box<dyn Error>> {
        let decrypted_from_email = if self.from_email.find('.').is_none() {
            rsa_keys.decrypt_str(&self.from_email)?
        } else {
            rsa_keys.hybrid_decrypt_str(&self.from_email)?
        };
        let decrypted_from_display_name = if self.from_display_name.find('.').is_none() {
            rsa_keys.decrypt_str(&self.from_display_name)?
        } else {
            rsa_keys.hybrid_decrypt_str(&self.from_display_name)?
        };
        let decrypted_to_email = if self.to_email.find('.').is_none() {
            rsa_keys.decrypt_str(&self.to_email)?
        } else {
            rsa_keys.hybrid_decrypt_str(&self.to_email)?
        };
        let decrypted_to_display_name = if self.to_display_name.find('.').is_none() {
            rsa_keys.decrypt_str(&self.to_display_name)?
        } else {
            rsa_keys.hybrid_decrypt_str(&self.to_display_name)?
        };
        let decrypted_context = if self.context.find('.').is_none() {
            rsa_keys.decrypt_str(&self.context)?
        } else {
            rsa_keys.hybrid_decrypt_str(&self.context)?
        };
        let decrypted_secret = if self.secret.find('.').is_none() {
            rsa_keys.decrypt_str(&self.secret)?
        } else {
            rsa_keys.hybrid_decrypt_str(&self.secret)?
        };
        let secret = Secret {
            from_email: decrypted_from_email,
            from_display_name: decrypted_from_display_name,
            to_email: decrypted_to_email,
            to_display_name: decrypted_to_display_name,
            context: decrypted_context,
            secret: decrypted_secret,
        };
        Ok(secret)
    }

    /// replaces the placeholders in a mail template:
    ///
    /// {ToDisplayName}   -> `&self.to_display_name`
    /// {FromDisplayName} -> `&self.from_display_name`
    /// {Context}         -> `&self.context`
    /// {UrlPayload}      -> `url_payload`
    ///
    /// # Agruments
    ///  
    /// - `url_payload`:      url payload that contains the rsa encrypted uuid (=file name)
    ///                       of the secret, the iv and key for the aes encrypted
    ///                       secret itself,
    ///                       (will replace {UrlPayload} in the mail template.
    ///
    /// # Returns
    ///
    /// - `String`
    pub fn build_mail_body(&self, mail_body_template: &str, url_payload: &str) -> String {
        mail_body_template
            .replace("{ToDisplayName}", &self.to_display_name)
            .replace("{FromDisplayName}", &self.from_display_name)
            .replace("{Context}", &self.context)
            .replace("{UrlPayload}", url_payload)
    }

    /// replaces the placeholder in a mail subject:
    ///
    /// {Context}         -> `&self.context`
    ///
    /// # Agruments
    ///  
    /// - `subject`:       subject with placeholder
    ///
    /// # Returns
    ///
    /// - `String`
    pub fn build_context(&self, subject: &str) -> String {
        subject.replace("{Context}", &self.context)
    }
}
