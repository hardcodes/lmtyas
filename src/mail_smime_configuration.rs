use crate::rsa_functions::RsaKeys;
use serde::Deserialize;
use std::sync::{Arc, RwLock};
use secstr::SecStr;

/// Holds data needed to sign mail messages for
/// Secure / Multipurpose Internet Mail Extensions (S/MIME)
#[derive(Clone, Deserialize)]
pub struct SmimeConfiguration {
    pub rsa_private_key_file: String,
    pub rsa_public_key_file: String,
    #[serde(skip)]
    pub rsa_keys: Arc<RwLock<RsaKeys>>,
    pub secure_passphrase: Option<SecStr>,
}

impl Default for SmimeConfiguration {
    fn default() -> Self {
        Self::new()
    }
}

impl SmimeConfiguration {
    pub fn new() -> SmimeConfiguration {
        SmimeConfiguration {
            rsa_private_key_file: String::new(),
            rsa_public_key_file: String::new(),
            rsa_keys: Arc::new(RwLock::new(RsaKeys::new())),
            secure_passphrase: None,
        }
    }
}
