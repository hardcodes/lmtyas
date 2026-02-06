#[cfg(feature = "api-access-token")]
use crate::access_token::AccessTokenConfiguration;
use crate::authenticated_user::SharedAuthenticatedUsersHashMap;
use crate::authentication_middleware::SharedRequestData;
#[cfg(feature = "authentication-oidc")]
use crate::authentication_oidc::ClientFromProviderMetaData;
#[cfg(feature = "authentication-oidc")]
use crate::authentication_oidc::{OidcConfiguration, SharedOidcVerificationDataHashMap};
#[cfg(feature = "oidc-auth-ldap")]
use crate::authentication_url::AUTH_ROUTE;
use crate::cert_renewal::TlsCertStatus;
#[cfg(feature = "ldap-common")]
use crate::ldap_common::LdapCommonConfiguration;
#[cfg(any(feature = "ldap-auth", feature = "authentication-oidc"))]
use crate::login_user_trait::Login;
use crate::mail_configuration::SendEMailConfiguration;
use crate::secret_functions::SharedSecretData;
use actix_web::dev::ServerHandle;
use log::info;
use regex::Regex;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::{Arc, RwLock};
#[cfg(feature = "hacaoi-openssl")]
type CookieRsaKeys = hacaoi::openssl::rsa::RsaKeys;
#[cfg(feature = "hacaoi-rust-crypto")]
type CookieRsaKeys = hacaoi::rust_crypto::rsa::RsaKeys;
// the trait RsaKeysFunctions is needed for OpenSSL and Rust-Crypto rsa
use hacaoi::{error::HacaoiError, rsa::RsaKeysFunctions};
#[cfg(feature = "hacaoi-openssl")]
type HybridCrypto = hacaoi::openssl::hybrid_crypto::HybridCrypto;
#[cfg(feature = "hacaoi-rust-crypto")]
type HybridCrypto = hacaoi::rust_crypto::hybrid_crypto::HybridCrypto;
use crate::error::LmtyasError;
use hacaoi::hybrid_crypto::HybridCryptoFunctions;

/// Holds the deserialized entries of the json file
/// that is passed to the program
#[derive(Clone, Deserialize, Debug)]
pub struct ConfigurationFile {
    pub web_bind_address: String,
    pub ssl_private_key_file: String,
    pub ssl_certificate_chain_file: String,
    pub rsa_private_key_file: String,
    pub secret_directory: String,
    pub email_configuration: SendEMailConfiguration,
    pub admin_accounts: Vec<String>,
    pub max_authrequest_age_seconds: i64,
    pub max_cookie_age_seconds: i64,
    pub fqdn: String,
    #[cfg(feature = "ldap-common")]
    pub ldap_common_configuration: LdapCommonConfiguration,
    #[cfg(feature = "oidc-auth-ldap")]
    pub oidc_configuration: OidcConfiguration,
    pub login_hint: String,
    pub mail_hint: Option<String>,
    pub imprint: Weblink,
    pub privacy: Weblink,
    #[cfg(feature = "api-access-token")]
    pub access_token_configuration: AccessTokenConfiguration,
}

impl ConfigurationFile {
    /// get the domain part of the stored fqdn
    /// which contains the <domain>:<port>
    pub fn get_domain(&self) -> String {
        match self.fqdn.split_once(':') {
            Some((domain, _)) => String::from(domain),
            None => self.fqdn.clone(),
        }
    }
}

/// Loads a json file and deserializes it into an
/// instance of ConfigurationFile
impl ConfigurationFile {
    /// Read the web service configuration from a json file.
    pub fn read_from_file<P: AsRef<Path>>(path: P) -> Result<Self, LmtyasError> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut parsed_config: ConfigurationFile = serde_json::from_reader(reader)?;
        parsed_config.pre_flight_check()?;
        Ok(parsed_config)
    }

    /// Make some pre flight checks after the configuration file has been loaded
    /// and before the service is started.
    fn pre_flight_check(&mut self) -> Result<(), LmtyasError> {
        // Check if the files for TLS exist, the service cannot start without them.
        if !Path::new(&self.ssl_private_key_file).exists() {
            return Err(format!(
                "ssl_private_key_file {} does not exist!",
                &self.ssl_private_key_file
            )
            .into());
        }
        if !Path::new(&self.ssl_certificate_chain_file).exists() {
            return Err(format!(
                "ssl_certificate_chain_file {} does not exist!",
                &self.ssl_certificate_chain_file
            )
            .into());
        }
        // Check if the `rsa_private_key_file` for encrypting and decrypting
        // the secrets exists because it is loaded later on during runtime,
        // when the password is entered by the administator.
        // The server must not start if such a key component is missing.
        if !Path::new(&self.rsa_private_key_file).exists() {
            return Err(format!(
                "rsa_private_key_file {} does not exist!",
                &self.rsa_private_key_file
            )
            .into());
        }
        // Check for mail template.
        if !Path::new(&self.email_configuration.mail_template_file.as_os_str()).exists() {
            return Err(format!(
                "mail template does not exist: {:?}",
                &self.email_configuration.mail_template_file.as_ref()
            )
            .into());
        }
        // Call function of the `Login` trait to build the regex
        // that validates a well formed user/account name.
        #[cfg(feature = "ldap-auth")]
        parsed_config
            .ldap_common_configuration
            .build_valid_user_regex()?;
        #[cfg(feature = "oidc-auth-ldap")]
        self.oidc_configuration.build_valid_user_regex()?;
        Ok(())
    }
}

/// Holds the complete configuration information
/// that is passed to the HttpServer
#[derive(Clone)]
pub struct ApplicationConfiguration {
    pub configuration_file: ConfigurationFile,
    // HybridCrytpo/RSA keys for secret encryption/decryption
    pub hybrid_crypto_for_secrets: Arc<RwLock<Option<HybridCrypto>>>,
    // RSA keys for cookie encryption/decryption
    pub rsa_keys_for_cookies: Arc<CookieRsaKeys>,
    // SharedSecret (context for creating uuids)
    pub shared_secret: Arc<RwLock<SharedSecretData>>,
    /// stores authenticated users
    pub shared_authenticated_users: Arc<RwLock<SharedAuthenticatedUsersHashMap>>,
    /// stores every incoming resource request
    pub shared_request_data: Arc<RwLock<SharedRequestData>>,
    /// stores the optional oidc cliet configuration
    #[cfg(feature = "oidc-auth-ldap")]
    pub oidc_client: Arc<ClientFromProviderMetaData>,
    /// stores the optional oidc verification data
    #[cfg(feature = "oidc-auth-ldap")]
    pub shared_oidc_verification_data: Arc<RwLock<SharedOidcVerificationDataHashMap>>,
    // stores the regex after the config file has been read
    pub email_regex: Regex,
    // stores the current status of the TLS/SSL certificate
    pub tls_cert_status: Arc<RwLock<TlsCertStatus>>,
    // stores the server handle of the unix domain socket server
    pub uds_server_handle: Arc<RwLock<Option<ServerHandle>>>,
}

/// Build a new instance of ApplicationConfiguration
impl ApplicationConfiguration {
    /// Reads the configuration file
    pub async fn read_from_file<P: AsRef<Path>>(
        configuration_file_path: P,
    ) -> Result<ApplicationConfiguration, LmtyasError> {
        let config_file = ConfigurationFile::read_from_file(configuration_file_path)?;

        #[cfg(feature = "authentication-oidc")]
        let oidc_client = config_file
            .oidc_configuration
            .discover_metadata_and_build_oidc_client(&config_file.fqdn, AUTH_ROUTE)
            .await?;

        let rsa_keys_for_cookies = match CookieRsaKeys::random(hacaoi::rsa::KeySize::Bit2048) {
            Err(e) => {
                return Err(format!(
                    "cannot generate random RSA keys for cookie encryption/decryption: {}",
                    &e
                )
                .into());
            }
            Ok(rsa_keys) => rsa_keys,
        };
        info!("created random RSA key pair for cookie encryption/decryption");
        let email_regex = match Regex::new(crate::EMAIL_REGEX) {
            Err(_) => {
                return Err(LmtyasError::FromStringError(
                    "cannot build generic email regex, see pub const EMAIL_REGEX in file lib.rs!"
                        .into(),
                ));
            }
            Ok(r) => r,
        };
        Ok(ApplicationConfiguration {
            configuration_file: config_file.clone(),
            hybrid_crypto_for_secrets: Arc::new(RwLock::new(None)),
            rsa_keys_for_cookies: Arc::new(rsa_keys_for_cookies),
            shared_secret: Arc::new(RwLock::new(SharedSecretData::new())),
            shared_authenticated_users: Arc::new(RwLock::new(
                SharedAuthenticatedUsersHashMap::new(config_file.admin_accounts),
            )),
            shared_request_data: Arc::new(RwLock::new(SharedRequestData::new())),
            #[cfg(feature = "authentication-oidc")]
            oidc_client: Arc::new(oidc_client),
            #[cfg(feature = "oidc-auth-ldap")]
            shared_oidc_verification_data: Arc::new(RwLock::new(
                SharedOidcVerificationDataHashMap::new(),
            )),
            email_regex,
            tls_cert_status: Arc::new(RwLock::new(TlsCertStatus::NotLoaded)),
            uds_server_handle: Arc::new(RwLock::new(None)),
        })
    }

    /// Reads the RSA key files which are referenced in the configuration file.
    pub fn load_rsa_keys(
        &self,
        rsa_private_key_password: &str,
    ) -> Result<HybridCrypto, HacaoiError> {
        HybridCrypto::from_file(
            &self.configuration_file.rsa_private_key_file,
            rsa_private_key_password,
        )
    }

    /// Load certificate chain and its private key and return it as `rustls::ServerConfig`
    pub fn load_rustls_config(&self) -> Result<rustls::ServerConfig, Box<dyn Error>> {
        let cert_chain = CertificateDer::pem_file_iter(
            self.configuration_file.ssl_certificate_chain_file.clone(),
        )?
        .map(|cert| cert.unwrap())
        .collect();
        let private_key =
            PrivateKeyDer::from_pem_file(self.configuration_file.ssl_private_key_file.clone())?;

        {
            let mut tls_cert_status_write_lock = self.tls_cert_status.write().unwrap();
            *tls_cert_status_write_lock = TlsCertStatus::HasBeenLoaded;
        }
        // Looking for a way to select ciphers explitictly, e.g. like
        // https://wiki.mozilla.org/Security/Server_Side_TLS#Intermediate_compatibility_(recommended)
        Ok(
            rustls::ServerConfig::builder_with_protocol_versions(rustls::ALL_VERSIONS)
                .with_no_client_auth()
                .with_single_cert(cert_chain, private_key)?,
        )
    }
}

/// Valid targets for opening the link to the imprint page
#[derive(Clone, Deserialize, Serialize, Debug)]
pub enum Target {
    #[serde(rename = "_blank")]
    Blank,
    #[serde(rename = "_self")]
    _Self,
    #[serde(rename = "_parent")]
    Parent,
    #[serde(rename = "_top")]
    Top,
}

/// Web link information, e.g. for the imprint or privacy statement page.
#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct Weblink {
    pub href: String,
    pub target: Target,
}
