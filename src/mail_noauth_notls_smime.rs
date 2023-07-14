pub use crate::mail_configuration::{
    ParseMailAddressErrorContext, ParseMailboxWithContext, SendEMail, SendEMailConfiguration,
};
use crate::rsa_functions::RsaKeys;
use crate::PROGRAM_NAME;
use lettre::{
    message::header::ContentType,
    message::{Mailbox, MultiPart, SinglePart},
    Message, SmtpTransport, Transport,
};
use secstr::SecStr;
use serde::Deserialize;
use std::error::Error;
use std::fmt;
use std::sync::{Arc, RwLock};
use log::{info, warn};

const MULTIPART_SIGNED_PROTOCOL: &str = "application/pkcs7-signature";
const MULTIPART_SIGNED_MICALG: &str = "sha-256";

impl SendEMail for SendEMailConfiguration {
    /// The `SendEMailConfiguration` trait is a contract
    /// for implementing different flavors of `send_mail()`.
    /// This is the S/Mime implementation that does not send
    /// credentials and does not use TLS but signs the mail
    /// body.
    fn send_mail(
        &self,
        mail_to: &str,
        mail_subject: &str,
        mail_body: &str,
    ) -> Result<(), Box<dyn Error>> {
        let parsed_mail_from = Mailbox::parse_with_context_on_error(
            &self.mail_from,
            ParseMailAddressErrorContext::FromAddress,
        )?;
        let parsed_mail_to =
            Mailbox::parse_with_context_on_error(mail_to, ParseMailAddressErrorContext::ToAddress)?;
        let email_message = match self.mail_smime_configuration {
            // No S/Mime configuration present, send mails without signing
            None => {
                warn!("S/Mime certificate has not been loaded before sending mail!");
                match Message::builder()
                    .from(parsed_mail_from)
                    .to(parsed_mail_to)
                    .subject(mail_subject)
                    .header(ContentType::TEXT_PLAIN)
                    .user_agent(PROGRAM_NAME.to_string())
                    .body(String::from(mail_body))
                {
                    Ok(m) => m,
                    Err(e) => {
                        return Err(Box::<dyn Error + Send + Sync>::from(format!(
                            "Error building email message: {}",
                            e,
                        )));
                    }
                }
            }
            // S/Mime configuration present, send signed mails
            Some(_) => {
                let signature = String::from("yada yada");
                let multipart_message = MultiPart::signed(
                    MULTIPART_SIGNED_PROTOCOL.to_string(),
                    MULTIPART_SIGNED_MICALG.to_string(),
                )
                .singlepart(SinglePart::plain(String::from(mail_body)))
                .singlepart(SinglePart::plain(signature));

                match Message::builder()
                    .from(parsed_mail_from)
                    .to(parsed_mail_to)
                    .subject(mail_subject)
                    .user_agent(PROGRAM_NAME.to_string())
                    .multipart(multipart_message)
                {
                    Ok(m) => m,
                    Err(e) => {
                        return Err(Box::<dyn Error + Send + Sync>::from(format!(
                            "Error building email message: {}",
                            e,
                        )));
                    }
                }
            }
        };

        let tp = SmtpTransport::builder_dangerous(&self.mail_server_address);
        let tp_with_port = tp.port(self.mail_server_port);
        let smtp_transport = tp_with_port.build();
        smtp_transport.send(&email_message)?;
        Ok(())
    }
}

/// Holds data needed to sign mail messages for
/// Secure / Multipurpose Internet Mail Extensions (S/MIME)
#[derive(Clone, Deserialize)]
pub struct SmimeConfiguration {
    pub rsa_private_key_file: String,
    pub rsa_public_key_file: String,
    pub enrypted_password: String,
    #[serde(skip)]
    rsa_keys: Arc<RwLock<RsaKeys>>,
    #[serde(skip)]
    secure_passphrase: Option<SecStr>,
}

/// Debug implementation to satisfy #[derive(Debug)] from
/// SendEMailConfiguration without printing any data.
impl fmt::Debug for SmimeConfiguration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmimeConfiguration")
            .field("rsa_private_key_file", &self.rsa_private_key_file)
            .field("rsa_public_key_file", &self.rsa_public_key_file)
            .finish()
    }
}

impl Default for SmimeConfiguration {
    fn default() -> Self {
        Self::new()
    }
}

impl SmimeConfiguration {
    /// build a new `SmimeConfiguration` just
    fn new() -> SmimeConfiguration {
        SmimeConfiguration {
            rsa_private_key_file: String::new(),
            // TODO: do we even need the public key file for message signing?
            rsa_public_key_file: String::new(),
            enrypted_password: String::new(),
            rsa_keys: Arc::new(RwLock::new(RsaKeys::new())),
            secure_passphrase: None,
        }
    }

    fn read_smime_certificate(&mut self) -> Result<(), Box<dyn Error>> {
        // TODO set the password after loading the global RSA keys, so that
        // we can decrypt the password from the configuration file.
        info!("Loading S/Mime certificate...");
        self.secure_passphrase = Some(SecStr::from("12345678901234"));
        if self.secure_passphrase.is_some() {
            let mut rsa_write_lock = self.rsa_keys.write().unwrap();
            rsa_write_lock.read_from_files(
                &self.rsa_private_key_file,
                &self.rsa_public_key_file,
                &self.secure_passphrase.as_ref().unwrap(),
            )?;
            info!("S/Mime certificate has been loaded.");
            Ok(())
        } else {
            const RSA_PASSWORD_NOT_SET: &str =
                "Password for S/Mime certificate is unknown, inform system administrator";
            let boxed_error = Box::<dyn Error + Send + Sync>::from(RSA_PASSWORD_NOT_SET);
            Err(boxed_error)
        }
    }
}

pub trait SmimeConfigurationBuilder {
    fn build_smime_config() -> SmimeConfiguration;
}

impl SmimeConfigurationBuilder for SendEMailConfiguration {
    fn build_smime_config() -> SmimeConfiguration {
        SmimeConfiguration::new()
    }
}
