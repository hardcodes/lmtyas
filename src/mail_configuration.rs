use serde::Deserialize;
use std::error::Error;
use std::fs;
use std::path::Path;

/// Holds the information needed to
/// send email to the receiver of a
/// secret
#[derive(Clone, Deserialize, Debug)]
pub struct SendEMailConfiguration {
    pub mail_server_address: String,
    pub mail_server_port: u16,
    pub mail_from: String,
    pub mail_subject: String,
    pub mail_template_file: Box<Path>,
    pub mail_credentails: Option<EMailCredetials>,
}

impl SendEMailConfiguration {
    /// loads the mail template file
    pub fn load_mail_template(&self) -> Result<String, Box<dyn Error>> {
        let mail_body_template = fs::read_to_string(&self.mail_template_file)?;
        Ok(mail_body_template)
    }
}

/// Holds optional credentials tp
/// send emails.
#[derive(Clone, Deserialize, Debug)]
pub struct EMailCredetials {
    pub mail_user: String,
    pub mail_password: String,
}

/// This trait is a contract for implementing different
/// flavors of `send_mail()`.
/// The default implementation does not send credentials
/// and does not use TLS.
pub trait SendEMail {
    /// sends an email to the receiver of a secret
    ///
    /// # Arguments
    ///
    /// - `mail_to`:          mail address of the receiver of the secret.
    /// - `mail_subject`:     subject of the mail
    /// - `mail_body`:        body of the mail
    fn send_mail(&self, mail_to: &str, mail_subject: &str, mail_body: &str) -> Result<(), Box<dyn Error>>;
}
