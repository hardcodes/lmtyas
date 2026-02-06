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
    pub mail_credentails: Option<EMailCredentials>,
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
pub struct EMailCredentials {
    pub mail_user: String,
    pub mail_password: String,
}

/// Used to add details to email address parsing errors
#[derive(Debug)]
pub enum ParseMailAddressErrorContext {
    FromAddress,
    ToAddress,
    CCAddress,
    BCCAddress,
    ReplyToAddress,
}

/// This trait adds functionality to the lettre crate
pub trait ParseMailboxWithContext {
    /// parse an email address into the lettre `Mailbox` format and
    /// add a context to the error message if that fails.
    ///
    /// # Arguments
    ///
    /// - `address`:         email address that should be pared into a `Mailbox`
    /// - `error_context`:   context that shows what the email address should be used for
    ///   (from, to, cc, bcc)
    fn parse_with_context_on_error(
        address: &str,
        error_context: ParseMailAddressErrorContext,
    ) -> Result<lettre::message::Mailbox, Box<dyn Error>>;
}

impl ParseMailboxWithContext for lettre::message::Mailbox {
    #[inline(always)]
    fn parse_with_context_on_error(
        address: &str,
        error_context: ParseMailAddressErrorContext,
    ) -> Result<lettre::message::Mailbox, Box<dyn Error>> {
        match address.parse::<lettre::message::Mailbox>() {
            Ok(p) => Ok(p),
            Err(e) => Err(Box::<dyn Error + Send + Sync>::from(format!(
                "{}, {:?}",
                e, error_context
            ))),
        }
    }
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
    /// - `mail_reply_to`:    mail address of the sender of the secret, so that replies will
    ///   not go to the technical sender address.
    /// - `mail_subject`:     subject of the mail
    /// - `mail_body`:        body of the mail
    fn send_mail(
        &self,
        mail_to: &str,
        mail_reply_to: &str,
        mail_subject: &str,
        mail_body: &str,
    ) -> Result<(), Box<dyn Error>>;
}
