pub use crate::mail_configuration::{SendEMail, SendEMailConfiguration};
use lettre::{Message, SmtpTransport, Transport};
use std::error::Error;
use crate::PROGRAM_NAME;

impl SendEMail for SendEMailConfiguration {
    /// The `SendEMailConfiguration` trait is a contract
    /// for implementing different flavors of `send_mail()`.
    /// This is the default implementation that does not send
    /// credentials and does not use TLS.
    ///
    /// # Arguments
    ///
    /// - `mail_to`:          mail address of the receiver of the secret.
    /// - `mail_subject`:     subject of the mail
    /// - `mail_body`:        body of the mail
    fn send_mail(
        &self,
        mail_to: &str,
        mail_subject: &str,
        mail_body: &str
    ) -> Result<(), Box<dyn Error>> {

        let parsed_mail_from = self.mail_from.parse()?;
        let parsed_mail_to = mail_to.parse()?;
        let email = match Message::builder()
            .from(parsed_mail_from)
            .to(parsed_mail_to)
            .subject(mail_subject)
            .user_agent(PROGRAM_NAME.to_string())
            .body(String::from(mail_body)){
                Ok(m) => m,
                Err(e) => {return Err(Box::<dyn Error + Send + Sync>::from(format!(
                    "Error building email message: {}",
                    e,
                )));}
            };

        let tp = SmtpTransport::builder_dangerous(&self.mail_server_address);
        let tp_with_port = tp.port(self.mail_server_port);
        let smtp_transport = tp_with_port.build();
        smtp_transport.send(&email)?;
        Ok(())
    }
}
