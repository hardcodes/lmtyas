pub use crate::mail_configuration::{SendEMail, SendEMailConfiguration};
use lettre::{Message, SmtpTransport, Transport};
use std::error::Error;

impl SendEMail for SendEMailConfiguration {
    /// This trait is a contract for implementing different
    /// flavors of `send_mail()` implementations.
    /// The default implementation does not send credentials
    /// and does not use TLS.
    ///
    /// # Arguments
    ///
    /// - `context`:          description what the secret is for
    ///                       (as entered on the webpage by the sender).
    /// - `mail_to`:          mail address of the receiver of the secret.
    /// - `to_display_name`:  display name of the receiver of the secret
    ///                       (will replace {ToDisplayName} in the mail template).
    /// - `from_display_name: display name of the sender of the secret
    ///                       (will replace {FromDisplayName} in the mail template.
    /// - `url_payload`:      url payload that contains the rsa encrypted uuid (=file name)
    ///                       of the secret, the iv and key for the aes encrypted
    ///                       secret itself,
    ///                       (will replace {UrlPayload} in the mail template.
    fn send_mail(
        &self,
        mail_to: &str,
        mail_subject: &str,
        mail_body: &str
    ) -> Result<(), Box<dyn Error>> {

        let parsed_mail_from = self.mail_from.parse()?;
        let parsed_mail_to = mail_to.parse()?;
        let email = Message::builder()
            .from(parsed_mail_from)
            .to(parsed_mail_to)
            .subject(mail_subject)
            .body(String::from(mail_body))
            .unwrap();

        let tp = SmtpTransport::builder_dangerous(&self.mail_server_address);
        let tp_with_port = tp.port(self.mail_server_port);
        let smtp_transport = tp_with_port.build();
        smtp_transport.send(&email)?;
        Ok(())
    }
}
