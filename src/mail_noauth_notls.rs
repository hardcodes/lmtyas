pub use crate::mail_configuration::{
    ParseMailAddressErrorContext, ParseMailboxWithContext, SendEMail, SendEMailConfiguration,
};
use crate::PROGRAM_NAME;
use lettre::{message::header::ContentType, message::Mailbox, Message, SmtpTransport, Transport};
use std::error::Error;

impl SendEMail for SendEMailConfiguration {
    /// The `SendEMailConfiguration` trait is a contract
    /// for implementing different flavors of `send_mail()`.
    /// This is the default implementation (as in default feature)
    /// that does not send credentials and does not use TLS.
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
        let email_message = match Message::builder()
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
        };

        let tp = SmtpTransport::builder_dangerous(&self.mail_server_address);
        let tp_with_port = tp.port(self.mail_server_port);
        let smtp_transport = tp_with_port.build();
        smtp_transport.send(&email_message)?;
        Ok(())
    }
}
