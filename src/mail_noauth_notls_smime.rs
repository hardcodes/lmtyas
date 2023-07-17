pub use crate::mail_configuration::{
    ParseMailAddressErrorContext, ParseMailboxWithContext, SendEMail, SendEMailConfiguration,
};
use crate::rsa_functions::RsaKeys;
use crate::PROGRAM_NAME;
use lettre::{
    message::{Mailbox, MultiPart, SinglePart},
    Message, SmtpTransport, Transport,
};
use log::info;
use secstr::SecStr;
use serde::Deserialize;
use std::error::Error;
use std::path::Path;

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

        // TODO: how do we pass the signature here? Maybe add some function to SendEMail::send_mail
        // args, e.g. `helper_function: &dyn Fn(&str) -> String`
        let signature = String::from("yada yada");
        let multipart_message = MultiPart::signed(
            MULTIPART_SIGNED_PROTOCOL.to_string(),
            MULTIPART_SIGNED_MICALG.to_string(),
        )
        .singlepart(SinglePart::plain(String::from(mail_body)))
        .singlepart(SinglePart::plain(signature));

        let email_message = match Message::builder()
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
#[derive(Clone, Deserialize, Debug)]
pub struct SmimeConfiguration {
    pub rsa_private_key_file: String,
    pub rsa_public_key_file: String,
    pub enrypted_password: String,
}
pub struct SmimeCertificate {
    pub rsa_keys: RsaKeys,
}

impl SmimeCertificate {
    /// build a new `SmimeConfiguration` just
    pub fn new() -> SmimeCertificate {
        SmimeCertificate {
            rsa_keys: RsaKeys::new(),
        }
    }

    pub fn load_smime_certificate<P: AsRef<Path>>(
        &mut self,
        rsa_private_key_path: P,
        rsa_public_key_path: P,
        secure_password: &SecStr,
    ) -> Result<(), Box<dyn Error>> {
        info!("Loading S/Mime certificate...");
        self.rsa_keys.read_from_files(
            &rsa_private_key_path,
            &rsa_public_key_path,
            secure_password,
        )?;
        info!("S/Mime certificate has been loaded.");
        Ok(())
    }
}

impl Default for SmimeCertificate {
    fn default() -> Self {
        Self::new()
    }
}
