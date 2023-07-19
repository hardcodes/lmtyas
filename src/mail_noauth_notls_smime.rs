pub use crate::mail_configuration::{
    ParseMailAddressErrorContext, ParseMailboxWithContext, SendEMail, SendEMailConfiguration,
};
use crate::rsa_functions::RsaKeys;
use crate::PROGRAM_NAME;
use lettre::{
    message::{header::ContentType, Attachment, Mailbox, MultiPart, SinglePart},
    Message, SmtpTransport, Transport,
};
use log::info;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use secstr::SecStr;
use serde::Deserialize;
use std::error::Error;
use std::path::Path;

// See
// https://www.iana.org/assignments/media-types/media-types.xhtml#multipart
// https://www.iana.org/assignments/media-types/multipart/signed
const MULTIPART_SIGNED_PROTOCOL: &str = "application/pkcs7-signature";
const MULTIPART_SIGNED_MICALG: &str = "sha-256";
const SMIME_ATTACHMENT_FILENAME: &str = "smime.p7s";

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
        mail_signature: Option<Vec<u8>>,
    ) -> Result<(), Box<dyn Error>> {
        let parsed_mail_from = Mailbox::parse_with_context_on_error(
            &self.mail_from,
            ParseMailAddressErrorContext::FromAddress,
        )?;
        let parsed_mail_to =
            Mailbox::parse_with_context_on_error(mail_to, ParseMailAddressErrorContext::ToAddress)?;

        let attachment_filename = String::from(SMIME_ATTACHMENT_FILENAME);
        let attachent_content_type = ContentType::parse(MULTIPART_SIGNED_PROTOCOL)?;
        let attachment = Attachment::new(attachment_filename)
            .body(mail_signature.unwrap(), attachent_content_type);

        let multipart_message = MultiPart::signed(
            MULTIPART_SIGNED_PROTOCOL.to_string(),
            MULTIPART_SIGNED_MICALG.to_string(),
        )
        .singlepart(SinglePart::plain(String::from(mail_body)))
        .singlepart(attachment);

        let email_message = Message::builder()
            .from(parsed_mail_from)
            .to(parsed_mail_to)
            .subject(mail_subject)
            .user_agent(PROGRAM_NAME.to_string())
            .multipart(multipart_message)?;

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
    /// build a new `SmimeConfiguration` so it
    /// can be used in the application configuration.
    pub fn new() -> SmimeCertificate {
        SmimeCertificate {
            rsa_keys: RsaKeys::new(),
        }
    }

    /// Load the private and public key file of the
    /// S/Mime certificate
    pub fn load_smime_certificate<P: AsRef<Path>>(
        &mut self,
        rsa_private_key_path: P,
        rsa_public_key_path: P,
        secure_password: &SecStr,
    ) -> Result<(), Box<dyn Error>> {
        info!("loading S/Mime certificate...");
        self.rsa_keys.read_from_files(
            &rsa_private_key_path,
            &rsa_public_key_path,
            secure_password,
        )?;
        info!("S/Mime certificate has been loaded successfully.");
        Ok(())
    }

    /// Create a S/Mime signature.
    pub fn sign_mail_body(&self, mail_body: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        let private_key = PKey::from_rsa(self.rsa_keys.rsa_private_key.as_ref().unwrap().clone())?;
        let mut signer = Signer::new(MessageDigest::sha256(), &private_key)?;
        signer.update(mail_body.as_bytes())?;
        Ok(signer.sign_to_vec()?)
    }
}

impl Default for SmimeCertificate {
    fn default() -> Self {
        Self::new()
    }
}
