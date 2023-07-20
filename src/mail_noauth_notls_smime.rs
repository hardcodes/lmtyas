pub use crate::mail_configuration::{
    ParseMailAddressErrorContext, ParseMailboxWithContext, SendEMail, SendEMailConfiguration,
};
use crate::unsecure_string::SecureStringToUnsecureString;
use crate::PROGRAM_NAME;
use lettre::{
    message::{header::ContentType, Attachment, Mailbox, MultiPart, SinglePart},
    Message, SmtpTransport, Transport,
};
use log::info;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use secstr::SecStr;
use serde::Deserialize;
use std::error::Error;
use std::path::Path;
use zeroize::Zeroize;

// See
// https://www.iana.org/assignments/media-types/media-types.xhtml#multipart
// https://www.iana.org/assignments/media-types/multipart/signed
// https://datatracker.ietf.org/doc/html/rfc8551
// https://datatracker.ietf.org/doc/html/rfc1847
const MULTIPART_SIGNED_PROTOCOL: &str = "application/pkcs7-signature";
// Message Integrity Check (MIC)
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
    pub enrypted_password: String,
}
pub struct SmimeCertificate {
    pub rsa_private_key: Option<Rsa<openssl::pkey::Private>>,
}

impl SmimeCertificate {
    /// build a new `SmimeConfiguration` so it
    /// can be used in the application configuration.
    pub fn new() -> SmimeCertificate {
        SmimeCertificate {
            rsa_private_key: None,
        }
    }

    /// Load the private and public key file of the
    /// S/Mime certificate
    pub fn load_smime_certificate<P: AsRef<Path>>(
        &mut self,
        rsa_private_key_path: P,
        secure_passphrase: &SecStr,
    ) -> Result<(), Box<dyn Error>> {
        info!("loading S/Mime configuration...");
        let rsa_private_key_file = std::fs::read_to_string(rsa_private_key_path)?;
        let mut unsecure_passphrase = secure_passphrase.to_unsecure_string();
        let rsa_private_key = Rsa::private_key_from_pem_passphrase(
            rsa_private_key_file.as_bytes(),
            unsecure_passphrase.as_bytes(),
        )?;
        unsecure_passphrase.zeroize();
        self.rsa_private_key = Some(rsa_private_key);
        info!("S/Mime configuration has been loaded successfully.");
        Ok(())
    }

    /// Create a S/Mime signature.
    pub fn sign_mail_body(&self, mail_body: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        let private_key = PKey::from_rsa(self.rsa_private_key.as_ref().unwrap().clone())?;
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
