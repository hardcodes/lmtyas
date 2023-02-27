use base64::{
    alphabet,
    engine::{self, general_purpose},
    Engine as _,
};
use core::convert::AsRef;
use std::error::Error;

/// This trait simplifys the use of the base64 string endoding
/// functions and make them testable so that future changes
/// induced from the base64 crate can be validated.
pub trait Base64StringConversions<T> {
    /// convert a string slice to a base64 encoded String.
    fn to_base64_encoded(&self) -> String;

    /// convert a string slice to a url safe base64 encoded String.
    fn to_base64_urlsafe_encoded(&self) -> String;
}

impl<T> Base64StringConversions<T> for T
where
    T: AsRef<[u8]>,
{
    fn to_base64_encoded(&self) -> String
    where
        T: AsRef<[u8]>,
    {
        general_purpose::STANDARD.encode(self)
    }

    fn to_base64_urlsafe_encoded(&self) -> String
    where
        T: AsRef<[u8]>,
    {
        const CUSTOM_ENGINE: engine::GeneralPurpose =
            engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::PAD);
        CUSTOM_ENGINE.encode(self)
    }
}

/// This trait simplifys the use of the base64 decoding functions
/// and make them testable so that future changes induced from the
/// base64 crate can be validated.
pub trait Base64VecU8Conversions {
    /// convert a base64 encoded string slice to a plaintext Vec<u8>.
    fn from_base64_encoded(b64: &str) -> Result<Vec<u8>, Box<dyn Error>>;

    /// convert a usl safe base64 encoded string slice to a plaintext Vec<u8>.
    fn from_base64_urlsafe_encoded(b64: &str) -> Result<Vec<u8>, Box<dyn Error>>;
}

impl Base64VecU8Conversions for Vec<u8> {
    fn from_base64_encoded(b64: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(base64::engine::general_purpose::STANDARD.decode(b64)?)
    }

    fn from_base64_urlsafe_encoded(b64: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        const CUSTOM_ENGINE: engine::GeneralPurpose =
            engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::PAD);

        Ok(CUSTOM_ENGINE.decode(b64)?)
    }
}
