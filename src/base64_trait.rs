use std::error::Error;

/// This trait simplifys the use of the base64 string endoding
/// functions and make them testable so that future changes
/// induced from the base64 crate can be validated.
pub trait Base64StringConversions {
    /// convert a string slice to a base64 encoded String.
    fn to_base64_encoded(&self) -> String;

    /// convert a string slice to a url safe base64 encoded String.
    fn to_base64_urlsafe_encoded(&self) -> String;
}

impl Base64StringConversions for String {
    fn to_base64_encoded(&self) -> String {
        base64::encode(self.as_bytes())
    }

    fn to_base64_urlsafe_encoded(&self) -> String {
        let base64_config = base64::Config::new(base64::CharacterSet::UrlSafe, true);
        base64::encode_config(self.as_bytes(), base64_config)
    }
}

/// This trait simplifys the use of the base64 Vec<u8> endoding
/// functions and make them testable so that future changes
/// induced from the base64 crate can be validated.
pub trait VecU8Base64Conversions {
    /// convert a Vec<u8> to a base64 encoded Vec<u8>.
    fn to_base64_encoded(&self) -> String;

    /// convert a Vec<u8> slice to a url safe base64 encoded Vec<u8>.
    fn to_base64_urlsafe_encoded(&self) -> String;
}

impl VecU8Base64Conversions for Vec<u8> {
    fn to_base64_encoded(&self) -> String {
        base64::encode(self)
    }

    fn to_base64_urlsafe_encoded(&self) -> String {
        let base64_config = base64::Config::new(base64::CharacterSet::UrlSafe, true);
        base64::encode_config(self, base64_config)
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
        Ok(base64::decode(b64)?)
    }

    fn from_base64_urlsafe_encoded(b64: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(base64::decode_config(
            b64.trim_matches(char::from(0)),
            base64::URL_SAFE,
        )?)
    }
}
