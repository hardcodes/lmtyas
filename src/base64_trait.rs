use std::error::Error;

/// This trait simplifys the use of the base64 endoding and
/// decoding functions and make them testable so that
/// future changes induced from the base64 crate can be
/// validated.
pub trait Base64StringConversions {
    /// convert a string slice to a base64 encoded String.
    fn to_base64_encoded_string(&self) -> String;

    /// convert a string slice to a url safe base64 encoded String.
    fn to_base64_urlsafe_encoded_string(&self) -> String;

    /// convert a base64 encoded string slice to a plaintext String.
    fn from_base64_encoded(b64: &str) -> Result<String, Box<dyn Error>>;

    /// convert a usl safe base64 encoded string slice to a plaintext String.
    fn from_base64_urlsafe_encoded(b64: &str) -> Result<String, Box<dyn Error>>;
}

impl Base64StringConversions for String {
    fn to_base64_encoded_string(&self) -> String {
        base64::encode(self.as_bytes())
    }

    fn to_base64_urlsafe_encoded_string(&self) -> String {
        let base64_config = base64::Config::new(base64::CharacterSet::UrlSafe, true);
        base64::encode_config(self.as_bytes(), base64_config)
    }

    fn from_base64_encoded(b64: &str) -> Result<String, Box<dyn Error>> {
        let bytes = base64::decode(b64)?;
        let plaintext = String::from_utf8(bytes)?;
        Ok(plaintext.trim_matches(char::from(0)).to_string())
    }

    fn from_base64_urlsafe_encoded(b64: &str) -> Result<String, Box<dyn Error>> {
        let bytes = base64::decode_config(b64.trim_matches(char::from(0)), base64::URL_SAFE)?;
        let plaintext = String::from_utf8(bytes)?;
        Ok(plaintext.trim_matches(char::from(0)).to_string())
    }
}
