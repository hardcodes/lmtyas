use secstr::SecStr;

/// This trait is used to conveniently convert
/// `SecStr`s into `String`s
pub trait SecureStringToUnsecureString {
    fn to_unsecure_string(&self) -> std::string::String;
}

/// Converts `SecStr` into unsecure `String`
///
/// # Arguments
///
/// - none
///
/// # Returns
///
/// - `String`: unsecure representation of the stored string
impl SecureStringToUnsecureString for SecStr {
    fn to_unsecure_string(&self) -> std::string::String {
        let tmp_passwd = &self.clone();
        let unsecure_password = tmp_passwd
            .unsecure()
            .iter()
            .map(|&c| c as char)
            .collect::<String>();
        unsecure_password
    }
}