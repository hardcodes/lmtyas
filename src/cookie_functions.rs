use actix_web::{
    cookie::time::Duration, cookie::time::OffsetDateTime, cookie::Cookie, http, http::StatusCode,
    HttpResponse,
};
use log::{debug, warn};
use std::fmt;
use std::str::FromStr;
#[cfg(feature = "hacaoi-openssl")]
type CookieRsaKeys = hacaoi::openssl::rsa::RsaKeys;
// the trait RsaKeysFunctions is needed for OpenSSL and Rust-Crypto rsa
use hacaoi::rsa::RsaKeysFunctions;

/// Name of the cookie that is sent to an authenticated user browser
pub const COOKIE_NAME: &str = env!("CARGO_PKG_NAME");
pub const COOKIE_PATH: &str = "/";
// Graceperiod for countercheck, see `counter_is_valid`.
pub const MAX_COOKIE_COUNTER_DIFFERENCE: u16 = 1;

/// Contains data inside a cookie before it is
/// encrypted or after it is decrypted.
#[derive(Debug, PartialEq)]
pub struct CookieData {
    /// Identifies the user account for the current session
    pub uuid: uuid::Uuid,
    /// Counting cookie lifetime updates
    pub cookie_update_lifetime_counter: u16,
}

impl CookieData {
    /// This function is called to validate the counter
    /// stored in this `CookieData`struct. A simple test
    /// for equality does not work because that leads to
    /// many situations with race conditions in the javascript
    /// world.
    /// Therefore the counter is valid if it is in the
    /// range of `MAX_COOKIE_COUNTER_DIFFERENCE`. Since the
    /// cookie lifetime is updated every 60 seconds, this
    /// should be sufficient to catch those cases.
    pub fn counter_is_valid(&self, counter: u16) -> bool {
        if self.cookie_update_lifetime_counter > counter {
            // That should never happen!
            warn!("cookie_update_lifetime_counter is too big!");
            return false;
        }
        counter - self.cookie_update_lifetime_counter <= MAX_COOKIE_COUNTER_DIFFERENCE
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct CookieDataError;

impl fmt::Display for CookieDataError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "cannot parse cookie data")
    }
}

impl FromStr for CookieData {
    type Err = CookieDataError;

    /// Parse String with CookieData:
    ///
    /// ```ignore
    /// <uuid>;<cookie_update_lifetime_counter>
    /// ```
    fn from_str(decrypted_cookie: &str) -> Result<Self, Self::Err> {
        let (uuid_str, cookie_update_lifetime_counter_str) =
            decrypted_cookie.split_once(';').ok_or(CookieDataError)?;
        let uuid_fromstr = uuid_str
            .parse::<uuid::Uuid>()
            .map_err(|_| CookieDataError)?;
        let cookie_update_lifetime_counter_fromstr = cookie_update_lifetime_counter_str
            .parse::<u16>()
            .map_err(|_| CookieDataError)?;

        Ok(CookieData {
            uuid: uuid_fromstr,
            cookie_update_lifetime_counter: cookie_update_lifetime_counter_fromstr,
        })
    }
}

impl fmt::Display for CookieData {
    /// Display the data as String. Used to as source data for an encrypted cookie.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{};{}", self.uuid, self.cookie_update_lifetime_counter)
    }
}

/// build a new rsa encrypted authentication cookie
///
/// # Arguments
///
/// - `cookie_value`:    containing the value that should be placed inside the cookie
/// - `max_age_seconds`: lifetime of the cookie in seconds
/// - `rsa`:             rsa keys to encrypt the cookie
///
/// # Returns
///
/// - `actix_web::cookie::Cookie`
pub fn build_new_encrypted_authentication_cookie(
    plaintext_cookie_value: &str,
    max_age_seconds: i64,
    domain: &str,
    rsa: &CookieRsaKeys,
) -> Cookie<'static> {
    let encrypted_cookie_value =
        match rsa.encrypt_str_pkcs1v15_padding_to_b64(plaintext_cookie_value) {
            Err(_) => String::from("invalid_rsa_cookie"),
            Ok(value) => value,
        };
    #[cfg(feature = "ldap-auth")]
    let same_site = actix_web::cookie::SameSite::Strict;
    #[cfg(feature = "oidc-auth-ldap")]
    let same_site = actix_web::cookie::SameSite::Lax;
    let new_cookie = Cookie::build(COOKIE_NAME, encrypted_cookie_value)
        .secure(true)
        .http_only(true)
        .path(COOKIE_PATH)
        .domain(String::from(domain))
        .max_age(Duration::seconds(max_age_seconds))
        .same_site(same_site)
        .finish();
    new_cookie
}

/// Builds a new HTTPResponse with an authentication cookie inside
///
/// # Arguments
///
/// - `cookie`:         cookie struct that will be serialized
/// - `allowed_origin`: URL where the cookie is valid
///
/// # Returns
///
/// - `HttpResponse`
pub fn build_new_cookie_response(cookie: &Cookie) -> HttpResponse {
    HttpResponse::build(StatusCode::OK)
        .content_type("application/text")
        .append_header((http::header::SET_COOKIE, cookie.to_string()))
        .body("OK")
}

/// Builds a new HTTPResponse with a SEE_OTHER status code and
/// an authentication cookie inside
///
/// # Arguments
///
/// - `cookie`:         cookie struct that will be serialized
/// - `allowed_origin`: URL where the cookie is valid
///
/// # Returns
///
/// - `HttpResponse`
#[allow(dead_code)]
pub fn build_redirect_to_resource_url_response(cookie: &Cookie, location: String) -> HttpResponse {
    HttpResponse::build(StatusCode::FOUND)
        .append_header((http::header::LOCATION, location))
        .append_header((http::header::SET_COOKIE, cookie.to_string()))
        .finish()
}

/// Get plaintext cookie value from rsa encrypted value.
///
/// # Arguments
///
/// - `transmitted_cookie`: base64 encoded and rsa encrypted cookie value
///   containing <uuid>;<cookie_update_lifetime_counter>
/// - `rsa`:                rsa keys to decrypt the cookie
pub fn get_decrypted_cookie_data(
    encrypted_cookie_value: &str,
    rsa: &CookieRsaKeys,
) -> Result<CookieData, CookieDataError> {
    let decrypted_cookie_value = rsa
        .decrypt_b64_pkcs1v15_padding_to_string(encrypted_cookie_value)
        .unwrap_or_else(|_| -> String { "invalid_rsa_cookie_value".to_string() });
    debug!("decrypted_cookie_value = {}", &decrypted_cookie_value);
    CookieData::from_str(&decrypted_cookie_value)
}

/// Returns an empty cookie with an expiration date of the
/// unix epoch (1970-01-01 0:00 UTC).
pub fn empty_unix_epoch_cookie() -> Cookie<'static> {
    #[cfg(feature = "ldap-auth")]
    let same_site = actix_web::cookie::SameSite::Strict;
    #[cfg(feature = "oidc-auth-ldap")]
    let same_site = actix_web::cookie::SameSite::Lax;
    let empty_unix_epoch_cookie = Cookie::build(COOKIE_NAME, "".to_string())
        .secure(true)
        .http_only(true)
        .path(COOKIE_PATH)
        .expires(OffsetDateTime::UNIX_EPOCH)
        .same_site(same_site)
        .finish();
    empty_unix_epoch_cookie
}
