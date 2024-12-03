use crate::rsa_functions::RsaKeys;
use actix_web::{
    cookie::time::Duration, cookie::time::OffsetDateTime, cookie::Cookie, http, http::StatusCode,
    HttpResponse,
};
use log::debug;
use std::fmt;
use std::str::FromStr;

/// Name of the cookie that is sent to an authenticated user browser
pub const COOKIE_NAME: &str = env!("CARGO_PKG_NAME");
pub const COOKIE_PATH: &str = "/";

/// Contains data that is used to build a cookie.
#[derive(Debug, PartialEq)]
pub struct CookieData {
    /// Identifies the user account for the current session
    pub uuid: uuid::Uuid,
    /// Timestamp of the last cookie update in seconds since the Unix epoch.
    pub unix_timestamp: u64,
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
    /// <uuid>;<unix_time_stamp>
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (uuid_str, unix_time_stamp_str) = s.split_once(';').ok_or(CookieDataError)?;
        let uuid_fromstr = uuid_str
            .parse::<uuid::Uuid>()
            .map_err(|_| CookieDataError)?;
        let unix_time_stamp_fromstr = unix_time_stamp_str
            .parse::<u64>()
            .map_err(|_| CookieDataError)?;

        Ok(CookieData {
            uuid: uuid_fromstr,
            unix_timestamp: unix_time_stamp_fromstr,
        })
    }
}

impl fmt::Display for CookieData {
    /// Display the data as String. Used to as source data for an enrypted cookie.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{};{}",
            self.uuid.to_string(),
            self.unix_timestamp.to_string()
        )
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
    cookie_value: &str,
    max_age_seconds: i64,
    domain: &str,
    rsa: &RsaKeys,
) -> Cookie<'static> {
    let encrypted_cookie_value = match rsa.rsa_public_key_encrypt_str(cookie_value) {
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
pub fn build_new_cookie_response(cookie: &Cookie, allowed_origin: String) -> HttpResponse {
    HttpResponse::build(StatusCode::OK)
        .content_type("application/text")
        .append_header((http::header::SET_COOKIE, cookie.to_string()))
        .append_header(("Access-Control-Allow-Origin", allowed_origin))
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
pub fn build_redirect_to_resource_url_response(
    cookie: &Cookie,
    location: String,
    allowed_origin: String,
) -> HttpResponse {
    HttpResponse::build(StatusCode::FOUND)
        .append_header((http::header::LOCATION, location))
        .append_header((http::header::SET_COOKIE, cookie.to_string()))
        .append_header(("Access-Control-Allow-Origin", allowed_origin))
        .finish()
}

/// Get plain cookie value from rsa encrypted value.
///
/// # Arguments
///
/// - `transmitted_cookie`: base64 encoded and rsa encrypted cookie value
///  containing <uuid>;<unix_time_stamp>
/// - `rsa`:                rsa keys to decrypt the cookie
pub fn get_decrypted_cookie_data(
    transmitted_cookie_value: &str,
    rsa: &RsaKeys,
) -> Result<CookieData, CookieDataError> {
    let decrypted_cookie_value = rsa
        .rsa_private_key_decrypt_str(transmitted_cookie_value)
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
