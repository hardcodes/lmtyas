use crate::base64_trait::{Base64StringConversions, Base64VecU8Conversions};
use crate::rsa_functions::RsaKeys;
use actix_web::{
    cookie::time::Duration, cookie::time::OffsetDateTime, cookie::Cookie, http, http::StatusCode,
    HttpResponse,
};

/// Name of the cookie that is sent to an authenticated user browser
pub const COOKIE_NAME: &str = env!("CARGO_PKG_NAME");
pub const COOKIE_PATH: &str = "/";

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

/// build a new base64 encoded authentication cookie. Only used
/// as long the password for the rsa private key is not set and
/// hence the keys have not been loaded yet.
///
/// # Arguments
///
/// - `cookie_value`:    containing the value that should be placed inside the cookie
/// - `max_age_seconds`: lifetime of the cookie in seconds
///
/// # Returns
///
/// - `actix_web::cookie::Cookie`
pub fn build_new_base64_authentication_cookie(
    cookie_value: &str,
    max_age_seconds: i64,
    domain: &str,
) -> Cookie<'static> {
    let encoded_cookie_value = cookie_value.to_string().to_base64_encoded();
    #[cfg(feature = "ldap-auth")]
    let same_site = actix_web::cookie::SameSite::Strict;
    #[cfg(feature = "oidc-auth-ldap")]
    let same_site = actix_web::cookie::SameSite::Lax;

    let new_cookie = Cookie::build(COOKIE_NAME, encoded_cookie_value)
        .secure(true)
        .http_only(true)
        .path(COOKIE_PATH)
        .domain(String::from(domain))
        .max_age(Duration::seconds(max_age_seconds))
        .same_site(same_site)
        .finish();
    new_cookie
}

/// build a new rsa encrypted or base64 encoded authentication cookie,
/// depending on loaded rsa keys.
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
pub fn build_new_authentication_cookie(
    cookie_value: &str,
    max_age_seconds: i64,
    domain: &str,
    rsa: &RsaKeys,
) -> Cookie<'static> {
    match rsa.rsa_private_key {
        Some(_) => {
            build_new_encrypted_authentication_cookie(cookie_value, max_age_seconds, domain, rsa)
        }
        None => build_new_base64_authentication_cookie(cookie_value, max_age_seconds, domain),
    }
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

/// Get plain cookie value (rsa decrypt or base64 decode)
///
/// # Arguments
///
/// - `transmitted_cookie`: cookie value that is either rsa encrypted or base64 encoded
/// - `rsa`:                rsa keys to decrypt the cookie
///
/// # Returns
///
/// - plain cookie value as String
pub fn get_plain_cookie_string(transmitted_cookie: &str, rsa: &RsaKeys) -> String {
    // when the rsa key pair already has been loaded,
    // the cookie value is encrypted with the rsa public
    // key otherwise its simply base64 encoded.
    match rsa.rsa_private_key {
        Some(_) => rsa
            .rsa_private_key_decrypt_str(transmitted_cookie)
            .unwrap_or_else(|_| -> String { "invalid_rsa_cookie_value".to_string() }),
        None => String::from_utf8(
            Vec::from_base64_encoded(transmitted_cookie)
                .unwrap_or_else(|_| -> Vec<u8> { "invalid_base64_cookie".as_bytes().to_vec() }),
        )
        .unwrap_or_else(|_| -> String { "invalid_base64_utf8".to_string() }),
    }
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
