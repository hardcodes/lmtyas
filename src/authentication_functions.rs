//#[macro_use]
use log::{debug, warn};
extern crate env_logger;
use crate::authenticated_user::AuthenticatedUser;
use crate::configuration::ApplicationConfiguration;
use crate::cookie_functions::{
    build_new_cookie_response, build_new_encrypted_authentication_cookie, COOKIE_NAME,
};
use crate::header_value_trait::HeaderValueExctractor;
use crate::http_traits::CustomHttpResponse;
use actix_web::{error::ErrorUnauthorized, http, web, Error, HttpRequest, HttpResponse};
use uuid::Uuid;

/// Get the possible authenticated user from cookies.
/// Returns immediately with a ready future.
/// The future is needed for impl FromRequest.
///
/// # Arguments
///
/// - `req`: containing the header with the cookies for authentication
///
/// # Returns
///
/// `Result<AuthenticatedUser, HttpResponse>`
pub fn get_authenticated_user(req: &HttpRequest) -> Result<AuthenticatedUser, Error> {
    let app_data: Option<&web::Data<ApplicationConfiguration>> = req.app_data();
    if app_data.is_none() {
        warn!("app_data is empty(none)!");
        return Err(ErrorUnauthorized("ERROR: no app_data!"));
    }
    let application_configuration = app_data.unwrap().clone();

    for header_value in req.head().headers().get_all(http::header::COOKIE) {
        debug!(
            "get_authenticated_user(), header_value = {:?}",
            &header_value
        );

        if let Some(cookie) = header_value.get_value_for_cookie_with_name(COOKIE_NAME) {
            debug!("cookie = {}", &cookie);
            let plain_cookie;
            {
                let rsa_read_lock = application_configuration.rsa_keys.read().unwrap();
                plain_cookie = match rsa_read_lock.rsa_private_key {
                    Some(_) => rsa_read_lock
                        .decrypt_str(&cookie)
                        .unwrap_or("invalid_rsa_cookie_value".to_string()),
                    None => String::from_utf8(
                        base64::decode(&cookie)
                            .unwrap_or("invalid_base64_cookie".as_bytes().to_vec()),
                    )
                    .unwrap_or("invalid_base64_utf8".to_string()),
                };
            }
            if let Ok(parsed_cookie_uuid) = Uuid::parse_str(&plain_cookie) {
                if let Some(authenticated_user) = application_configuration
                    .shared_authenticated_users
                    .read()
                    .unwrap()
                    .authenticated_users_hashmap
                    .get(&parsed_cookie_uuid)
                {
                    debug!(
                        "cookie = {}, authenticated_user = {}",
                        &cookie, authenticated_user.user_name
                    );
                    return Ok(authenticated_user.clone());
                }
            } else {
                warn!("Can not parse uuid from cookie! cookie = {}", &cookie);
                return Err(ErrorUnauthorized(
                    "ERROR: authorization cookie can not be parsed! Who are you?",
                ));
            }
        }
    }
    warn!("No cookie with name {} found!", COOKIE_NAME);
    Err(ErrorUnauthorized(
        "ERROR: no matching cookie found! Authorization expired?",
    ))
}

/// Update the cookie lifetime of the authenticated user.
///
/// # Arguments
///
/// - `req`: `HttpRequest` containing the header with the cookies for authentication
///
/// # Returns
///
/// `HttpResponse`
pub fn update_authenticated_user_cookie_lifetime(req: &HttpRequest) -> HttpResponse {
    let app_data: Option<&web::Data<ApplicationConfiguration>> = req.app_data();
    if app_data.is_none() {
        warn!("app_data is empty(none)!");
        return HttpResponse::from_error(ErrorUnauthorized("ERROR: no app_data!"));
    }
    let application_configuration = app_data.unwrap().clone();
    for header_value in req.head().headers().get_all(http::header::COOKIE) {
        debug!(
            "update_authenticated_user_cookie_lifetime(), header_value = {:?}",
            &header_value
        );
        if let Some(cookie) = header_value.get_value_for_cookie_with_name(COOKIE_NAME) {
            let plain_cookie;
            {
                let rsa_read_lock = application_configuration.rsa_keys.read().unwrap();
                plain_cookie = match rsa_read_lock.rsa_private_key {
                    Some(_) => rsa_read_lock
                        .decrypt_str(&cookie)
                        .unwrap_or("invalid_rsa".to_string()),
                    None => String::from_utf8(base64::decode(&cookie).unwrap())
                        .unwrap_or("invalid_base64".to_string()),
                };
            }
            if let Ok(parsed_cookie_uuid) = Uuid::parse_str(&plain_cookie) {
                let mut shared_authenticated_users_write_lock= application_configuration
                    .shared_authenticated_users
                    .write()
                    .unwrap();
                if let Some(authenticated_user) = shared_authenticated_users_write_lock
                    .authenticated_users_hashmap
                    .get_mut(&parsed_cookie_uuid)
                {
                    debug!(
                        "cookie = {}, authenticated_user = {}, updating cookie lifetime",
                        &cookie, authenticated_user.user_name
                    );
                    // update the timestamp in the hashmap, so that the cleanup routine
                    // will not remove this entry
                    authenticated_user.update_timestamp();
                    // create cookie with the same value but renewed cookie lifetime
                    let rsa_read_lock = application_configuration.rsa_keys.read().unwrap();
                    let updated_cookie = build_new_encrypted_authentication_cookie(
                        parsed_cookie_uuid.to_string(),
                        application_configuration
                            .configuration_file
                            .max_cookie_age_seconds,
                        &rsa_read_lock,
                    );
                    let cookie_response = build_new_cookie_response(
                        &updated_cookie,
                        application_configuration.configuration_file.fqdn.clone(),
                    );
                    debug!("HttpResponse = {:?}", &cookie_response);
                    return cookie_response;
                }
            } else {
                warn!("Can not parse uuid from cookie! cookie_value = {}", &cookie);
                return HttpResponse::ok_text_response(
                    "ERROR: authorization cookie can not be parsed! Who are you?",
                );
            }
        }
    }
    warn!("No cookie with name {} found!", COOKIE_NAME);
    HttpResponse::ok_text_response("ERROR: no matching cookie found! Authorization expired?")
}
