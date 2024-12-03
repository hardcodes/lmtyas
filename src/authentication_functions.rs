use log::{debug, warn};
extern crate env_logger;
use crate::authenticated_user::AuthenticatedUser;
use crate::configuration::ApplicationConfiguration;
use crate::cookie_functions::{
    build_new_cookie_response, build_new_encrypted_authentication_cookie,
    get_decrypted_cookie_data, CookieData, COOKIE_NAME,
};
use crate::header_value_trait::HeaderValueExctractor;
use crate::http_traits::CustomHttpResponse;
use actix_web::{error::ErrorUnauthorized, http, web, Error, HttpRequest, HttpResponse};

/// Convenience function that returns the `Uuid` encoded in the authentication
/// cookie that may be inside the headers of the `HttpRequest`.
#[inline]
pub fn get_cookie_uuid_from_http_request(
    req: &HttpRequest,
    application_configuration: &ApplicationConfiguration,
) -> Option<CookieData> {
    for header_value in req.head().headers().get_all(http::header::COOKIE) {
        debug!("get_cookie_uuid(), header_value = {:?}", &header_value);

        if let Some(encrypted_cookie_value) =
            header_value.get_value_for_cookie_with_name(COOKIE_NAME)
        {
            debug!("encrypted_cookie_value = {}", &encrypted_cookie_value);
            if let Ok(decrypted_cookie_data) = get_decrypted_cookie_data(
                &encrypted_cookie_value,
                &application_configuration.rsa_keys_for_cookies,
            ) {
                return Some(decrypted_cookie_data);
            } else {
                warn!(
                    "Can not decrypt/parse cookie! cookie = {}",
                    &encrypted_cookie_value
                );
            }
        }
    }
    debug!("No cookie found!");
    None
}

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
    let parsed_cookie_data =
        match get_cookie_uuid_from_http_request(req, &application_configuration) {
            Some(uuid) => uuid,
            None => {
                return Err(ErrorUnauthorized(
                    "ERROR: no matching cookie found! Authorization expired?",
                ));
            }
        };

    if let Some(authenticated_user) = application_configuration
        .shared_authenticated_users
        .read()
        .unwrap()
        .authenticated_users_hashmap
        .get(&parsed_cookie_data.uuid)
    {
        debug!(
            "parsed_cookie_data = {}, authenticated_user = {}",
            &parsed_cookie_data, authenticated_user.user_name
        );
        let unix_timestamp_to_compare = authenticated_user.time_stamp.timestamp() as u64;
        if parsed_cookie_data.unix_timestamp != unix_timestamp_to_compare {
            warn!(
                "Cookie timestamp does not match; cookie: {}, must be = {} ",
                &parsed_cookie_data.unix_timestamp, &unix_timestamp_to_compare
            );
            return Err(ErrorUnauthorized(
                "ERROR: no matching cookie found! Authorization expired?",
            ));    
        }
        // OK, cookie is valid
        return Ok(authenticated_user.clone());
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
    let mut parsed_cookie_data =
        match get_cookie_uuid_from_http_request(req, &application_configuration) {
            Some(uuid) => uuid,
            None => {
                return HttpResponse::ok_text_response(
                    "ERROR: no matching cookie found! Authorization expired?",
                );
            }
        };

    let mut shared_authenticated_users_write_lock = application_configuration
        .shared_authenticated_users
        .write()
        .unwrap();
    if let Some(authenticated_user) = shared_authenticated_users_write_lock
        .authenticated_users_hashmap
        .get_mut(&parsed_cookie_data.uuid)
    {
        debug!(
            "parsed_cookie_uuid = {}, authenticated_user = {}, updating cookie lifetime",
            &parsed_cookie_data.to_string(),
            authenticated_user.user_name
        );
        let timestamp_to_compare = authenticated_user.time_stamp.timestamp() as u64;
        // Update only if timestamp matches
        if parsed_cookie_data.unix_timestamp != timestamp_to_compare {
            warn!(
                "cookie timestamp does not match; cookie: {}, must be = {} ",
                &parsed_cookie_data.unix_timestamp, &timestamp_to_compare
            );
            return HttpResponse::ok_text_response(
                "ERROR: no matching cookie found! Authorization expired?",
            );
        }
        // Update the timestamp in the hashmap, so that the cleanup routine
        // will not remove this entry
        authenticated_user.update_timestamp();
        parsed_cookie_data.unix_timestamp = authenticated_user.time_stamp.timestamp() as u64;
        // create cookie with same uuid value but renewed cookie lifetime
        let updated_cookie = build_new_encrypted_authentication_cookie(
            &parsed_cookie_data.to_string(),
            application_configuration
                .configuration_file
                .max_cookie_age_seconds,
            &application_configuration.configuration_file.get_domain(),
            &application_configuration.rsa_keys_for_cookies,
        );
        let cookie_response = build_new_cookie_response(
            &updated_cookie,
            application_configuration.configuration_file.fqdn.clone(),
        );
        debug!(
            "updated cookie lifetime, HttpResponse = {:?}",
            &cookie_response
        );
        return cookie_response;
    }

    warn!("No cookie with name {} found!", COOKIE_NAME);
    HttpResponse::ok_text_response("ERROR: no matching cookie found! Authorization expired?")
}
