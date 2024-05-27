use log::{debug, warn};
extern crate env_logger;
use crate::authenticated_user::AuthenticatedUser;
use crate::configuration::ApplicationConfiguration;
use crate::cookie_functions::{
    build_new_authentication_cookie, build_new_cookie_response, get_plain_cookie_string,
    COOKIE_NAME,
};
use crate::header_value_trait::HeaderValueExctractor;
use crate::http_traits::CustomHttpResponse;
use actix_web::{error::ErrorUnauthorized, http, web, Error, HttpRequest, HttpResponse};
use uuid::Uuid;

/// Get the possible authenticated user from cookies.
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
                // when the rsa key pair already has been loaded,
                // the cookie value is encrypted with the rsa public
                // key otherwise its simply base64 encoded.
                plain_cookie = get_plain_cookie_string(&cookie, &rsa_read_lock);
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
            let rsa_read_lock = application_configuration.rsa_keys.read().unwrap();
            // when the rsa key pair already has been loaded,
            // the cookie value is encrypted with the rsa public
            // key otherwise its simply base64 encoded.
            let plain_cookie = get_plain_cookie_string(&cookie, &rsa_read_lock);
            if let Ok(parsed_cookie_uuid) = Uuid::parse_str(&plain_cookie) {
                let mut shared_authenticated_users_write_lock = application_configuration
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
                    let updated_cookie = build_new_authentication_cookie(
                        &parsed_cookie_uuid.to_string(),
                        application_configuration
                            .configuration_file
                            .max_cookie_age_seconds,
                        &application_configuration.configuration_file.get_domain(),
                        &rsa_read_lock,
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
            } else {
                warn!("Can not parse uuid from cookie! cookie_value = {}", &cookie);
                return HttpResponse::err_text_response(
                    "ERROR: authorization cookie can not be parsed! Who are you?",
                );
            }
        }
    }
    warn!("No cookie with name {} found!", COOKIE_NAME);
    HttpResponse::err_text_response("ERROR: no matching cookie found! Authorization expired?")
}
