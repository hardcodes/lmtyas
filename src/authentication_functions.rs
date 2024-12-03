use log::{debug, info, warn};
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

/// Convenience function that returns `CookieData` encoded in the authentication
/// cookie that may be inside the headers of the `HttpRequest`.
#[inline]
pub fn get_decrypted_cookie_data_from_http_request(
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
pub fn get_authenticated_user_from_request(req: &HttpRequest) -> Result<AuthenticatedUser, Error> {
    let app_data: Option<&web::Data<ApplicationConfiguration>> = req.app_data();
    if app_data.is_none() {
        warn!("app_data is none (get_authenticated_user_from_request)!");
        return Err(ErrorUnauthorized("ERROR: no app_data!"));
    }
    let application_configuration = app_data.unwrap().clone();
    let decrypted_cookie_data =
        match get_decrypted_cookie_data_from_http_request(req, &application_configuration) {
            Some(cookie_data) => cookie_data,
            None => {
                info!("Cannot get authenticated user, no cookie data found.");
                return Err(ErrorUnauthorized(
                    "ERROR: no valid cookie found! Authorization expired?",
                ));
            }
        };

    if let Some(authenticated_user) = application_configuration
        .shared_authenticated_users
        .read()
        .unwrap()
        .authenticated_users_hashmap
        .get(&decrypted_cookie_data.uuid)
    {
        debug!(
            "decrypted_cookie_data = {}, authenticated_user = {}",
            &decrypted_cookie_data, authenticated_user.user_name
        );
        if decrypted_cookie_data.cookie_update_lifetime_counter != authenticated_user.cookie_update_lifetime_counter {
            warn!(
                "Cookie lifetime counter does not match: (cookie = {}, expected = {})",
                &decrypted_cookie_data.cookie_update_lifetime_counter, &authenticated_user.cookie_update_lifetime_counter
            );
            return Err(ErrorUnauthorized(
                "ERROR: no matching cookie found! Authorization expired?",
            ));
        }
        // OK, cookie is valid
        return Ok(authenticated_user.clone());
    }

    warn!(
        "No cookie with name {} or no authenticated_user found!",
        COOKIE_NAME
    );
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
    let decrypted_cookie_data =
        match get_decrypted_cookie_data_from_http_request(req, &application_configuration) {
            Some(uuid) => uuid,
            None => {
                info!("Cannot update cookie lifetime, no valid cookie data.");
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
        .get_mut(&decrypted_cookie_data.uuid)
    {
        debug!(
            "decrypted_cookie_data = {}, authenticated_user = {}, updating cookie lifetime",
            &decrypted_cookie_data.to_string(),
            authenticated_user.user_name
        );
        // Update only if timestamp matches
        if decrypted_cookie_data.cookie_update_lifetime_counter != authenticated_user.cookie_update_lifetime_counter {
            warn!(
                "Cannot update cookie lifetime, counter does not match: (cookie = {}, expected = {})",
                &decrypted_cookie_data.cookie_update_lifetime_counter, &authenticated_user.cookie_update_lifetime_counter
            );
            return HttpResponse::ok_text_response(
                "ERROR: no matching cookie found! Authorization expired?",
            );
        }
        // Update the timestamp in the hashmap, so that the cleanup routine
        // will not remove this entry
        authenticated_user.update_timestamp();
        // create cookie with same uuid value but renewed cookie lifetime
        let updated_cookie = build_new_encrypted_authentication_cookie(
            &decrypted_cookie_data.to_string(),
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

    warn!(
        "No cookie with name {} or no authenticated_user found!",
        COOKIE_NAME
    );
    HttpResponse::ok_text_response("ERROR: no matching cookie found! Authorization expired?")
}

// TODO: extract common parts of get_authenticated_user_from_request and update_authenticated_user_cookie_lifetime
