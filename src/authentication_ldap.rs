extern crate env_logger;
use crate::authentication_middleware::AuthenticationRedirect;
use crate::base64_trait::Base64VecU8Conversions;
use crate::configuration::ApplicationConfiguration;
use crate::cookie_functions::{build_new_encrypted_authentication_cookie, empty_unix_epoch_cookie};
use crate::http_traits::CustomHttpResponse;
use crate::ip_address::IpAdressString;
pub use crate::ldap_common::{LdapCommonConfiguration, LdapSearchResult};
pub use crate::login_user_trait::Login;
use actix_web::{http, http::Method, http::StatusCode, web, web::Bytes, HttpRequest, HttpResponse};
use async_trait::async_trait;
use ldap3::{ldap_escape, LdapConnAsync};
use log::{debug, info, warn};
use regex::Regex;
use serde::Deserialize;
use std::error::Error;
use uuid::Uuid;
use zeroize::Zeroize;

// maximum bytes that can be transferred as login data
const MAX_BYTES: usize = 384;
// maximum length of a password
const MAX_PASSWORD_LENGTH: usize = 128;

/// Holds the configuration to access an LDAP server
/// extending the common ldap configuration with
/// data needed for authentication
#[derive(Clone, Deserialize, Debug)]
pub struct LdapAuthConfiguration {
    pub ldap_bind_user_dn: String,
    pub valid_user_regex: String,
    #[serde(skip_deserializing)]
    pub user_regex: Option<Regex>,
}

#[async_trait(?Send)]
pub trait LdapLogin {
    async fn ldap_login(&self, user_name: &str, password: &str) -> Result<(), Box<dyn Error>>;
}

#[async_trait(?Send)]
impl LdapLogin for LdapCommonConfiguration {
    /// Bind to the ldap server with the given user and password,
    /// AKA login
    ///
    /// # Arguments
    ///
    /// - `user_name`:      uid of the user that should be looked up.
    /// - `password`:       password used to bind
    ///
    /// # Returns
    ///
    /// - `Result<(), Box<dyn Error>>` - either Ok() or an error
    async fn ldap_login(&self, user_name: &str, password: &str) -> Result<(), Box<dyn Error>> {
        let (conn, mut ldap) = LdapConnAsync::new(&self.url).await?;
        ldap3::drive!(conn);
        debug!("Connected to {}", &&self.url);
        ldap.simple_bind(
            &self
                .authentication
                .ldap_bind_user_dn
                .replace("{0}", &ldap_escape(user_name)),
            password,
        )
        .await?
        .success()?;
        debug!("ldap.simple_bind() -> OK");
        Ok(ldap.unbind().await?)
    }
}

/// Data that gets POSTed when
/// a user logs in
#[derive(Deserialize, Debug)]
pub struct LoginData {
    #[serde(rename = "LoginName")]
    pub login_name: String,
    #[serde(rename = "LoginPassword")]
    pub login_password: String,
    #[serde(rename = "RequestId")]
    pub request_id: String,
}

#[async_trait(?Send)]
impl Login for LdapCommonConfiguration {
    async fn login_user(
        bytes: Bytes,
        request: HttpRequest,
        application_configuration: web::Data<ApplicationConfiguration>,
    ) -> HttpResponse {
        debug!("bytes = {:?}", &bytes);
        debug!("request = {:?}", &request);
        let peer_ip = &request.get_peer_ip_address();
        debug!("peer_ip = {:?}", &peer_ip);
        // accept POST method only
        if Method::POST != request.method() {
            return HttpResponse::Forbidden().finish();
        }
        // 1. validate input
        //
        //
        if bytes.len() > MAX_BYTES {
            return HttpResponse::err_text_response(format!(
                "ERROR: more than {} bytes of data sent",
                &MAX_BYTES
            ));
        }
        let bytes_vec = bytes.to_vec();
        let form_data = match String::from_utf8(bytes_vec) {
            Ok(form_data) => form_data,
            Err(_) => {
                return HttpResponse::err_text_response("ERROR: invalid utf8 in form data");
            }
        };
        let mut parsed_form_data = match serde_json::from_str(&form_data) as Result<LoginData, _> {
            Ok(parsed_form_data) => parsed_form_data,
            Err(_) => {
                return HttpResponse::err_text_response("ERROR: could not parse json form data");
            }
        };
        debug!("parsed_form_data={:?}", &parsed_form_data);
        // is the login_name valid?
        // prevent sending bogus data to the ldap server.
        let valid_user_regex = match &application_configuration
            .configuration_file
            .ldap_common_configuration
            .authentication
            .user_regex
        {
            Some(r) => r,
            None => {
                warn!("valid user regex is not defined");
                return HttpResponse::err_text_response("ERROR: valid user regex is not defined");
            }
        };
        if !valid_user_regex.is_match(&parsed_form_data.login_name) {
            return HttpResponse::err_text_response("ERROR: invalid login name format");
        }
        // what ID was assigned to the resource request?
        let request_id = match Uuid::parse_str(&parsed_form_data.request_id) {
            Ok(request_id) => request_id,
            Err(_) => {
                return HttpResponse::err_text_response("ERROR: cannot parse request id");
            }
        };
        info!(
            "login attempt (peer_ip = {}, request_id = {})",
            &peer_ip,
            &request_id.to_string()
        );
        // what url/resource has been requested before login?
        let url_requested;
        {
            // sending of the async ldap queries with the RwLock still locked
            // is not possible, so we will close it right after accessing
            // the data
            let mut auth_state_write_lock = application_configuration
                .shared_request_data
                .write()
                .unwrap();
            let auth_request = match auth_state_write_lock
                .authentication_state_hashmap
                .get_mut(&request_id)
            {
                None => {
                    warn!(
                        "login attempt with expired or invalid authentication request id {}",
                        &request_id
                    );
                    return HttpResponse::err_text_response(
                        "ERROR: invalid request id, login expired",
                    );
                }
                Some(a) => a,
            };
            if auth_request.has_been_used {
                warn!(
                    "authentication request id {} has already been used, possible replay attack!",
                    &request_id
                );
                return HttpResponse::err_text_response("ERROR: login failed");
            } else {
                // mark resource request as used so that this ID cannot be used anymore
                auth_request.has_been_used = true;
                url_requested = auth_request.url_requested.clone();
            }
            // is authentication taking place from the same ip address as the resource request?
            if peer_ip.ne(&auth_request.peer_ip) {
                // NO! This maybe fishy. This also happens if devices have multiple IP addresses, e.g. a laptop with
                // both active wifi and wired ethernet adapters.
                warn!(
                    "IP address changed since resource request: peer_address = {:?}, auth_request = {}",
                    &peer_ip, &auth_request
                );
                return HttpResponse::err_text_response("ERROR: login failed");
            }
        }

        // at this point input data is validated and
        // uuid of the request has been found
        //
        // 2. check if user exists
        // keep it in a block to make the compiler happy
        // because of the result lifetime
        let ldap_search_result = match &application_configuration
            .configuration_file
            .ldap_common_configuration
            .ldap_search_by_uid(
                &parsed_form_data.login_name,
                Some(
                    &application_configuration
                        .configuration_file
                        .ldap_common_configuration
                        .user_filter,
                ),
            )
            .await
        {
            Err(e) => {
                warn!(
                    "error while looking up user {}: {}",
                    &parsed_form_data.login_name, &e
                );
                return HttpResponse::err_text_response("ERROR: login failed");
            }
            Ok(l) => l.clone(),
        };
        // dirty hack to build a json string from the ldap query result,
        // so it can be serialized.
        let ldap_result = match serde_json::from_str(&ldap_search_result.replace(['[', ']'], ""))
            as Result<LdapSearchResult, _>
        {
            Err(e) => {
                warn!(
                    "can not serde_json::from_str({}): {}",
                    &ldap_search_result, &e
                );
                return HttpResponse::err_text_response("ERROR: login failed");
            }
            Ok(r) => r,
        };
        if ldap_result.user_name != parsed_form_data.login_name {
            warn!(
                "user {} does not exist in ldap",
                &parsed_form_data.login_name
            );
            return HttpResponse::err_text_response("ERROR: login failed");
        }

        // 3. try to bind with the given password, AKA login
        //
        //
        info!(
            "user {} exists in ldap, trying bind...",
            &parsed_form_data.login_name
        );
        // the password was encoded before the transfer to make sure
        // that special characters would be transferred correctly.
        // tested with
        // PASS!"§$%&/()=?ß\´`+*~'#-_.:,;<>|WORD
        let base64_decoded_password =
            match Vec::from_base64_encoded(&parsed_form_data.login_password) {
                Ok(v) => v,
                Err(e) => {
                    warn!(
                        "Cannot decode base64 password from user {}: {}",
                        &parsed_form_data.login_name, &e
                    );
                    return HttpResponse::err_text_response("ERROR: login failed");
                }
            };
        let mut password = match String::from_utf8(base64_decoded_password) {
            Ok(decoded_password) => decoded_password.trim_matches(char::from(0)).to_string(),
            Err(e) => {
                warn!(
                    "could not convert to utf8 password from user {}: {}",
                    &parsed_form_data.login_name, &e
                );
                return HttpResponse::err_text_response("ERROR: login not possible");
            }
        };

        if password.len() > MAX_PASSWORD_LENGTH {
            warn!(
                "password of user {} is too long!",
                &parsed_form_data.login_name
            );
            return HttpResponse::err_text_response("ERROR: password is too long!");
        }

        parsed_form_data.login_password.zeroize();
        match &application_configuration
            .configuration_file
            .ldap_common_configuration
            .ldap_login(&parsed_form_data.login_name, &password)
            .await
        {
            Err(e) => {
                password.zeroize();
                warn!(
                    "user {} could not log in: {}",
                    &parsed_form_data.login_name, &e
                );
                return HttpResponse::err_text_response("ERROR: login failed");
            }
            Ok(_) => {
                password.zeroize();

                if let Some(cookie_data) = application_configuration
                    .shared_authenticated_users
                    .write()
                    .unwrap()
                    .new_cookie_data_for(
                        &parsed_form_data.login_name,
                        &ldap_result.first_name,
                        &ldap_result.last_name,
                        &ldap_result.mail,
                        &peer_ip,
                    )
                {
                    info!("login success for user {}", &parsed_form_data.login_name);
                    // The cookie value is encrypted with a generated rsa
                    // public key.
                    let cookie = build_new_encrypted_authentication_cookie(
                        &cookie_data.to_string(),
                        application_configuration
                            .configuration_file
                            .max_cookie_age_seconds,
                        &application_configuration.configuration_file.get_domain(),
                        &application_configuration.rsa_keys_for_cookies,
                    );
                    let proto_fqdn = format!(
                        "https://{}",
                        &application_configuration.configuration_file.fqdn
                    );
                    let redirect_url = format!("{}{}", &proto_fqdn, &url_requested);
                    debug!("redirect_url = {:?}", &redirect_url);
                    // set authentication cookie and answer
                    // with url to open.
                    return HttpResponse::ok_text_response_with_cookie(redirect_url, cookie);
                } else {
                    warn!(
                        "cannot create cookie id for user {}",
                        &parsed_form_data.login_name
                    );
                    return HttpResponse::err_text_response("ERROR: login failed");
                }
            }
        }
    }

    fn build_valid_user_regex(&mut self) -> Result<(), Box<dyn Error>> {
        let user_regex = Regex::new(&self.authentication.valid_user_regex)?;
        self.authentication.user_regex = Some(user_regex);
        Ok(())
    }
}

impl AuthenticationRedirect for LdapCommonConfiguration {
    fn get_authentication_redirect_response(
        _request_path_with_query: &str,
        request_uuid: &Uuid,
        application_configuration: &ApplicationConfiguration,
    ) -> HttpResponse {
        let redirect_url = format!(
            "https://{}/authentication/ldap.html?request={}",
            &application_configuration.configuration_file.fqdn,
            &request_uuid.to_string()
        );
        debug!(
            "get_authentication_redirect_response() => {}",
            &redirect_url
        );
        let authentication_redirect_response = HttpResponse::build(StatusCode::FOUND)
            .append_header((http::header::LOCATION, redirect_url))
            .append_header((
                http::header::SET_COOKIE,
                empty_unix_epoch_cookie().to_string(),
            ))
            .finish();
        authentication_redirect_response
    }
}
