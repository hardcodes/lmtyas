extern crate env_logger;
use crate::authentication_middleware::AuthenticationRedirect;
use crate::authentication_middleware::PeerIpAddress;
use crate::authentication_middleware::UNKNOWN_PEER_IP;
use crate::authentication_url::AUTH_LOGIN_FAIL_PAGE;
use crate::configuration::ApplicationConfiguration;
use crate::http_traits::CustomHttpResponse;
pub use crate::login_user_trait::Login;
use actix_web::{
    http, http::Method, http::StatusCode, web, web::Bytes, web::Query, HttpRequest, HttpResponse,
};
use async_trait::async_trait;
use chrono::Duration;
use chrono::{DateTime, Utc};
use log::{debug, info, warn};
use openidconnect::CodeTokenRequest;
use openidconnect::{
    core::{
        CoreAuthenticationFlow, CoreClient, CoreProviderMetadata, CoreResponseType,
        CoreUserInfoClaims,
    },
    reqwest::async_http_client,
    AccessTokenHash, AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

/// Holds the configuration to access an oidc server
/// for user authentication
#[derive(Clone, Deserialize, Debug)]
pub struct OidcConfiguration {
    pub provider_metadata_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub valid_user_regex: String,
    #[serde(skip_deserializing)]
    pub user_regex: Option<Regex>,
}

/// Stores the information that is needed
/// to validate a response from the oidc
/// server
pub struct OidcVerificationData {
    pub pkce_verifier: PkceCodeVerifier,
    pub csrf_token: CsrfToken,
    pub nonce: Nonce,
    /// when was the request made, used to prune old entries
    pub time_stamp: DateTime<Utc>,
    /// will be set to true when a (possible) assertion has arrived
    pub has_been_used: bool,
}

impl OidcVerificationData {
    pub fn new(pkce_verifier: PkceCodeVerifier, csrf_token: CsrfToken, nonce: Nonce) -> Self {
        Self {
            pkce_verifier,
            csrf_token,
            nonce,
            time_stamp: Utc::now(),
            has_been_used: false,
        }
    }
}

/// custom formatter to suppress secrets
impl fmt::Display for OidcVerificationData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(has_been_used={}, time_stamp={}, state={})",
            self.has_been_used,
            self.time_stamp,
            self.csrf_token.secret()
        )
    }
}

pub type SharedOidcVerificationDataHashMap = HashMap<Uuid, OidcVerificationData>;

/// Removes aged authentication requests
#[inline]
pub fn cleanup_oidc_authentication_data_hashmap(
    shared_oidc_verfication_data: &Arc<RwLock<SharedOidcVerificationDataHashMap>>,
    max_age_in_seconds: i64,
) {
    let time_to_delete = Utc::now() - Duration::seconds(max_age_in_seconds);
    let shared_oidc_verfication_data_read_lock = shared_oidc_verfication_data.read().unwrap();
    let mut items_to_remove: Vec<uuid::Uuid> = Vec::new();
    shared_oidc_verfication_data_read_lock
        .iter()
        .for_each(|(k, v)| {
            // remove authentication requests that already have been used
            // or were not used in a timely manner
            if v.has_been_used || v.time_stamp < time_to_delete {
                info!(
                    "removing oidc authentication data {} {}",
                    &k.to_string(),
                    &v.to_string()
                );
                items_to_remove.push(*k);
            }
        });
    drop(shared_oidc_verfication_data_read_lock);

    let mut shared_oidc_verfication_data_write_lock = shared_oidc_verfication_data.write().unwrap();
    for item in items_to_remove {
        shared_oidc_verfication_data_write_lock.remove(&item);
    }
}

fn handle_error<T: std::error::Error>(fail: &T, message: &'static str) {
    let mut error_mesage = format!("{}", message);
    let mut current_fail: Option<&dyn std::error::Error> = Some(fail);
    while let Some(cause) = current_fail {
        error_mesage += &format!("\n    caused by: {}", cause);
        current_fail = cause.source();
    }
    warn!("{}", error_mesage);
}

#[async_trait(?Send)]
impl Login for OidcConfiguration {
    async fn login_user(
        _bytes: Bytes,
        request: HttpRequest,
        application_configuration: web::Data<ApplicationConfiguration>,
    ) -> HttpResponse {
        debug!("oidc response:\n\n{:?}", request);
        // accept GET method only
        if Method::GET != request.method() {
            return HttpResponse::Forbidden().finish();
        }
        let peer_ip = Peer::get_peer_ip_address(&request);
        debug!("peer_address = {:?}", &peer_ip);

        // extract "code" and "state"
        let query = match Query::<HashMap<String, String>>::from_query(request.query_string()) {
            Ok(q) => q,
            Err(e) => {
                warn!(
                    "cannot create hashmap from oidc response parameters: {}",
                    &e
                );
                return HttpResponse::build(StatusCode::SEE_OTHER)
                    .append_header((http::header::LOCATION, AUTH_LOGIN_FAIL_PAGE))
                    .finish();
            }
        };
        let response_code = match query.get("code") {
            Some(c) => c,
            None => {
                warn!("no 'code' in oidc response");
                return HttpResponse::build(StatusCode::SEE_OTHER)
                    .append_header((http::header::LOCATION, AUTH_LOGIN_FAIL_PAGE))
                    .finish();
            }
        };
        let response_state = match query.get("state") {
            Some(s) => s,
            None => {
                warn!("no 'state' in oidc response");
                return HttpResponse::build(StatusCode::SEE_OTHER)
                    .append_header((http::header::LOCATION, AUTH_LOGIN_FAIL_PAGE))
                    .finish();
            }
        };

        let code = AuthorizationCode::new(response_code.to_string());
        let state = CsrfToken::new(response_state.to_string());

        debug!("code = {:?}", &code);
        debug!("state = {:?}", &state);

        // what ID was assigned to the resource request?
        let request_id = match Uuid::parse_str(state.secret()) {
            Ok(request_id) => request_id,
            Err(_) => {
                warn!("state cannot be parsed as uuid");
                return HttpResponse::build(StatusCode::SEE_OTHER)
                    .append_header((http::header::LOCATION, AUTH_LOGIN_FAIL_PAGE))
                    .finish();
            }
        };
        debug!("request_id = {}", &request_id.to_string());
        // what url/resource has been requested before login?
        let url_requested;
        {
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
                    return HttpResponse::build(StatusCode::SEE_OTHER)
                        .append_header((http::header::LOCATION, AUTH_LOGIN_FAIL_PAGE))
                        .finish();
                }
                Some(a) => a,
            };
            if auth_request.has_been_used {
                warn!(
                    "authentication request id {} has already been used, possible replay attack!",
                    &request_id
                );
                return HttpResponse::build(StatusCode::SEE_OTHER)
                    .append_header((http::header::LOCATION, AUTH_LOGIN_FAIL_PAGE))
                    .finish();
            } else {
                // mark resource request as used so that this ID cannot be used anymore
                auth_request.has_been_used = true;
                url_requested = auth_request.url_requested.clone();
            };
            // is authentication taking place from the same ip address as the resource request?
            if peer_ip.ne(&auth_request.peer_ip) {
                warn!(
                "IP address changed since resource request: peer_address = {:?}, auth_request = {}",
                &peer_ip, &auth_request
            );
                return HttpResponse::build(StatusCode::SEE_OTHER)
                    .append_header((http::header::LOCATION, AUTH_LOGIN_FAIL_PAGE))
                    .finish();
            }
        }
        debug!("url_requested = {}", &url_requested);

        // At this point we made sure that the response refers to a resource
        // request that we've already seen.
        // Next: verify that the response is valid = get the access token
        let pkce_verifier_secret;
        let nonce;
        {
            let mut shared_oidc_verfication_data_write_lock = application_configuration
                .shared_oidc_verification_data
                .write()
                .unwrap();
            let oidc_verification_data =
                match shared_oidc_verfication_data_write_lock.get_mut(&request_id) {
                    None => {
                        warn!(
                    "oidc login attempt with expired or invalid oidc verification data id {}",
                    &request_id
                );
                        return HttpResponse::build(StatusCode::SEE_OTHER)
                            .append_header((http::header::LOCATION, AUTH_LOGIN_FAIL_PAGE))
                            .finish();
                    }
                    Some(a) => a,
                };
            if oidc_verification_data.has_been_used {
                warn!(
                    "oidc verification data id {} has already been used, possible replay attack!",
                    &request_id
                );
                return HttpResponse::build(StatusCode::SEE_OTHER)
                    .append_header((http::header::LOCATION, AUTH_LOGIN_FAIL_PAGE))
                    .finish();
            } else {
                // mark oidc verification data as used so that this ID cannot be used anymore
                // This should not even be possible since the request id has already been
                // validated, but better safe than sorry.
                oidc_verification_data.has_been_used = true;
            }
            // PkceCodeVerifier does not implement the copy trait
            pkce_verifier_secret = oidc_verification_data.pkce_verifier.secret().to_owned();
            nonce = oidc_verification_data.nonce.to_owned();
        }
        let pkce_verifier = PkceCodeVerifier::new(pkce_verifier_secret);
        info!("Getting ID token for request_id {}", &request_id);
        let token_response = match application_configuration
            .oidc_client
            .exchange_code(code)
            .set_pkce_verifier(pkce_verifier)
            .request_async(async_http_client)
            .await
        {
            Ok(t) => t,
            Err(e) => {
                handle_error(&e, "ID token request failed.");
                // so far we get
                // "data did not match any variant of untagged enum Timestamp"
                return HttpResponse::build(StatusCode::SEE_OTHER)
                    .append_header((http::header::LOCATION, AUTH_LOGIN_FAIL_PAGE))
                    .finish();
            }
        };

        debug!("token_response = {:?}", &token_response);
        // Extract the ID token.
        let id_token = match token_response.id_token() {
            Some(t) => t,
            None => {
                warn!("ID token cannot be extracted");
                return HttpResponse::build(StatusCode::SEE_OTHER)
                    .append_header((http::header::LOCATION, AUTH_LOGIN_FAIL_PAGE))
                    .finish();
            }
        };
        info!("Received ID token for request_id {}", &request_id);

        let claims = match id_token.claims(
            &application_configuration.oidc_client.id_token_verifier(),
            &nonce,
        ) {
            Ok(c) => c,
            Err(e) => {
                handle_error(&e, "Cannot extract claims from ID token.");
                return HttpResponse::build(StatusCode::SEE_OTHER)
                    .append_header((http::header::LOCATION, AUTH_LOGIN_FAIL_PAGE))
                    .finish();
            }
        };

        let access_token_hash = match claims.access_token_hash() {
            Some(a) => a,
            None => {
                warn!("Cannot extract access token hash from claims");
                return HttpResponse::build(StatusCode::SEE_OTHER)
                    .append_header((http::header::LOCATION, AUTH_LOGIN_FAIL_PAGE))
                    .finish();
            }
        };

        debug!("access_token_hash = {:?}", &access_token_hash);

        let _signing_algorithm = match id_token.signing_alg() {
            Ok(a) => a,
            Err(e) => {
                handle_error(&e, "Cannot extract signing algorithm from ID token.");
                return HttpResponse::build(StatusCode::SEE_OTHER)
                    .append_header((http::header::LOCATION, AUTH_LOGIN_FAIL_PAGE))
                    .finish();
            }
        };

        HttpResponse::Forbidden().finish()
    }

    fn build_valid_user_regex(&mut self) -> Result<(), Box<dyn Error>> {
        let user_regex = Regex::new(&self.valid_user_regex)?;
        self.user_regex = Some(user_regex);
        Ok(())
    }
}

impl AuthenticationRedirect for OidcConfiguration {
    fn get_authentication_redirect_response(
        _request_path_with_query: &str,
        request_uuid: &Uuid,
        application_configuration: &ApplicationConfiguration,
    ) -> HttpResponse {
        // Generate a PKCE challenge, so that we can validate the response from the
        // oidc server later on.
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        // use our request_uuid as csrf token. It can be revealed since
        // the response is validated by requesting an access token.
        let csrf_token = CsrfToken::new(request_uuid.to_string());
        let (redirect_url, csrf_token, nonce) = &application_configuration
            .oidc_client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                move || csrf_token,
                Nonce::new_random,
            )
            // Set the desired scopes.
            .add_scope(Scope::new("email".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            // Set the PKCE code challenge.
            .set_pkce_challenge(pkce_challenge)
            .url();
        let verification_data =
            OidcVerificationData::new(pkce_verifier, csrf_token.to_owned(), nonce.to_owned());
        debug!(
            "get_authentication_redirect_response() => {}",
            &redirect_url
        );
        let mut shared_oidc_verfication_data_write_lock = application_configuration
            .shared_oidc_verification_data
            .write()
            .unwrap();
        // use the same uuid as in the AuthenticationState, so we can find it later on
        let uuid = request_uuid.to_owned();
        shared_oidc_verfication_data_write_lock.insert(uuid, verification_data);
        drop(shared_oidc_verfication_data_write_lock);
        HttpResponse::build(StatusCode::SEE_OTHER)
            .append_header((http::header::LOCATION, redirect_url.as_str()))
            .finish()
    }
}

struct Peer;

impl PeerIpAddress for Peer {
    fn get_peer_ip_address(request: &HttpRequest) -> String {
        match request.peer_addr() {
            None => UNKNOWN_PEER_IP.to_string(),
            Some(s) => s.ip().to_string(),
        }
    }
}
