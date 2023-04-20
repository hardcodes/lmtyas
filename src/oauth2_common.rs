extern crate env_logger;
use crate::authentication_middleware::AuthenticationRedirect;
use crate::authentication_middleware::PeerIpAddress;
use crate::authentication_middleware::UNKNOWN_PEER_IP;
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
use oauth2::TokenResponse;
use oauth2::{
    reqwest::async_http_client, AuthorizationCode, CsrfToken, PkceCodeChallenge, PkceCodeVerifier,
    Scope,
};
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

/// Holds the configuration to access an oauth server
/// for user authentication
#[derive(Clone, Deserialize, Debug)]
pub struct Oauth2Configuration {
    pub client_id: String,
    pub client_secret: String,
    pub auth_url: String,
    pub token_url: String,
    pub valid_user_regex: String,
    #[serde(skip_deserializing)]
    pub user_regex: Option<Regex>,
}

/// Stores the information that is needed
/// to validate a response from the oauth2
/// server
pub struct Oauth2VerificationData {
    pub pkce_verifier: PkceCodeVerifier,
    pub csrf_token: CsrfToken,
    /// when was the request made, used to prune old entries
    pub time_stamp: DateTime<Utc>,
    /// will be set to true when a (possible) assertion has arrived
    pub has_been_used: bool,
}

impl Oauth2VerificationData {
    pub fn new(pkce_verifier: PkceCodeVerifier, csrf_token: CsrfToken) -> Self {
        Self {
            pkce_verifier,
            csrf_token,
            time_stamp: Utc::now(),
            has_been_used: false,
        }
    }
}

/// custom formatter to suppress secrets
impl fmt::Display for Oauth2VerificationData {
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

pub type SharedOauth2VerificationDataHashMap = HashMap<Uuid, Oauth2VerificationData>;

/// Removes aged authentication requests
#[inline]
pub fn cleanup_oauth2_authentication_data_hashmap(
    shared_oauth2_verfication_data: &Arc<RwLock<SharedOauth2VerificationDataHashMap>>,
    max_age_in_seconds: i64,
) {
    let time_to_delete = Utc::now() - Duration::seconds(max_age_in_seconds);
    let shared_oauth2_verfication_data_read_lock = shared_oauth2_verfication_data.read().unwrap();
    let mut items_to_remove: Vec<uuid::Uuid> = Vec::new();
    shared_oauth2_verfication_data_read_lock
        .iter()
        .for_each(|(k, v)| {
            // remove authentication requests that already have been used
            // or were not used in a timely manner
            if v.has_been_used || v.time_stamp < time_to_delete {
                info!(
                    "removing oauth2 authentication data {} {}",
                    &k.to_string(),
                    &v.to_string()
                );
                items_to_remove.push(*k);
            }
        });
    drop(shared_oauth2_verfication_data_read_lock);

    let mut shared_oauth2_verfication_data_write_lock =
        shared_oauth2_verfication_data.write().unwrap();
    for item in items_to_remove {
        shared_oauth2_verfication_data_write_lock.remove(&item);
    }
}

#[async_trait(?Send)]
impl Login for Oauth2Configuration {
    async fn login_user(
        _bytes: Bytes,
        request: HttpRequest,
        application_configuration: web::Data<ApplicationConfiguration>,
    ) -> HttpResponse {
        debug!("oauth2 response:\n\n{:?}", request);
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
                    "cannot create hashmap from oauth response parameters: {}",
                    &e
                );
                return HttpResponse::err_text_response("ERROR: invalid response");
            }
        };
        let response_code = match query.get("code") {
            Some(c) => c,
            None => {
                warn!("no 'code' in oauth response");
                return HttpResponse::err_text_response("ERROR: invalid response");
            }
        };
        let response_state = match query.get("state") {
            Some(s) => s,
            None => {
                warn!("no 'state' in oauth response");
                return HttpResponse::err_text_response("ERROR: invalid response");
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
                return HttpResponse::err_text_response("ERROR: invalid response");
            }
        };
        debug!("request_id = {}", &request_id.to_string());
        // what url/resource has been requested before login?
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
                return HttpResponse::err_text_response("ERROR: invalid request id, login expired");
            }
            Some(a) => a,
        };
        let url_requested = if auth_request.has_been_used {
            warn!(
                "authentication request id {} has already been used, possible replay attack!",
                &request_id
            );
            return HttpResponse::err_text_response("ERROR: login failed");
        } else {
            // mark resource request as used so that this ID cannot be used anymore
            auth_request.has_been_used = true;
            auth_request.url_requested.clone()
        };
        // is authentication taking place from the same ip address as the resource request?
        if peer_ip.ne(&auth_request.peer_ip) {
            warn!(
                "IP address changed since resource request: peer_address = {:?}, auth_request = {}",
                &peer_ip, &auth_request
            );
            return HttpResponse::err_text_response("ERROR: login failed");
        }
        drop(auth_state_write_lock);
        debug!("url_requested = {}", &url_requested);

        // At this point we made sure that the response refers to a resource
        // request that we've already seen.
        // Next: verify that the response is valid = get the access token
        let mut shared_oauth2_verfication_data_write_lock = application_configuration
            .shared_oauth2_verification_data
            .write()
            .unwrap();
        let oauth2_verification_data = match shared_oauth2_verfication_data_write_lock
            .get_mut(&request_id)
        {
            None => {
                warn!(
                    "oauth login attempt with expired or invalid oauth verification data id {}",
                    &request_id
                );
                return HttpResponse::err_text_response("ERROR: invalid request id, login expired");
            }
            Some(a) => a,
        };
        if oauth2_verification_data.has_been_used {
            warn!(
                "oauth verification data id {} has already been used, possible replay attack!",
                &request_id
            );
            return HttpResponse::err_text_response("ERROR: login failed");
        } else {
            // mark oauth verification data as used so that this ID cannot be used anymore
            // This should not even be possible since the request id has already been
            // validated, but better safe than sorry.
            oauth2_verification_data.has_been_used = true;
        }
        // PkceCodeVerifier does not implement the copy trait
        let pkce_verifier_secret = oauth2_verification_data.pkce_verifier.secret().to_owned();
        drop(shared_oauth2_verfication_data_write_lock);
        info!("Getting access token for request_id {}", &request_id);
        let token_result = match application_configuration
            .oauth2_client
            .exchange_code(code)
            .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier_secret))
            .request_async(async_http_client)
            .await
        {
            Ok(t) => t,
            Err(e) => {
                warn!("Token request failed: {}", &e);
                return HttpResponse::err_text_response("ERROR: login failed");
            }
        };
        info!("Received access token for request_id {}", &request_id);
        debug!("token_result = {:?}", &token_result.access_token().secret());

        // At this point the user has authorized us to access the wanted information,
        // we still do not know who he/she/it is.
        HttpResponse::Forbidden().finish()
    }

    fn build_valid_user_regex(&mut self) -> Result<(), Box<dyn Error>> {
        let user_regex = Regex::new(&self.valid_user_regex)?;
        self.user_regex = Some(user_regex);
        Ok(())
    }
}

impl AuthenticationRedirect for Oauth2Configuration {
    fn get_authentication_redirect_response(
        _request_path_with_query: &str,
        request_uuid: &Uuid,
        application_configuration: &ApplicationConfiguration,
    ) -> HttpResponse {
        // Generate a PKCE challenge, so that we can validate the response from the
        // oauth2 server later on.
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        // use our request_uuid as csrf token. It can be revealed since
        // the response is validated by requesting an access token.
        let csrf_token = CsrfToken::new(request_uuid.to_string());
        let (redirect_url, csrf_token) = &application_configuration
            .oauth2_client
            .authorize_url(move || csrf_token)
            // Set the desired scopes.
            .add_scope(Scope::new("email".to_string()))
            // Set the PKCE code challenge.
            .set_pkce_challenge(pkce_challenge)
            .url();
        let verification_data = Oauth2VerificationData::new(pkce_verifier, csrf_token.to_owned());
        debug!(
            "get_authentication_redirect_response() => {}",
            &redirect_url
        );
        let mut shared_oauth2_verfication_data_write_lock = application_configuration
            .shared_oauth2_verification_data
            .write()
            .unwrap();
        // use the same uuid as in the AuthenticationState, so we can find it later on
        let uuid = request_uuid.to_owned();
        shared_oauth2_verfication_data_write_lock.insert(uuid, verification_data);
        drop(shared_oauth2_verfication_data_write_lock);
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
