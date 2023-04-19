extern crate env_logger;
use crate::authentication_middleware::AuthenticationRedirect;
use crate::authentication_middleware::PeerIpAddress;
use crate::authentication_middleware::UNKNOWN_PEER_IP;
use crate::configuration::ApplicationConfiguration;
pub use crate::login_user_trait::Login;
use actix_web::{http, http::Method, http::StatusCode, web, web::Bytes, HttpRequest, HttpResponse};
use async_trait::async_trait;
use chrono::Duration;
use chrono::{DateTime, Utc};
use log::{debug, info};
use oauth2::{CsrfToken, PkceCodeChallenge, PkceCodeVerifier, Scope};
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::error::Error;
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
}

impl Oauth2VerificationData {
    pub fn new(pkce_verifier: PkceCodeVerifier, csrf_token: CsrfToken) -> Self {
        Self {
            pkce_verifier,
            csrf_token,
            time_stamp: Utc::now(),
        }
    }
}

pub type SharedOauth2VerificationDataHashMap = HashMap<Uuid, Oauth2VerificationData>;

/// Removes aged authentication requests
#[inline]
pub fn cleanup_oauth2_authentication_state_hashmap(
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
            if v.time_stamp < time_to_delete {
                info!("removing oauth2 authentication request {}", &k.to_string());
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
        _application_configuration: web::Data<ApplicationConfiguration>,
    ) -> HttpResponse {
        debug!("oauth2 response:\n\n{:?}", request);
        // accept GET method only
        if Method::GET != request.method() {
            return HttpResponse::Forbidden().finish();
        }
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
        let (redirect_url, csrf_token) = &application_configuration
            .oauth2_client
            .authorize_url(CsrfToken::new_random)
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
