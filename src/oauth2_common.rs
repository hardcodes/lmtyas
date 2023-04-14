extern crate env_logger;
use crate::authentication_middleware::AuthenticationRedirect;
use crate::configuration::ApplicationConfiguration;
pub use crate::login_user_trait::Login;
use actix_web::{web, web::Bytes, HttpRequest, HttpResponse};
use async_trait::async_trait;
use regex::Regex;
use serde::Deserialize;
use std::error::Error;
use uuid::Uuid;
use crate::authentication_middleware::PeerIpAddress;
use crate::authentication_middleware::UNKNOWN_PEER_IP;

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

#[async_trait(?Send)]
impl Login for Oauth2Configuration {
    async fn login_user(
        bytes: Bytes,
        request: HttpRequest,
        application_configuration: web::Data<ApplicationConfiguration>,
    ) -> HttpResponse {
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
        request_path_with_query: &str,
        request_uuid: &Uuid,
        application_configuration: &ApplicationConfiguration,
    ) -> HttpResponse {
        HttpResponse::Forbidden().finish()
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
