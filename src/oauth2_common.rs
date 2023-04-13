extern crate env_logger;
pub use crate::login_user_trait::Login;
use serde::Deserialize;
use regex::Regex;
use async_trait::async_trait;
use actix_web::{http, http::StatusCode, web, web::Bytes, HttpRequest, HttpResponse};
use crate::configuration::ApplicationConfiguration;
use std::error::Error;

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
        HttpResponse::Forbidden()
    }

    fn build_valid_user_regex(&mut self) -> Result<(), Box<dyn Error>> {
        let user_regex = Regex::new(&self.valid_user_regex)?;
        self.user_regex = Some(user_regex);
        Ok(())
    }
}