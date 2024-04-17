use crate::base64_trait::Base64VecU8Conversions;
use crate::configuration::ApplicationConfiguration;
use crate::header_value_trait::HeaderValueExctractor;
use actix_web::{
    dev::Payload,
    error::{ErrorForbidden, ErrorUnauthorized},
    http, web, Error, FromRequest, HttpRequest,
};
use chrono::DateTime;
use log::{debug, warn};
use serde::Deserialize;
use std::fmt;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use uuid::Uuid;

/// Payload of an access token, that can be used for scripting.
///
/// It resembles a JWT but it is reduced to our purpose.
///
/// ```json
/// {
///     "iss": "https://127.0.0.1:8844",
///     "sub": "5ca81a4c-9c04-4c94-a2e7-c8349288445b",
///     "aud": "https://127.0.0.1:8844/api/v1/secret",
///     "nbf": 1713275828,
///     "exp": 1861830000,
///     "jti": "dcQvbWnx2VDJpXDeX+Q6eekheaqveGtVoIN6pQJ9OwpKmrCO4RSe2QYwuOXTr4nqKxgw7ZDrHuqTm2k2IXDr8RKzDiaEaEslTZQ5HR2YMCfJxMNida2lf5NiKBo0lILdFG/beDHMhnofbAblKuwpSV52qlJRqK77qoBI0IzHpNk/Gq9MUUqjfZfqLjuchviD4sV9ZQA0ABIOE5hLPZ2JXgb19V6qIOWIPQadwneKa3sq1ed8xlwZtUGHg+A24fIO/O3rXd6KZ7pTqPY4m5bBMGO7EdicXZeLnBY+4aHbS46c4p8ADfBGXmwSLiusyIyqkEMbAel4vNJ0mnLDlhbkiVFhs7CLxT0wLJhpUYkUw/8Sig3CNMpPU+7mCu9AsqWUMhl8H8jnWGDILbrYosAH5iyjDhm1FxNRDG7MoOSBeDK5ddLUqqNuX+rTxiJanaks8YMrtGM5jCZXGNc89nQSRw3TRGVhR8h2IsAerP77lbrVjgNWtzlYCvhjDk1a5Wf/c8jqzXQkPO2QFIDaR0lPw9Xx1ybxdTrvPylW5gydZRBopAPbOc87KGvzdn61ESKxcha3NjbBZ8J+L4eNlz8/3dm9QgEek6u+6kiXg6njefDEhXWQOVQhHP3zjicaHmoL0f6fSfxxlpc0EVfwmycDhXTYwwWwz9mBWTqBgMGfC/I="
// }
/// ```
#[derive(Deserialize)]
pub struct AccessTokenPayload {
    pub iss: String,
    pub sub: Uuid,
    pub aud: String,
    pub nbf: i64,
    pub exp: i64,
    pub jti: String,
}

impl fmt::Display for AccessTokenPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(sub={}, nbf={}, exp={})",
            self.sub.to_string(),
            self.nbf,
            self.exp
        )
    }
}

/// Implementation of the FromRequest trait to
/// extract an AccessTokenPayload from a HttpRequest
/// Makes accessing token data in handler functions
/// easier.
impl FromRequest for AccessTokenPayload {
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<AccessTokenPayload, Error>>>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let req = req.clone();
        Box::pin(async move { get_access_token_payload(&req) })
    }
}

fn get_access_token_payload(req: &HttpRequest) -> Result<AccessTokenPayload, Error> {
    let app_data: Option<&web::Data<ApplicationConfiguration>> = req.app_data();
    if app_data.is_none() {
        warn!("get_access_token_payload(): app_data is empty(none)!");
        return Err(ErrorUnauthorized("No app_data, configuration missing!"));
    }
    for header_value in req.head().headers().get_all(http::header::AUTHORIZATION) {
        let b64_bearer_token = match header_value.get_bearer_token_value() {
            Some(encrypted_b64_bearer_token) => encrypted_b64_bearer_token,
            None => {
                warn!("Unkown bearer token value!");
                return Err(ErrorUnauthorized("No access token found!"));
            }
        };
        debug!("b64_bearer_token = {}", &b64_bearer_token);
        let bearer_token_json_utf8 = match Vec::from_base64_urlsafe_encoded(&b64_bearer_token) {
            Err(e) => {
                warn!("Cannot decode base64 bearer token: {}", &e);
                return Err(ErrorUnauthorized("Access token has invalid base64!"));
            }
            Ok(bearer_token_json_utf8) => bearer_token_json_utf8,
        };
        let bearer_token_json = match String::from_utf8(bearer_token_json_utf8) {
            Err(_) => {
                warn!("could not parse utf8 bearer token payload!");
                return Err(ErrorUnauthorized("Could not parse access token!"));
            }
            Ok(bearer_token_json) => bearer_token_json,
        };
        debug!("bearer_token_json = {}", &bearer_token_json);
        let bearer_token =
            match serde_json::from_str(&bearer_token_json) as Result<AccessTokenPayload, _> {
                Ok(bearer_token) => bearer_token,
                Err(e) => {
                    warn!("could not parse json bearer token payload: {}", &e);
                    return Err(ErrorUnauthorized("Could not parse access token!"));
                }
            };
        debug!("bearer_token = {}", &bearer_token);
        let application_configuration = app_data.unwrap().clone();
        let sub = bearer_token.sub.to_string();
        let path = Path::new(
            &application_configuration
                .configuration_file
                .access_token_configuration
                .api_access_files,
        )
        .join(sub.clone());
        if !path.exists() {
            warn!("Token file {} does not exist!", &path.display());
            return Err(ErrorUnauthorized("Unkown access token!"));
        }

        let rsa_read_lock = application_configuration.rsa_keys.read().unwrap();
        if let Ok(decrypted_jti) = rsa_read_lock.decrypt_str(&bearer_token.jti) {
            debug!("decrypted_jti = {}", &decrypted_jti);
            if decrypted_jti != sub {
                warn!(
                    "decrypted token value {} does not match sub value {}",
                    &decrypted_jti, &sub
                );
                return Err(ErrorForbidden("Invalid access token!"));
            }
        }
        let access_token_file = match AccessTokenFile::read_from_disk(path) {
            Err(e) => {
                warn!("Cannot read access token file: {}", &e);
                return Err(ErrorUnauthorized("Unkown access token!"));
            }
            Ok(access_token_file) => access_token_file,
        };

        if let Err(validation_error) = validate_access_token(&bearer_token, &access_token_file) {
            warn!("{}", &validation_error);
            return Err(ErrorForbidden("Invalid access token!"));
        }

        // TODO: check ip addresses
        return Ok(bearer_token);
    }
    warn!("No valid access token found!");
    Err(ErrorForbidden("No access token found!"))
}

fn validate_access_token(
    access_token: &AccessTokenPayload,
    access_token_file: &AccessTokenFile,
) -> Result<(), Box<dyn std::error::Error>> {
    if access_token.nbf != access_token_file.nbf {
        return Err("tampered access token, nbf does not match".into());
    }
    if access_token.exp != access_token_file.exp {
        return Err("tampered access token, exp does not match".into());
    }
    let now = chrono::offset::Local::now();
    debug!("now = {}", &now);
    let exp = DateTime::from_timestamp(access_token_file.exp, 0).expect("Invalid exp timestamp!");
    let nbf = DateTime::from_timestamp(access_token_file.nbf, 0).expect("Invalid nbf timestamp!");
    if exp < now {
        return Err("Access token expired!".into());
    }
    if nbf > now {
        return Err("Access token not yet valid!".into());
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize)]
pub struct AccessTokenConfiguration {
    pub api_access_files: String,
}

#[derive(Deserialize)]
pub struct AccessTokenFile {
    pub ip_adresses: Vec<String>,
    pub nbf: i64,
    pub exp: i64,
}

impl AccessTokenFile {
    fn read_from_disk<P: AsRef<Path>>(
        path: P,
    ) -> Result<AccessTokenFile, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(&path)?;
        let access_token_file: AccessTokenFile = serde_json::from_str(&content)?;
        Ok(access_token_file)
    }
}
