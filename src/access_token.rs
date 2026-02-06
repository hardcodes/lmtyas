use crate::configuration::ApplicationConfiguration;
use crate::header_value_trait::HeaderValueExctractor;
use crate::ip_address::IpAdressString;
use crate::MAX_BEARER_TOKEN_LEN;
use actix_web::{
    dev::Payload,
    error::{ErrorForbidden, ErrorServiceUnavailable, ErrorUnauthorized},
    http, web, Error, FromRequest, HttpRequest,
};
use chrono::DateTime;
use hacaoi::base64_trait::Base64VecU8Conversions;
use hacaoi::rsa::RsaKeysFunctions;
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use uuid::Uuid;
use zeroize::Zeroize;

/// Payload of an access token, that can be used for scripting.
///
/// It resembles a JWT but it is reduced to our purpose.
/// See resources/tests/access_token_payload/test-token-payload.json
///
/// ```json
/// {
///     "iss": "https://127.0.0.1:8844",
///     "sub": "5ca81a4c-9c04-4c94-a2e7-c8349288445b",
///     "aud": "https://127.0.0.1:8844/api/v1/secret",
///     "nbf": 1713275828,
///     "exp": 1861830000,
///     "jti": "wtHWCqUULzycA1q5YgW/W6l3qqFgWhcDhX5EQ+2GfTm9NQdTt8YfBTZjxtstM4/gG0YTfmlKajvkhz95Vo4pHbXPSgWAI0uu3rWIfZf47ApBMt76JvSI75KPC73StTBeRNaXCrXd3yCUsMgqQou/gEnendZgc4c6FU8aQqQQJVkjDZ0Rfswjz0kAPDcn1uiiLo0m6FGglIKQhPFwm6W8bAzbXzKZyXXTUx+l+ew4r/v+fZM4rM3LS4hm4DbY9Q4SD5SHalXAARrxvAcsMINycAQDMt6BZkdUd9gk3tbHiAaS7Bfpp11mIdEiyOhUkRSWA/201mD+qOEVe0g8QPbuYhnlf2t4ZiBlA4JM7M6Wtgjtss5c7fGp7M0jY0xhkMeqxfnKbPlbLDH3nvRTzzs2w/pXBSgceEqheKhEQsVvhj4hVsk9fk0O/DNa4veA5zZSNEm5GoMK6me3wLxABKoHpEZ9Bbp7m7jH4TkX6mpIYi1t/bL0HKsq2Fn0aPj88VkbURkJoer/r24T9YyTEJGamMt+f8nLI68iQ+u9DSRKKvM5zG5JtapYhK/mnB6d7w0h0w7eLqZZLo1X8cUcDxR80OL64Kxg0CndhwbcRabj5/YSZNBKodsc2DDwLujF9PQ9IBVF98K0fYHwMb6VAJY9PDoLPt0LAFiFd2aSA5i6Ja4="
// }
/// ```
#[derive(Deserialize, Clone, Serialize)]
pub struct AccessTokenPayload {
    /// Information for the access token user
    pub iss: String,
    /// The name of our access token file
    pub sub: Uuid,
    /// Information for the access token user
    pub aud: String,
    /// Not valid before (Unix timestamp)
    pub nbf: i64,
    /// Expires at (Unix timestamp)
    pub exp: i64,
    // Base64 encoded and rsa encrypted UUID that must match the `sub` value.
    pub jti: String,
}

impl fmt::Display for AccessTokenPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(sub={}, nbf={}, exp={})", self.sub, self.nbf, self.exp)
    }
}

impl Drop for AccessTokenPayload {
    fn drop(&mut self) {
        self.iss.zeroize();
        self.aud.zeroize();
        self.nbf.zeroize();
        self.exp.zeroize();
        self.jti.zeroize();
        let mut sub_bytes = self.sub.into_bytes();
        sub_bytes.zeroize();
    }
}

/// Implementation of the FromRequest trait to
/// extract an `AccessTokenPayload` from a `HttpRequest`
/// and validate it. The info plus request `ip_address`,
/// `from_email` and `from_display_name` from the associated
/// `AccessTokenFile` is then returned as `ValidatedAccessTokenPayload`.
/// Makes accessing token data in handler functions
/// easier and protects the route.
impl FromRequest for ValidatedAccessTokenPayload {
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<ValidatedAccessTokenPayload, Error>>>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let req = req.clone();
        Box::pin(async move { get_access_token_payload(&req).await })
    }
}

/// Extracts the access token from the request and validates it.
async fn get_access_token_payload(req: &HttpRequest) -> Result<ValidatedAccessTokenPayload, Error> {
    let app_data: Option<&web::Data<ApplicationConfiguration>> = req.app_data();
    if app_data.is_none() {
        // Should not happen!
        warn!("get_access_token_payload(): app_data is empty (none)!");
        return Err(ErrorServiceUnavailable(
            "No app_data, configuration missing!",
        ));
    }
    // we checked already, so unwrap() is ok.
    let application_configuration = app_data.unwrap();
    // Don't accept access tokens when the RSA private key is unavailable.
    if application_configuration
        .hybrid_crypto_for_secrets
        .lock()
        .await
        .is_none()
    {
        info!("RSA private key has not been loaded, cannot accept access token.");
        return Err(ErrorServiceUnavailable("System not ready for encryption!"));
    }

    // If for whatever reason more than one "Authorization: Bearer <token>" header is presented,
    // we will look only at the first one.
    if let Some(header_value) = req
        .head()
        .headers()
        .get_all(http::header::AUTHORIZATION)
        .next()
    {
        let b64_bearer_token = match header_value.get_bearer_token_value() {
            Some(b64_bearer_token) => b64_bearer_token,
            None => {
                warn!("No bearer token value found in request!");
                return Err(ErrorUnauthorized("No access token found!"));
            }
        };
        debug!("b64_bearer_token = {}", &b64_bearer_token);
        if b64_bearer_token.len() > MAX_BEARER_TOKEN_LEN {
            warn!(
                "bearer token length {} > max {}",
                &b64_bearer_token.len(),
                MAX_BEARER_TOKEN_LEN
            );
            return Err(ErrorUnauthorized("Access token too big!"));
        }
        let bearer_token_json_utf8 = match Vec::from_base64_urlsafe_encoded(&b64_bearer_token) {
            Err(e) => {
                warn!("Cannot decode bearer token from base64: {}", &e);
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
        let sub = bearer_token.sub.to_string();

        let hybrid_crypto_lock = application_configuration
            .hybrid_crypto_for_secrets
            .lock()
            .await;
        if let Some(rsa_keys) = hybrid_crypto_lock.as_deref() {
            if let Err(e) = rsa_keys.validate_sha512_b64_signature(&sub, &bearer_token.jti) {
                warn!(
                    "could not verify signature (jti value) from access token: {}",
                    e
                );
                return Err(ErrorForbidden("Invalid access token!"));
            }
        }
        drop(hybrid_crypto_lock);
        // Only try to read the access token file after the `jti` value AKA signature has been
        // successfully verified. So that changing the UUID (a.k.a. `sub` value) in the presented
        // access token cannot be used to sniff out possible files.
        let path = Path::new(
            &application_configuration
                .configuration_file
                .access_token_configuration
                .api_access_files,
        )
        .join(sub.clone());

        // Read the file with the `sub` UUID as file name to validate the access token.
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

        let ip_address = req.get_peer_ip_address();
        if !access_token_file.ip_adresses.contains(&ip_address) {
            warn!(
                "host ip address {} is invalid for access token {}",
                &ip_address, &bearer_token
            );
            return Err(ErrorForbidden("Invalid access token!"));
        }
        info!(
            "host at ip address {} presented valid access token {}",
            &ip_address, &bearer_token
        );
        return Ok(ValidatedAccessTokenPayload {
            iss: bearer_token.iss.clone(),
            sub: bearer_token.sub.to_string(),
            aud: bearer_token.aud.clone(),
            nbf: bearer_token.nbf,
            exp: bearer_token.exp,
            from_email: access_token_file.from_email.clone(),
            from_display_name: access_token_file.from_display_name.clone(),
            mail_template_file: access_token_file.mail_template_file.clone(),
            ip_address,
        });
    }
    warn!("No valid access token found!");
    Err(ErrorForbidden("No access token found!"))
}

/// Checks if the values in the presented access token match
/// those stored in the file on disk.
#[inline(always)]
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
    let exp = match DateTime::from_timestamp(access_token_file.exp, 0) {
        None => {
            return Err("Invalid exp timestamp!".into());
        }
        Some(exp) => exp,
    };
    let nbf = match DateTime::from_timestamp(access_token_file.nbf, 0) {
        None => {
            return Err("Invalid nbf timestamp!".into());
        }
        Some(exp) => exp,
    };
    if exp < now {
        return Err("Access token expired!".into());
    }
    if nbf > now {
        return Err("Access token not yet valid!".into());
    }
    // Validate the `iss`and `aud` values only if present in the `AccessTokenFile`.
    match &access_token_file.iss {
        None => {
            info!("skipping iss validition");
        }
        Some(iss) => {
            if *iss != access_token.iss {
                return Err("tampered access token, iss does not match".into());
            }
        }
    }
    match &access_token_file.aud {
        None => {
            info!("skipping aud validition");
        }
        Some(aud) => {
            if *aud != access_token.aud {
                return Err("tampered access token, aud does not match".into());
            }
        }
    }
    Ok(())
}

/// Part of the configuration file for the lmtyas web service.
#[derive(Clone, Debug, Deserialize)]
pub struct AccessTokenConfiguration {
    /// Name of the directory where the access token files are stored.
    pub api_access_files: String,
}

/// Counterpart for access tokens stored on disk. Should be more than
/// fast enough to read these files each time.
#[derive(Deserialize)]
pub struct AccessTokenFile {
    /// List of valid ip addresses that may present this access token
    pub ip_adresses: Vec<String>,
    /// Not valid before (Unix timestamp)
    pub nbf: i64,
    /// Expires at (Unix timestamp)
    pub exp: i64,
    /// Email address that will be inserted when sending
    /// the email to the secret receiver
    pub from_email: String,
    /// Display name that gets used in the email sent
    /// to the secret receiver
    pub from_display_name: String,
    /// Optional mail template filename
    pub mail_template_file: Option<String>,
    /// Optional information for the access token user
    pub iss: Option<String>,
    /// Optional information for the access token user
    pub aud: Option<String>,
}

impl Drop for AccessTokenFile {
    fn drop(&mut self) {
        self.ip_adresses.zeroize();
        self.nbf.zeroize();
        self.from_email.zeroize();
        self.from_display_name.zeroize();
        self.exp.zeroize();
        self.mail_template_file.zeroize();
        self.iss.zeroize();
        self.aud.zeroize();
    }
}

impl AccessTokenFile {
    /// Reads the access token file at the given path
    /// and tries to parse its json into `AccessTokenFile`.
    pub fn read_from_disk<P: AsRef<Path>>(
        path: P,
    ) -> Result<AccessTokenFile, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(&path)?;
        let access_token_file: AccessTokenFile = serde_json::from_str(&content)?;
        Ok(access_token_file)
    }
}

/// Will be constructed after the access token has been verified.
/// The data will be used in the handler function of the api request.
/// This way the access token file must only be read once.
pub struct ValidatedAccessTokenPayload {
    /// Information the the user
    pub iss: String,
    /// The name of our access token file
    pub sub: String,
    /// Information the the user
    pub aud: String,
    /// Not valid before (Unix timestamp)
    pub nbf: i64,
    /// Expires at (Unix timestamp)
    pub exp: i64,
    /// Email address that will be inserted when sending
    /// the email to the secret receiver
    pub from_email: String,
    /// Display name that gets used in the email sent
    /// to the secret receiver
    pub from_display_name: String,
    /// Optional mail template filename
    pub mail_template_file: Option<String>,
    /// Ip_adress of the scripting host
    pub ip_address: String,
}

impl fmt::Display for ValidatedAccessTokenPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(sub={}, nbf={}, exp={}, from_email={}, from_display_name={})",
            self.sub, self.nbf, self.exp, self.from_email, self.from_display_name,
        )
    }
}

impl ValidatedAccessTokenPayload {
    /// loads the optional mail template file
    pub fn load_mail_template(
        mail_template_filename: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let mail_body_template = fs::read_to_string(mail_template_filename)?;
        Ok(mail_body_template)
    }
}
