extern crate env_logger;
use crate::authentication_middleware::AuthenticationRedirect;
use crate::authentication_url::AUTH_LOGIN_FAIL_PAGE;
use crate::configuration::ApplicationConfiguration;
use crate::cookie_functions::{
    build_new_encrypted_authentication_cookie, build_redirect_to_resource_url_response,
    empty_unix_epoch_cookie,
};
use crate::error::LmtyasError;
use crate::http_traits::CustomHttpResponse;
use crate::ip_address::IpAdressString;
pub use crate::login_user_trait::Login;
#[cfg(feature = "oidc-ldap")]
use crate::oidc_ldap::OidcUserLdapUserDetails;
use crate::MAX_AUTHREQUEST_AGE_SECONDS;
use actix_web::{
    http, http::Method, http::StatusCode, web, web::Bytes, web::Query, HttpRequest, HttpResponse,
};
use async_trait::async_trait;
use chrono::Duration;
use chrono::{DateTime, Utc};
use log::{debug, info, warn};
use openidconnect::reqwest;
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenResponse, ProviderMetadata, 
    EmptyAdditionalProviderMetadata
};
use openidconnect::core::{
    CoreAuthDisplay, CoreClaimName, CoreClaimType, CoreClient, CoreClientAuthMethod, CoreGrantType,
    CoreIdTokenClaims, CoreIdTokenVerifier, CoreJsonWebKey, CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm, CoreResponseMode, CoreResponseType, CoreRevocableToken,
    CoreSubjectIdentifierType, CoreProviderMetadata, CoreAuthenticationFlow
};
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::sync::{Arc, RwLock};
use uuid::Uuid;


type IdentityProviderMetadata = ProviderMetadata<
    EmptyAdditionalProviderMetadata,
    CoreAuthDisplay,
    CoreClientAuthMethod,
    CoreClaimName,
    CoreClaimType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

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

impl OidcConfiguration {
    pub async fn discover_metadata_and_build_oidc_client(
        &self,
        fqdn: &str,
        auth_route: &str,
    ) -> Result<openidconnect::core::CoreClient, LmtyasError> {
        info!(
                "getting provider metadata from {}",
                self.provider_metadata_url
        );
        let issuer_url = match IssuerUrl::new(self.provider_metadata_url.clone()) {
                Err(e) => {
                    return Err(format!("cannot build issuer_url: {}", e).into());
                }
                Ok(i) => i,
        };
        let http_client = match reqwest::ClientBuilder::new()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::redirect::Policy::none())
        .build() {
            Err(e) => {
                return Err(format!("cannot build http client to discover provider metadata: {}", e).into());
            }
            Ok(h) => h,
        };
        let provider_metadata = 
            // For version 3.x.x this call did not time out, we will se how it behaves with 4.x.x.
            match IdentityProviderMetadata::discover_async(issuer_url, &http_client).await {
                Err(e) => {
                    return Err(format!("cannot load oidc provider metadata: {}", e).into());
                }
                Ok(p) => p,
            
        };
        let redirect_url =
            match RedirectUrl::new(format!("https://{}/authentication{}", fqdn, auth_route)) {
                Err(e) => {
                    return Err(format!("invalid redirect URL {}", e).into());
                }
                Ok(r) => r,
            };

        Ok(CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(self.client_id.clone()),
            Some(ClientSecret::new(self.client_secret.clone())),
        )
        // Set the URL the user will be redirected to after the authorization process.
        .set_redirect_uri(redirect_url))
    }
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
            "(has_been_used={}, time_stamp={})",
            self.has_been_used, self.time_stamp,
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
    let time_to_delete = Utc::now()
        - Duration::try_seconds(max_age_in_seconds)
            .unwrap_or_else(|| Duration::try_seconds(MAX_AUTHREQUEST_AGE_SECONDS).unwrap());
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

/// Holds information about a fresh authenticated user
/// The same as `crate::ldap_common::LdapSearchResult` but
/// may be implemented without ldap.
#[derive(Deserialize, Debug)]
pub struct OidcUser {
    #[serde(rename = "uid")]
    pub user_name: String,
    #[serde(rename = "givenName")]
    pub first_name: String,
    #[serde(rename = "sn")]
    pub last_name: String,
    pub mail: String,
}

/// This trait must be implemented to get
/// user details after oidc login (= we got a valid id token)
/// The default implementation in `oidc_ldap.rs` uses an
/// external ldap server to do that. Using the ID/access token
/// to do so would also be possible in another implementation.
#[async_trait(?Send)]
pub trait OidcUserDetails {
    /// use the given email address to query user details
    async fn get_oidc_user_details_from_email(
        mail: &str,
        application_configuration: &ApplicationConfiguration,
    ) -> Result<OidcUser, Box<dyn Error>>;
}

#[cfg(feature = "oidc-ldap")]
type QueryAuthDetails = OidcUserLdapUserDetails;

fn warn_with_error_stack<T: std::error::Error>(fail: &T, message: &'static str) {
    let mut error_mesage = message.to_string();
    let mut current_fail: Option<&dyn std::error::Error> = Some(fail);
    while let Some(cause) = current_fail {
        error_mesage += &format!(", caused by: {}", cause);
        current_fail = cause.source();
    }
    warn!("{}", error_mesage);
}

#[async_trait(?Send)]
impl Login for OidcConfiguration {
    /// This function is called when a user logs in.
    /// In case of this OIDC implementation this means
    /// the callback (redirect) from the OIDC idp server.
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
        let peer_ip = &request.get_peer_ip_address();
        // redirect to login failure page used on errors
        let login_fail_redirect = HttpResponse::build(StatusCode::SEE_OTHER)
            .append_header((http::header::LOCATION, AUTH_LOGIN_FAIL_PAGE))
            .finish();

        let valid_user_regex = match &application_configuration
            .configuration_file
            .oidc_configuration
            .user_regex
        {
            Some(r) => r,
            None => {
                warn!("valid user regex is not defined");
                return login_fail_redirect;
            }
        };

        // extract "code" and "state" from the forwarded response
        let query = match Query::<HashMap<String, String>>::from_query(request.query_string()) {
            Ok(q) => q,
            Err(e) => {
                warn!(
                    "cannot create hashmap from oidc response parameters: {}",
                    &e
                );
                return login_fail_redirect;
            }
        };
        let response_code = match query.get("code") {
            Some(c) => c,
            None => {
                warn!("no 'code' in oidc response");
                return login_fail_redirect;
            }
        };
        let response_state = match query.get("state") {
            Some(s) => s,
            None => {
                warn!("no 'state' in oidc response");
                return login_fail_redirect;
            }
        };

        let code = AuthorizationCode::new(response_code.to_string());
        let state = CsrfToken::new(response_state.to_string());

        debug!("code = {:?}", &code);
        debug!("state = {:?}", &state);

        // what request_id was assigned to the resource request?
        let request_id = match Uuid::parse_str(state.secret()) {
            Ok(request_id) => request_id,
            Err(_) => {
                warn!("response state cannot be parsed as uuid");
                return login_fail_redirect;
            }
        };
        info!(
            "OIDC: login attempt (peer_ip = {}, request_id = {})",
            &peer_ip,
            &request_id.to_string()
        );
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
                        "OIDC: login attempt with expired or invalid authentication request id {}",
                        &request_id
                    );
                    return login_fail_redirect;
                }
                Some(a) => a,
            };
            if auth_request.has_been_used {
                warn!(
                    "OIDC: authentication request id {} has already been used, possible replay attack!",
                    &request_id
                );
                return login_fail_redirect;
            } else {
                // mark resource request as used so that this ID cannot be used anymore
                auth_request.has_been_used = true;
                url_requested = auth_request.url_requested.clone();
            };
            // is authentication taking place from the same ip address as the resource request?
            if peer_ip.ne(&auth_request.peer_ip) {
                // NO! This maybe fishy. This also happens if devices have multiple IP addresses, e.g. a laptop with
                // both active wifi and wired ethernet adapters.
                warn!(
                "OIDC: IP address changed since resource request: peer_address = {:?}, auth_request = {}",
                &peer_ip, &auth_request
            );
                return login_fail_redirect;
            }
        }
        debug!("url_requested = {}", &url_requested);

        // At this point we made sure that the response refers to a resource
        // request that we've already seen.
        // Next: verify that the response is valid = get the access/ID token
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
                    "OIDC: login attempt with expired or invalid oidc verification data id {}",
                    &request_id
                );
                        return login_fail_redirect;
                    }
                    Some(a) => a,
                };
            if oidc_verification_data.has_been_used {
                warn!(
                    "OIDC: verification data id {} has already been used, possible replay attack!",
                    &request_id
                );
                return login_fail_redirect;
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
        info!("PKCE: getting ID token for request_id {}", &request_id);
        let http_client = match reqwest::ClientBuilder::new()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::redirect::Policy::none())
        .build() {
            Err(e) => {
                warn!("cannot build http client to get ID token: {}", e);
                return login_fail_redirect;
            }
            Ok(h) => h,
        };
        let token_response = match application_configuration
            .oidc_client
            .exchange_code(code)
            .set_pkce_verifier(pkce_verifier)
            .request_async(http_client)
            .await
        {
            Ok(t) => t,
            Err(e) => {
                warn_with_error_stack(&e, "PKCE: ID token request failed");
                // If the crate openidconnect is not compiled with the feature
                // "accept-rfc3339-timestamps", we will get the error
                // "data did not match any variant of untagged enum Timestamp"
                // at this point using auth0 as oidc provider!
                // See https://github.com/ramosbugs/openidconnect-rs/issues/23.
                return login_fail_redirect;
            }
        };

        debug!("token_response = {:?}", &token_response);
        // Extract the ID token.
        let id_token = match token_response.id_token() {
            Some(t) => t,
            None => {
                warn!("PKCE: ID token cannot be extracted");
                return login_fail_redirect;
            }
        };
        info!("PKCE: Received ID token for request_id {}", &request_id);
        debug!("id_token = {:?}", &id_token);

        // Verify ID token authenticity/nonce and extract claims.
        let id_token_verifier = &application_configuration
            .oidc_client
            .id_token_verifier()
            .to_owned();
        let claims = match id_token.claims(id_token_verifier, &nonce) {
            Ok(c) => c,
            Err(e) => {
                warn_with_error_stack(&e, "OIDC: failed to verify ID token authenticity");
                return login_fail_redirect;
            }
        };
        info!(
            "OIDC: verified ID token authenticity for request_id {}",
            &request_id
        );
        debug!("claims = {:?}", &claims);
        let email = claims
            .email()
            .map(|email| email.as_str())
            .unwrap_or("<not provided>");
        debug!("email (claim) = {}", &email);

        /////////////////////////////////////////////////////////////////////////////////////
        // WARNING
        /////////////////////////////////////////////////////////////////////////////////////
        // Very dirty hack to fake an email address when using magnolia/mock-oidc-user-server
        // as development oidc server.
        #[cfg(debug_assertions)]
        let email = if email == "<not provided>" {
            let faked_email = match String::from_utf8(claims.subject().as_bytes().to_vec()) {
                Ok(faked_email) => Box::leak(faked_email.into_boxed_str()),
                _ => "<debug_faked_email>",
            };
            warn!("faked_email = {}", &faked_email);
            faked_email
        } else {
            email
        };
        /////////////////////////////////////////////////////////////////////////////////////

        if !valid_user_regex.is_match(email) {
            warn!(
                "OIDC: claim email address {} does not match regex: {}",
                &email,
                &application_configuration
                    .configuration_file
                    .oidc_configuration
                    .valid_user_regex
            );
            return login_fail_redirect;
        }

        info!(
            "OIDC: authentication completed (peer_ip = {}, request_id = {}, email = {})",
            &peer_ip,
            &request_id.to_string(),
            &email
        );

        // At this point we known the identitiy of the user. Let's get some more
        // infos...
        // To do that, we use an implementation of the `OidcUserDetails` trait.
        // A future implementation could use further claims to query user details.
        // This would mean further round trips to the IdP.
        let user_details = match QueryAuthDetails::get_oidc_user_details_from_email(
            email,
            &application_configuration,
        )
        .await
        {
            Ok(d) => d,
            Err(e) => {
                warn!("cannot get user details for email {}: {}", &email, &e);
                return login_fail_redirect;
            }
        };

        if let Some(cookie_data) = application_configuration
            .shared_authenticated_users
            .write()
            .unwrap()
            .new_cookie_data_for(
                &user_details.user_name,
                &user_details.first_name,
                &user_details.last_name,
                email,
                peer_ip,
            )
        {
            info!(
                "OIDC: login completed (peer_ip = {}, request_id = {}, email = {})",
                &peer_ip,
                &request_id.to_string(),
                &email
            );

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
            return build_redirect_to_resource_url_response(&cookie, url_requested);
        } else {
            warn!("cannot create cookie id for email {}", &email);
            return HttpResponse::err_text_response("ERROR: login failed");
        }
    }

    /// This function is called once the confguration file has been read
    /// so that the `Regex` must only be built once.
    fn build_valid_user_regex(&mut self) -> Result<(), LmtyasError> {
        let user_regex = Regex::new(&self.valid_user_regex)?;
        self.user_regex = Some(user_regex);
        Ok(())
    }
}

impl AuthenticationRedirect for OidcConfiguration {
    /// This function will be called when an unauthenticated user
    /// requests a route that needs authentication.
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
            // Set the PKCE code challenge.
            .set_pkce_challenge(pkce_challenge)
            .url();
        let verification_data =
            OidcVerificationData::new(pkce_verifier, csrf_token.to_owned(), nonce.to_owned());
        debug!(
            "get_authentication_redirect_response() => {}",
            &redirect_url
        );
        // use the same uuid as in the AuthenticationState, so we can find it later on
        let uuid = request_uuid.to_owned();
        let mut shared_oidc_verfication_data_write_lock = application_configuration
            .shared_oidc_verification_data
            .write()
            .unwrap();
        shared_oidc_verfication_data_write_lock.insert(uuid, verification_data);
        drop(shared_oidc_verfication_data_write_lock);
        HttpResponse::build(StatusCode::FOUND)
            .append_header((http::header::LOCATION, redirect_url.as_str()))
            .append_header((
                http::header::SET_COOKIE,
                empty_unix_epoch_cookie().to_string(),
            ))
            .finish()
    }
}
