use log::{debug, info, warn};
extern crate env_logger;
use crate::authentication_functions::get_decrypted_cookie_data_from_http_request;
#[cfg(feature = "ldap-auth")]
pub use crate::authentication_ldap::LdapCommonConfiguration;
#[cfg(feature = "oidc-auth-ldap")]
use crate::authentication_oidc::OidcConfiguration;
use crate::configuration::ApplicationConfiguration;
use crate::ip_address::IpAdressString;
use crate::{MAX_AUTHREQUEST_AGE_SECONDS, MAX_COOKIE_AGE_SECONDS};
#[cfg(any(feature = "ldap-auth", feature = "oidc-auth-ldap"))]
use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::{body::EitherBody, http::StatusCode, web, Error, HttpResponse};
use chrono::Duration;
use chrono::{DateTime, Utc};
use futures_util::future::LocalBoxFuture;
use std::collections::HashMap;
use std::fmt;
use std::future::{ready, Ready};
use std::sync::{Arc, RwLock};
use uuid::v1::{Context, Timestamp};
use uuid::Uuid;

#[cfg(feature = "ldap-auth")]
type AuthenticationRedirectType = LdapCommonConfiguration;
#[cfg(feature = "oidc-auth-ldap")]
type AuthenticationRedirectType = OidcConfiguration;

/// maximum number of authentication requests that are stored in the
/// hashmap to prevent a DOS attack.
const MAX_AUTH_REQUESTS: usize = 128;
/// Used to build unique uuids for resource requests
const NODE_ID: &[u8; 6] = &[0x0f, 0x12, 0x31, 0xbc, 0x57, 0x6a];

/// This trait must be implemented to redirect
/// not authenticated users to the right URI to
/// start the authentication process, e.g.
/// a login page or an external IdP.
pub trait AuthenticationRedirect {
    fn get_authentication_redirect_response(
        request_path_with_query: &str,
        request_uuid: &Uuid,
        application_configuration: &ApplicationConfiguration,
    ) -> HttpResponse;
}

/// Holds the information about a resource request
#[derive(Clone, Debug)]
pub struct AuthenticationState {
    /// will be set to true when a (possible) login request/response has arrived
    pub has_been_used: bool,
    /// url that was requested when entering the web service
    pub url_requested: String,
    /// when was the request made, used to prune old entries
    pub time_stamp: DateTime<Utc>,
    /// peer ip address that requested the resource
    pub peer_ip: String,
}

/// custom formatter to suppress secrets in the url
impl fmt::Display for AuthenticationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(has_been_used={}, time_stamp={}, peer_ip={})",
            self.has_been_used, self.time_stamp, self.peer_ip
        )
    }
}

impl AuthenticationState {
    /// Creates new empty Instance with current time stamp
    pub fn new(url: &str, peer_ip: &str) -> AuthenticationState {
        AuthenticationState {
            has_been_used: false,
            url_requested: String::from(url),
            time_stamp: Utc::now(),
            peer_ip: String::from(peer_ip),
        }
    }
}

/// Removes aged authentication requests
#[inline]
pub fn cleanup_authentication_state_hashmap(
    shared_request_data: &Arc<RwLock<SharedRequestData>>,
    max_age_in_seconds: i64,
) {
    let time_to_delete = Utc::now()
        - Duration::try_seconds(max_age_in_seconds)
            .unwrap_or_else(|| Duration::try_seconds(MAX_AUTHREQUEST_AGE_SECONDS).unwrap());
    let shared_request_data_read_lock = shared_request_data.read().unwrap();
    let mut items_to_remove: Vec<uuid::Uuid> = Vec::new();
    for (k, v) in &shared_request_data_read_lock.authentication_state_hashmap {
        // remove authentication requests that already have been used
        // or were not used in a timely manner
        if v.has_been_used || v.time_stamp < time_to_delete {
            info!("removing authentication request {}, {}", &k.to_string(), &v);
            items_to_remove.push(*k);
        }
    }
    drop(shared_request_data_read_lock);

    let mut shared_request_data_write_lock = shared_request_data.write().unwrap();
    for item in items_to_remove {
        shared_request_data_write_lock
            .authentication_state_hashmap
            .remove(&item);
    }
}

/// This hashmap uses the uuid that is generated upon a resource request
/// and forwarded to the login page, IdP etc. as key for the stored AuthenticationState.
pub type AuthenticationStateHashMap = HashMap<Uuid, AuthenticationState>;

pub struct SharedRequestData {
    /// holds the authentication requests
    pub authentication_state_hashmap: AuthenticationStateHashMap,
    /// used by the uuid crate to build unique uuids across threads
    pub uuid_context: Context,
}

impl Default for SharedRequestData {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedRequestData {
    pub fn new() -> SharedRequestData {
        SharedRequestData {
            authentication_state_hashmap: AuthenticationStateHashMap::new(),
            uuid_context: Context::new(1),
        }
    }

    /// Store a reuested url and return a uuid as reference for the IdP
    pub fn store_resource_request(&mut self, url: &str, peer_ip: &str) -> Option<uuid::Uuid> {
        debug!("store_resource_request()");

        // A real user/browser will come back again and start a new authentication
        // attempt. A possible attacker will simply knock on the server without
        // following the redirect and stopped after reaching MAX_AUTH_REQUESTS. So the
        // webservice won't consume all memory on the host.
        // A cleanup thread will remove old entries after `max_authrequest_age_seconds`,
        // so that the situation will resolve itself unless the server is still being
        // hammered on.
        if self.authentication_state_hashmap.len() >= MAX_AUTH_REQUESTS {
            warn!("MAX_AUTH_REQUESTS exceeded, possible DOS attack!");
            return None;
        }

        let authentication_state = AuthenticationState::new(url, peer_ip);
        let unix_timestamp_seconds = authentication_state.time_stamp.timestamp() as u64;
        let unix_timestamp_subsec_nanos = authentication_state.time_stamp.timestamp_subsec_nanos();
        let ts = Timestamp::from_unix(
            &self.uuid_context,
            unix_timestamp_seconds,
            unix_timestamp_subsec_nanos,
        );
        let request_uuid = Uuid::new_v1(ts, NODE_ID);
        debug!("built uuid {}", &request_uuid.to_string());
        self.authentication_state_hashmap
            .insert(request_uuid, authentication_state);

        debug!("returning uuid {}", &request_uuid.to_string());
        Some(request_uuid)
    }
}

// There are two steps in middleware processing.
// 1. Middleware initialization, middleware factory gets called with
//    next service in chain as parameter.
// 2. Middleware's call method gets called with normal request.
pub struct CheckAuthentication;

// .1 The middleware factory is the `Transform` trait from actix-service crate
// `S` - type of the next service
// `B` - type of response's body
impl<S, B> Transform<S, ServiceRequest> for CheckAuthentication
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = CheckAuthenticationMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(CheckAuthenticationMiddleware { service }))
    }
}

pub struct CheckAuthenticationMiddleware<S> {
    service: S,
}

// Service provides a symmetric and uniform API; the same abstractions can be used to represent both clients and servers.
// You can think about service as a function with one argument and result as a return type.
// In general form it looks like `async fn(Req) -> Result<Res, Err>. Service` trait just generalizing
// form of this function. Each parameter described as an assotiated type.
impl<S, B> Service<ServiceRequest> for CheckAuthenticationMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    /// 2. The middleware's call method gets called with a normal
    ///    request and is the main implementation of the middleware.
    fn call(&self, service_request: ServiceRequest) -> Self::Future {
        debug!(
            "CheckAuthenticationMiddleware, request {:?}",
            &service_request
        );

        let application_configuration = service_request
            .app_data::<web::Data<ApplicationConfiguration>>()
            .unwrap()
            .clone();
        let peer_ip = service_request.get_peer_ip_address();
        // At this point we must decide if a user is already authenticated.

        ////////////////////////////////////////////////////////////////////////////////////////////
        // Yes (cookie) ==> let the user access the requested resources
        ////////////////////////////////////////////////////////////////////////////////////////////
        if let Some(decrypted_cookie_data) = get_decrypted_cookie_data_from_http_request(
            service_request.request(),
            &application_configuration,
        ) {
            if let Some(authenticated_user) = application_configuration
                .shared_authenticated_users
                .read()
                .unwrap()
                .authenticated_users_hashmap
                .get(&decrypted_cookie_data.uuid)
            {
                let invalid_cookie_age = Utc::now()
                    - Duration::try_seconds(
                        application_configuration
                            .configuration_file
                            .max_cookie_age_seconds,
                    )
                    .unwrap_or_else(|| Duration::try_seconds(MAX_COOKIE_AGE_SECONDS).unwrap());
                // UUID inside cookie as referenced an `AuthenticatedUser`.
                if peer_ip.ne(&authenticated_user.peer_ip) {
                    warn!(
                        "Cookie stolen? peer_address = {:?}, authenticated_user = {}",
                        &peer_ip, &authenticated_user
                    );
                // check cookie age
                } else if authenticated_user.utc_date_time < invalid_cookie_age {
                    // A browser could hold a cookie that is older than 60 seconds and still valid, e.g. when
                    // an authenticated user is redirected to the index page. Since the `authenticated_user.time_stamp`
                    // is updated every 60 seconds on pages behind routes that require authentication, it should not be
                    // possible that we see cookies that are older than `max_cookie_age_seconds`.
                    // A behaving browser would have deleted that cookie at this point.
                    // Requests with outdated cookies smell fishy!
                    warn!(
                        "Cookie older than {} seconds! peer_address = {:?}, authenticated_user = {}",
                        &application_configuration
                    .configuration_file
                    .max_cookie_age_seconds, &peer_ip, &authenticated_user
                            );
                } else if !decrypted_cookie_data
                    .counter_is_valid(authenticated_user.cookie_update_lifetime_counter)
                {
                    // The cookie data may still be valid within the meaning of `max_cookie_age_seconds` but
                    // the counter value inside the cookie may not match: we are presented a cookie that has
                    // not been updated yet. However, there is a graceperiod to prevent race conditions,
                    // see `cookie_functions::MAX_COOKIE_COUNTER_DIFFERENCE`.
                    // If this check fails: Red flag!
                    warn!(
                        "Cookie lifetime counter does not match: (cookie = {}, expected = {}, peer_address = {:?}, authenticated_user = {})",
                        &decrypted_cookie_data.cookie_update_lifetime_counter,
                        &authenticated_user.cookie_update_lifetime_counter, &peer_ip, &authenticated_user
                    );
                } else {
                    info!("user is already authenticated: {}", &authenticated_user);

                    let service_request_future = self.service.call(service_request);

                    return Box::pin(async move {
                        service_request_future
                            .await
                            .map(ServiceResponse::map_into_left_body)
                    });
                }
            };
            // Some browers show up with expired cookies. Those will fall through
            // since there is no `AuthenticatedUser` stored for the decrypted UUID
            // left. So it will be handled as if no cookie was present.
        }

        ////////////////////////////////////////////////////////////////////////////////////////////
        // No  ==>       redirect to the URI provided by the AuthenticationRedirect trait
        //               implementation.
        //               We use request_uuid as RelayState.
        ////////////////////////////////////////////////////////////////////////////////////////////
        debug!("no cookie found, user is not authenticated!");
        let request_path_with_query = match &service_request.query_string().len() {
            0 => service_request.path().to_owned(),
            _ => format!(
                "{}?{}",
                &service_request.path(),
                &service_request.query_string()
            ),
        };
        debug!("storing request before redirecting...");
        if let Some(request_uuid) = &application_configuration
            .shared_request_data
            .write()
            .unwrap()
            .store_resource_request(&request_path_with_query, &peer_ip)
        {
            debug!(
                "uuid for the request {} is {}",
                &request_path_with_query, &request_uuid
            );
            // If no (valid) cookie is present, the browser is redirected to the configured
            // authentication instance. A possible invalid cookie will be deleted by giving
            // the browser the order to delete any cookie from this service with the redirect
            // response.
            let redirect_service_response =
                    <AuthenticationRedirectType as AuthenticationRedirect>::get_authentication_redirect_response(
                        &request_path_with_query,
                        request_uuid,
                        &application_configuration,
                    );
            // redirect browser to the given URI
            return Box::pin(async {
                Ok(service_request
                    .into_response(redirect_service_response)
                    .map_into_right_body())
            });
        }
        // no UUID was generated = too many requests
        debug!("no uuid, returning server busy");
        let busy_response = HttpResponse::build(StatusCode::TOO_MANY_REQUESTS).finish();
        Box::pin(async {
            Ok(service_request
                .into_response(busy_response)
                .map_into_right_body())
        })
    }

    forward_ready!(service);
}
