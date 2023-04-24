use log::{debug, info, warn};
extern crate env_logger;
#[cfg(feature = "ldap-auth")]
pub use crate::authentication_ldap::LdapCommonConfiguration;
use crate::configuration::ApplicationConfiguration;
use crate::cookie_functions::{get_plain_cookie_string, COOKIE_NAME};
use crate::header_value_trait::HeaderValueExctractor;
#[cfg(feature = "oidc-auth-ldap")]
use crate::authentication_oidc::OidcConfiguration;
#[cfg(any(feature = "ldap-auth", feature = "oidc-auth-ldap"))]
use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::{body::EitherBody, http, http::StatusCode, web, Error, HttpRequest, HttpResponse};
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

/// Holds the information about a resoure request
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
    let time_to_delete = Utc::now() - Duration::seconds(max_age_in_seconds);
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
        if self.authentication_state_hashmap.len() >= MAX_AUTH_REQUESTS {
            // A real user/browser will come back again and start a new authentication
            // attempt. A possible attacker will simply knock on the server without
            // following the redirect and stopped after reaching MAX_AUTH_REQUESTS. So the
            // webservice won't consume all memory on the host.
            // A cleanup thread will remove old entries after 10 minutes, so that the
            // situation will resolve itself unless the server is still being hammered on.
            warn!("MAX_AUTH_REQUESTS exceeded, possible DOS attack!");
            return None;
        } else {
            self.authentication_state_hashmap
                .insert(request_uuid, authentication_state);
        }
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
    /// request and is the main implementation of the middleware.
    fn call(&self, request: ServiceRequest) -> Self::Future {
        debug!("CheckAuthenticationMiddleware, request {:?}", &request);

        let application_configuration = request
            .app_data::<web::Data<ApplicationConfiguration>>()
            .unwrap()
            .clone();
        let peer_ip = if let Some(s) = request.peer_addr() {
            s.ip().to_string()
        } else {
            UNKNOWN_PEER_IP.to_string()
        };
        // At this point we must decide if a user is already authenticated.
        // Yes (cookie) ==> let the user access the requested resources
        for header_value in request.head().headers().get_all(http::header::COOKIE) {
            debug!("header_value = {:?}", &header_value);
            debug!("looking for cookie {}", &COOKIE_NAME);
            if let Some(cookie) = header_value.get_value_for_cookie_with_name(COOKIE_NAME) {
                debug!("possible authorization cookie = {}", &cookie);
                let rsa_read_lock = application_configuration.rsa_keys.read().unwrap();
                // when the rsa key pair already has been loaded,
                // the cookie value is encrypted with the rsa public
                // key otherwise its simply base64 encoded.
                let plain_cookie = get_plain_cookie_string(&cookie, &rsa_read_lock);
                if let Ok(parsed_cookie_uuid) = Uuid::parse_str(&plain_cookie) {
                    if let Some(auth_request) = application_configuration
                        .shared_authenticated_users
                        .read()
                        .unwrap()
                        .authenticated_users_hashmap
                        .get(&parsed_cookie_uuid)
                    {
                        if peer_ip.ne(&auth_request.peer_ip) {
                            warn!(
                                "Cookie stolen? peer_address = {:?}, auth_request = {}",
                                &peer_ip, &auth_request
                            );
                        } else {
                            info!("user is already authenticated: {}", &auth_request);

                            let service_request_future = self.service.call(request);

                            return Box::pin(async move {
                                service_request_future
                                    .await
                                    .map(ServiceResponse::map_into_left_body)
                            });
                        }
                    };
                }
            }
        }

        // No  ==>       redirect to the URI provided by the AuthenticationRedirect trait
        //               implementation.
        // We use request_uuid as RelayState.
        debug!("no cookie found, user is not authenticated!");
        let request_path_with_query = match &request.query_string().len() {
            0 => request.path().to_owned(),
            _ => format!("{}?{}", &request.path(), &request.query_string()),
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
            let redirect_service_response =
                    <AuthenticationRedirectType as AuthenticationRedirect>::get_authentication_redirect_response(
                        &request_path_with_query,
                        request_uuid,
                        &application_configuration,
                    );
            // redirect browser to the given URI
            return Box::pin(async {
                Ok(request
                    .into_response(redirect_service_response)
                    .map_into_right_body())
            });
        }
        // no UUID was generated = too many requests
        debug!("no uuid, returning server busy");
        let busy_response = HttpResponse::build(StatusCode::TOO_MANY_REQUESTS).finish();
        Box::pin(async { Ok(request.into_response(busy_response).map_into_right_body()) })
    }

    forward_ready!(service);
}

/// This trait must be implemented to get the ip address
/// of the client peer. The implementation may vary if
/// the service is running behind a proxy.
pub(crate) trait PeerIpAddress {
    /// get the ip address of the peer requesting resources
    fn get_peer_ip_address(request: &HttpRequest) -> String;
}

pub const UNKNOWN_PEER_IP: &str = "unknown peer";
