use chrono::{DateTime, Utc};
use log::{debug, info, warn};
use std::collections::HashMap;
use uuid::v1::{Context, Timestamp};
use uuid::Uuid;
extern crate env_logger;
use crate::authentication_functions::get_authenticated_user_from_request;
use crate::cookie_functions::CookieData;
use crate::MAX_COOKIE_AGE_SECONDS;
use actix_web::{dev::Payload, error::ErrorUnauthorized, Error, FromRequest, HttpRequest};
use chrono::Duration;
use rand::distr::Alphanumeric;
use rand::{rng, Rng};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use zeroize::Zeroize;

/// Maximum number of authenticated users that are stored in the
/// hashmap to prevent server overload or contain a DOS attack.
pub const MAX_AUTH_USERS: usize = 512;
/// Used to build unique uuids for resource requests.
const NODE_ID: &[u8; 6] = &[0x27, 0x9b, 0xbe, 0x13, 0x86, 0x80];
// Number of characters in the random generated CSRF token.
const CSRF_TOKEN_LENGTH: usize = 256;

/// Defines the type of user
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccessScope {
    User,
    ScriptUser,
    Administrator,
}

/// Holds the information of an authenticated user.
/// (name, email and timestamp of authentication/cookie update).
#[derive(Clone)]
pub struct AuthenticatedUser {
    pub user_name: String,
    pub first_name: String,
    pub last_name: String,
    pub mail: String,
    pub utc_date_time: DateTime<Utc>,
    pub access_scope: AccessScope,
    pub peer_ip: String,
    pub cookie_update_lifetime_counter: u16,
    pub csrf_token: String,
}

impl Drop for AuthenticatedUser {
    fn drop(&mut self) {
        self.user_name.zeroize();
        self.first_name.zeroize();
        self.last_name.zeroize();
        self.mail.zeroize();
        self.peer_ip.zeroize();
        self.csrf_token.zeroize();
    }
}

/// custom formatter to suppress first name, last name and mail address
impl fmt::Display for AuthenticatedUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(debug_assertions)]
        {
            write!(
                f,
                "(user_name={}, time_stamp={}, access_scope={:?}, peer_ip={}, cookie_update_counter={}, csrf_token={})",
                self.user_name, self.utc_date_time, self.access_scope, self.peer_ip, self.cookie_update_lifetime_counter, self.csrf_token
            )
        }
        #[cfg(not(debug_assertions))]
        {
            write!(
                f,
                "(user_name={}, time_stamp={}, access_scope={:?}, peer_ip={})",
                self.user_name, self.utc_date_time, self.access_scope, self.peer_ip
            )
        }
    }
}

impl AuthenticatedUser {
    /// Creates a new instance with the given user data and current time stamp.
    pub fn new<S>(
        user_name: S,
        first_name: S,
        last_name: S,
        mail: S,
        access_scope: AccessScope,
        peer_ip: S,
    ) -> Self
    where
        S: Into<String>,
    {
        Self {
            user_name: user_name.into(),
            first_name: first_name.into(),
            last_name: last_name.into(),
            mail: mail.into(),
            access_scope,
            peer_ip: peer_ip.into(),
            utc_date_time: Utc::now(),
            cookie_update_lifetime_counter: 0,
            csrf_token: rng()
                .sample_iter(&Alphanumeric)
                .take(CSRF_TOKEN_LENGTH)
                .map(char::from)
                .collect(),
        }
    }

    /// Get display name of authenticated user
    /// (first name [SPACE] last name)
    pub fn display_name(&self) -> String {
        format!("{} {}", &self.first_name, &self.last_name)
            .trim()
            .to_string()
    }

    /// Update the timestamp before a cookie lifetime is expired
    /// to stay in the hashmap
    pub fn update_timestamp(&mut self) {
        self.utc_date_time = Utc::now();
        // This counter is used to compare a received cookie with data in the hashmap, this
        // way a cookies changes its content with every update.
        self.cookie_update_lifetime_counter = self.cookie_update_lifetime_counter.wrapping_add(1);
        debug!("update_timestamp(), self = {}", &self);
    }
}

/// Administrators are still users just with a different scope
pub struct AuthenticatedAdministrator(AuthenticatedUser);

impl AuthenticatedAdministrator {
    /// Get the CSRF token.
    pub fn csrf_token(&self) -> String {
        self.0.csrf_token.clone()
    }
}

/// custom formatter to suppress first name, last name and mail address
impl fmt::Display for AuthenticatedAdministrator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Implementation of the FromRequest trait to
/// extract an AuthenticatedUser from a HttpRequest
/// Makes accessing user data in handler functions
/// easier.
impl FromRequest for AuthenticatedUser {
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<AuthenticatedUser, Error>>>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let req = req.clone();
        Box::pin(async move { get_authenticated_user_from_request(&req) })
    }
}

/// Implementation of the FromRequest trait to
/// extract an AuthenticatedAdministrator from a HttpRequest
/// Makes accessing user data in handler functions
/// easier. And allows secure admin routes.
impl FromRequest for AuthenticatedAdministrator {
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<AuthenticatedAdministrator, Error>>>>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        let fut = AuthenticatedUser::from_request(req, payload);
        Box::pin(async move {
            match fut.await {
                Ok(user) => {
                    if user.access_scope == AccessScope::Administrator {
                        return Ok(AuthenticatedAdministrator(user));
                    }
                    Err(ErrorUnauthorized("ERROR: Not an administrator!"))
                }
                Err(err) => Err(err),
            }
        })
    }
}

/// This hashmap uses the uuid that is generated when a new user is inserted
/// as a key. The uuid is stored as enrypted cookie in the client browser.
pub type AuthenticatedUsersHashMap = HashMap<Uuid, AuthenticatedUser>;

/// Information about authenticated users shared between the worker threads
pub struct SharedAuthenticatedUsersHashMap {
    /// holds the authenticated users
    pub authenticated_users_hashmap: AuthenticatedUsersHashMap,
    /// used by the uuid crate to build unique uuids across threads
    pub uuid_context: Context,
    /// These accounts are designated administrators
    /// from the configuration file.
    /// They are ot derived from the ldap server because
    /// other authentication methods may be
    /// implemented in future versions.
    /// There shouldn't be too many accounts anyway.
    admin_accounts: Vec<String>,
}

impl SharedAuthenticatedUsersHashMap {
    /// Creates a new instance
    ///
    /// # Arguments
    ///
    /// - `admin_accounts`:  `Vec<String>` containing the user names of
    ///   valid administrators.
    pub fn new(admin_accounts: Vec<String>) -> SharedAuthenticatedUsersHashMap {
        SharedAuthenticatedUsersHashMap {
            authenticated_users_hashmap: AuthenticatedUsersHashMap::new(),
            uuid_context: Context::new(1),
            admin_accounts,
        }
    }

    /// Store authenticated user data and return the uuid for the cookie
    pub fn new_cookie_data_for(
        &mut self,
        user_name: &str,
        first_name: &str,
        last_name: &str,
        mail: &str,
        peer_ip: &str,
    ) -> Option<CookieData> {
        // A real user/browser will come back again and start a new authentication
        // attempt. A possible attacker will simply knock on the server without beeing
        // redirected to the authentication url again and stopped after reaching MAX_AUTH_USERS.
        // So the webservice won't consume all memory on the host.
        if self.authenticated_users_hashmap.len() >= MAX_AUTH_USERS {
            warn!("MAX_AUTH_USERS exceeded, server busy or possible DOS attack!");
            return None;
        }

        // check if it's an administrator
        let scope = match self.admin_accounts.contains(&user_name.to_string()) {
            true => AccessScope::Administrator,
            false => AccessScope::User,
        };
        let authenticated_user =
            AuthenticatedUser::new(user_name, first_name, last_name, mail, scope, peer_ip);
        let unix_timestamp_seconds = authenticated_user.utc_date_time.timestamp() as u64;
        let unix_timestamp_subsec_nanos = authenticated_user.utc_date_time.timestamp_subsec_nanos();
        let ts = Timestamp::from_unix(
            &self.uuid_context,
            unix_timestamp_seconds,
            unix_timestamp_subsec_nanos,
        );
        let request_uuid = Uuid::new_v1(ts, NODE_ID);

        self.authenticated_users_hashmap
            .insert(request_uuid, authenticated_user);
        Some(CookieData {
            uuid: request_uuid,
            cookie_update_lifetime_counter: 0,
        })
    }
}

/// Removes aged authenticated users.
///
/// This happens when the `max_cookie_age_seconds` from the configuration
/// file have elapsed.
/// The html files with forms call the route `/authenticated/keep_session_alive`
/// once a minute, to update the cookie timestamp. Once they leave the forms,
/// they will be removed after `max_cookie_age_seconds` + [1, `cleanup_timers::TIMER_INTERVAL_SECONDS`].
#[inline]
pub fn cleanup_authenticated_users_hashmap(
    shared_authenticated_users: &Arc<RwLock<SharedAuthenticatedUsersHashMap>>,
    max_age_in_seconds: i64,
) {
    let time_to_delete = Utc::now()
        - Duration::try_seconds(max_age_in_seconds)
            .unwrap_or_else(|| Duration::try_seconds(MAX_COOKIE_AGE_SECONDS).unwrap());
    let shared_authenticated_users_read_lock = shared_authenticated_users.read().unwrap();
    let mut items_to_remove: Vec<uuid::Uuid> = Vec::new();
    for (k, v) in &shared_authenticated_users_read_lock.authenticated_users_hashmap {
        // remove authenticated users after the configured time
        if v.utc_date_time < time_to_delete {
            info!("removing {}, {}", &k.to_string(), &v);
            items_to_remove.push(*k);
        }
    }
    drop(shared_authenticated_users_read_lock);

    let mut shared_authenticated_users_write_lock = shared_authenticated_users.write().unwrap();
    for item in items_to_remove {
        shared_authenticated_users_write_lock
            .authenticated_users_hashmap
            .remove(&item);
    }
}
