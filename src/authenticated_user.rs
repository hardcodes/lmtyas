use chrono::{DateTime, Utc};
use log::{info, warn};
use std::collections::HashMap;
use uuid::v1::{Context, Timestamp};
use uuid::Uuid;
extern crate env_logger;
use crate::authentication_functions::get_authenticated_user;
use actix_web::{dev::Payload, error::ErrorUnauthorized, Error, FromRequest, HttpRequest};
use chrono::Duration;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};

/// maximum number of authenticated users that are stored in the
/// hashmap to prevent server overload or a DOS attack.
pub const MAX_AUTH_USERS: usize = 512;
/// Used to build unique uuids for resource requests
const NODE_ID: &[u8; 6] = &[0x27, 0x9b, 0xbe, 0x13, 0x86, 0x80];

/// Defines the type of user
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccessScope {
    User,
    Administrator,
}

/// Holds the information of an authenticated user (name and timestamp of authentication).
#[derive(Clone)]
pub struct AuthenticatedUser {
    pub user_name: String,
    pub first_name: String,
    pub last_name: String,
    pub mail: String,
    pub time_stamp: DateTime<Utc>,
    pub access_scope: AccessScope,
    pub peer_ip: String,
}

/// custom formatter to suppress first name, last name and mail address
impl fmt::Display for AuthenticatedUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(user_name={}, time_stamp={}, access_scope={:?}, peer_ip={})",
            self.user_name, self.time_stamp, self.access_scope, self.peer_ip
        )
    }
}

/// Administrators are still users just with a different scope
pub struct AuthenticatedAdministrator(AuthenticatedUser);

/// Holds the information of an authenticated user
impl AuthenticatedUser {
    /// Creates a new instance with the given user name and current time stamp.
    fn new(
        user_name: &str,
        first_name: &str,
        last_name: &str,
        mail: &str,
        access_scope: AccessScope,
        peer_ip: &str,
    ) -> AuthenticatedUser {
        AuthenticatedUser {
            user_name: String::from(user_name),
            first_name: String::from(first_name),
            last_name: String::from(last_name),
            mail: String::from(mail),
            access_scope,
            peer_ip: String::from(peer_ip),
            time_stamp: Utc::now(),
        }
    }

    /// Update the timestamp before a cookie lifetime is expied to
    /// stay in the hashmap
    pub fn update_timestamp(&mut self) {
        self.time_stamp = Utc::now()
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
        Box::pin(async move { get_authenticated_user(&req) })
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
/// as a key. The uuid is stored as cookie in the client browser.
pub type AuthenticatedUsersHashMap = HashMap<Uuid, AuthenticatedUser>;

/// Information about authenticated users shared between the worker threads
pub struct SharedAuthenticatedUsersHashMap {
    /// holds the authenticated users
    pub authenticated_users_hashmap: AuthenticatedUsersHashMap,
    /// used by the uuid crate to build unique uuids across threads
    pub uuid_context: Context,
    /// These accounts are administrators
    /// Not derived from the ldap server because
    /// other authentication methods may be
    /// implemented in future versions.
    /// It shouldn't be too many accounts anyway.
    admin_accounts: Vec<String>,
}

impl SharedAuthenticatedUsersHashMap {
    /// Creates a new instance
    ///
    /// # Arguments
    ///
    /// - `admin_accounts`:  `Vec<String>` containing the user names of
    ///                       valid administrators.
    pub fn new(admin_accounts: Vec<String>) -> SharedAuthenticatedUsersHashMap {
        SharedAuthenticatedUsersHashMap {
            authenticated_users_hashmap: AuthenticatedUsersHashMap::new(),
            uuid_context: Context::new(1),
            admin_accounts,
        }
    }

    /// Store an authenticated user name and return the uuid for the cookie
    pub fn new_cookie_uuid_for(
        &mut self,
        user_name: &str,
        first_name: &str,
        last_name: &str,
        mail: &str,
        peer_ip: &str,
    ) -> Option<uuid::Uuid> {
        // check if it's an administrator
        let scope = match self.admin_accounts.contains(&user_name.to_string()) {
            true => AccessScope::Administrator,
            false => AccessScope::User,
        };
        let authenticated_user =
            AuthenticatedUser::new(user_name, first_name, last_name, mail, scope, peer_ip);
        let unix_timestamp_seconds = authenticated_user.time_stamp.timestamp() as u64;
        let unix_timestamp_subsec_nanos = authenticated_user.time_stamp.timestamp_subsec_nanos();
        let ts = Timestamp::from_unix(
            &self.uuid_context,
            unix_timestamp_seconds,
            unix_timestamp_subsec_nanos,
        );
        let request_uuid = Uuid::new_v1(ts, NODE_ID);
        if self.authenticated_users_hashmap.len() >= MAX_AUTH_USERS {
            // A real user/browser will come back again and start a new authentication
            // attempt. A possible attacker will simply knock on the server without beeing
            // redirected to the authentication url again and stopped after reaching MAX_AUTH_USERS.
            // So the webservice won't consume all memory on the host.
            warn!("MAX_AUTH_USERS exceeded, possible DOS attack!");
            return None;
        } else {
            self.authenticated_users_hashmap
                .insert(request_uuid, authenticated_user);
        }
        Some(request_uuid)
    }
}

/// Removes aged authenticated users.
/// This happens when the `max_cookie_age_seconds` from the configuration
/// file have past.
/// The html files with forms call the route `/authenticated/keep_session_alive`
/// once a minute, to update the cookie timestamp. Once they leave the forms,
/// they will be removed, after `max_cookie_age_seconds`.
#[inline]
pub fn cleanup_authenticated_users_hashmap(
    shared_authenticated_users: &Arc<RwLock<SharedAuthenticatedUsersHashMap>>,
    max_age_in_seconds: i64,
) {
    let time_to_delete = Utc::now() - Duration::seconds(max_age_in_seconds);
    let shared_authenticated_users_read_lock = shared_authenticated_users.read().unwrap();
    let mut items_to_remove: Vec<uuid::Uuid> = Vec::new();
    for (k, v) in &shared_authenticated_users_read_lock.authenticated_users_hashmap {
        // remove authenticated users after the configured time
        if v.time_stamp < time_to_delete {
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
