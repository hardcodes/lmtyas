// tell the rust compiler which modules we have in extra files
#[cfg(feature = "api-access-token")]
pub mod access_token;
pub mod aes_trait;
pub mod app_macro;
pub mod authenticated_user;
pub mod authentication_functions;
#[cfg(feature = "ldap-auth")]
pub mod authentication_ldap;
pub mod authentication_middleware;
#[cfg(feature = "authentication-oidc")]
pub mod authentication_oidc;
// pub mod base64_trait;
pub mod cert_renewal;
pub mod cleanup_timer;
pub mod cli_parser;
pub mod configuration;
pub mod cookie_functions;
pub mod csrf_html_template;
pub mod error;
#[cfg(feature = "get-userdata-ldap")]
pub mod get_userdata_ldap;
pub mod get_userdata_trait;
pub mod handler_functions;
pub mod header_value_trait;
pub mod http_traits;
pub mod ip_address;
#[cfg(feature = "ldap-common")]
pub mod ldap_common;
pub mod log_functions;
pub mod login_user_trait;
pub mod mail_configuration;
#[cfg(feature = "mail-noauth-notls")]
pub mod mail_noauth_notls;
#[cfg(feature = "oidc-ldap")]
pub mod oidc_ldap;
pub mod secret_functions;
pub mod string_trait;
pub mod unsecure_string;

pub const PROGRAM_NAME: &str = env!("CARGO_PKG_NAME");
pub const PROGRAM_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const PROGRAM_AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
pub const PROGRAM_DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");
pub const UNKNOWN_RECEIVER_EMAIL: &str = "UNKOWN RECEIVER EMAIL";
#[cfg(debug_assertions)]
pub const BUILD_TYPE: &str = "DEBUG build";
#[cfg(not(debug_assertions))]
pub const BUILD_TYPE: &str = "release build";
#[cfg(target_os = "windows")]
compile_error!("target_os windows is not supported");
// generic regex to validate email address format
pub const EMAIL_REGEX: &str = r"^([a-zA-Z0-9_\-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([a-zA-Z0-9\-]+\.)+))([a-zA-Z]{2,5}|[0-9]{1,3})(\]?)$";
/// max length of form data
pub const MAX_FORM_BYTES_LEN: usize = 20_000;
/// max length of form fields
pub const MAX_FORM_INPUT_LEN: usize = 11_000;
// fallback value if the value in the config file is out of bounds.
pub const MAX_AUTHREQUEST_AGE_SECONDS: i64 = 300;
// fallback value if the value in the config file is out of bounds.
pub const MAX_COOKIE_AGE_SECONDS: i64 = 120;
// The access token should fit in here.
#[cfg(feature = "api-access-token")]
pub const MAX_BEARER_TOKEN_LEN: usize = 1_408;

#[cfg(feature = "ldap-auth")]
pub mod authentication_url {
    pub const AUTH_ROUTE: &str = "/login";
    pub const AUTH_PATH: &str = "./web-content/authentication-ldap/";
    pub const AUTH_INDEX_PAGE: &str = "nothing-here.html";
}

#[cfg(feature = "oidc-auth-ldap")]
pub mod authentication_url {
    pub const AUTH_ROUTE: &str = "/callback";
    pub const AUTH_PATH: &str = "./web-content/authentication-oidc/";
    pub const AUTH_INDEX_PAGE: &str = "nothing-here.html";
    pub const AUTH_LOGIN_FAIL_PAGE: &str = "/authentication/login-fail.html";
}

// capacity of the vector that stores the cleanup timers.
#[cfg(feature = "oidc-auth-ldap")]
pub const TIMER_VEC_CAPACITY: usize = 3;
#[cfg(not(feature = "oidc-auth-ldap"))]
pub const TIMER_VEC_CAPACITY: usize = 2;

// command to start and stop containers
#[cfg(debug_assertions)]
pub const CONTAINER_COMMAND: &str = "podman";
//pub const CONTAINER_COMMAND: &str = "docker";
