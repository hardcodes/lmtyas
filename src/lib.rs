// tell the rust compiler which modules we have in extra files
pub mod aes_functions;
pub mod authenticated_user;
pub mod authentication_functions;
#[cfg(feature = "ldap-auth")]
pub mod authentication_ldap;
pub mod authentication_middleware;
#[cfg(feature = "authentication-oidc")]
pub mod authentication_oidc;
pub mod base64_trait;
pub mod cleanup_timer;
pub mod cli_parser;
pub mod configuration;
pub mod cookie_functions;
#[cfg(feature = "get-userdata-ldap")]
pub mod get_userdata_ldap;
pub mod get_userdata_trait;
pub mod handler_functions;
pub mod header_value_trait;
pub mod http_traits;
#[cfg(feature = "ldap-common")]
pub mod ldap_common;
pub mod log_functions;
pub mod login_user_trait;
pub mod mail_configuration;
#[cfg(feature = "mail-noauth-notls")]
pub mod mail_noauth_notls;
#[cfg(feature = "mail-noauth-notls-smime")]
pub mod mail_noauth_notls_smime;
#[cfg(feature = "oidc-ldap")]
pub mod oidc_ldap;
pub mod rsa_functions;
pub mod secret_functions;
pub mod string_trait;
pub mod unsecure_string;

pub const PROGRAM_NAME: &str = env!("CARGO_PKG_NAME");
pub const PROGRAM_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const PROGRAM_AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
pub const PROGRAM_DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");
pub const UNKOWN_RECEIVER_EMAIL: &str = "UNKOWN RECEIVER EMAIL";
// generic regex to validate email address format
pub const EMAIL_REGEX: &str = r"^([a-zA-Z0-9_\-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([a-zA-Z0-9\-]+\.)+))([a-zA-Z]{2,5}|[0-9]{1,3})(\]?)$";

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

#[cfg(feature = "oidc-auth-ldap")]
pub const TIMER_VEC_CAPACITY: usize = 3;
#[cfg(not(feature = "oidc-auth-ldap"))]
pub const TIMER_VEC_CAPACITY: usize = 2;
