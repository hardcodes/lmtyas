// tell the rust compiler which modules we have in extra files
pub mod aes_functions;
pub mod authenticated_user;
pub mod authentication_functions;
#[cfg(feature = "ldap-auth")]
pub mod authentication_ldap;
pub mod authentication_middleware;
pub mod base64_trait;
pub mod cli_parser;
pub mod configuration;
pub mod cookie_functions;
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
#[cfg(feature = "authentication-oidc")]
pub mod authentication_oidc;
#[cfg(feature = "get-userdata-ldap")]
pub mod get_userdata_ldap;
pub mod rsa_functions;
pub mod secret_functions;
pub mod unsecure_string;

pub const PROGRAM_NAME: &str = env!("CARGO_PKG_NAME");
pub const PROGRAM_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const PROGRAM_AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
pub const PROGRAM_DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

#[cfg(feature = "ldap-auth")]
pub mod authentication_url {
    pub const AUTH_ROUTE: &str = "/login";
    pub const AUTH_PATH: &str = "./authentication-ldap/";
    pub const AUTH_INDEX_PAGE: &str = "nothing-here.html";
}

#[cfg(feature = "oidc-auth-ldap")]
pub mod authentication_url {
    pub const AUTH_ROUTE: &str = "/callback";
    pub const AUTH_PATH: &str = "./authentication-oidc/";
    pub const AUTH_INDEX_PAGE: &str = "nothing-here.html";
}
