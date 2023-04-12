// tell the rust compiler which modules we have in extra files
pub mod aes_functions;
pub mod authenticated_user;
pub mod authentication_functions;
#[cfg(feature = "ldap-auth")]
pub mod authentication_ldap;
#[cfg(feature = "ldap-common")]
pub mod ldap_common;
pub mod authentication_middleware;
pub mod base64_trait;
pub mod cli_parser;
pub mod configuration;
pub mod cookie_functions;
pub mod get_userdata_trait;
pub mod handler_functions;
pub mod header_value_trait;
pub mod http_traits;
pub mod log_functions;
pub mod login_user_trait;
pub mod mail_configuration;
#[cfg(feature = "mail-noauth-notls")]
pub mod mail_noauth_notls;
pub mod rsa_functions;
pub mod secret_functions;
pub mod unsecure_string;

pub const PROGRAM_NAME: &str = env!("CARGO_PKG_NAME");
pub const PROGRAM_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const PROGRAM_AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
pub const PROGRAM_DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

#[cfg(feature = "ldap-auth")]
pub const AUTH_PAGE: &str = "nothing-here.html";
