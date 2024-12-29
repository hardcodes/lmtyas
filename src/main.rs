use actix_files::Files;
use actix_web::{guard, middleware, web, App, HttpResponse, HttpServer};
#[cfg(feature = "ldap-auth")]
use lmtyas::authentication_ldap::LdapCommonConfiguration;
use lmtyas::authentication_middleware::CheckAuthentication;
#[cfg(feature = "oidc-auth-ldap")]
use lmtyas::authentication_oidc::OidcConfiguration;
use lmtyas::authentication_url;
use lmtyas::cleanup_timer::build_cleanup_timers;
use lmtyas::cli_parser::{parse_cli_parameters, ARG_CONFIG_FILE};
use lmtyas::configuration::ApplicationConfiguration;
use lmtyas::handler_functions::*;
use lmtyas::log_functions::extract_request_path;
use lmtyas::login_user_trait::Login;
use lmtyas::MAX_FORM_BYTES_LEN;
use log::info;
use log::warn;
use std::io::Write;
use std::path::Path;

#[cfg(feature = "ldap-auth")]
type AuthConfiguration = LdapCommonConfiguration;
#[cfg(feature = "oidc-auth-ldap")]
type AuthConfiguration = OidcConfiguration;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // crate env_logger is configured via the RUST_LOG environment variable
    #[cfg(debug_assertions)]
    std::env::set_var("RUST_LOG", "debug, actix_web=trace");
    #[cfg(not(debug_assertions))]
    std::env::set_var("RUST_LOG", "info, actix_web=info");
    env_logger::builder()
        .format(|buf, record| writeln!(buf, "{}: {}", record.level(), record.args()))
        .init();

    // parse cli parameters and load the configuration
    let clap_arg_matches = parse_cli_parameters();
    let config_file: String = clap_arg_matches
        .get_one::<String>(ARG_CONFIG_FILE)
        .unwrap()
        .to_string();
    let application_configuration =
        match ApplicationConfiguration::read_from_file(Path::new(&config_file)).await {
            Err(e) => {
                warn!("Cannot load application configuration: {}", &e);
                std::process::exit(1);
            }
            Ok(a) => a,
        };
    // make a clone of the web_bind_address since it will be used
    // after moving application_configuration into the webservice
    let web_bind_address = application_configuration
        .configuration_file
        .web_bind_address
        .clone();

    // build cleanup timers and store references to keep them running
    let timer_guards = build_cleanup_timers(&application_configuration);
    info!("started {} cleanup timers", timer_guards.len());

    // values for the csp-header
    let content_security_policy = concat!(
        "form-action 'self';",
        "frame-ancestors 'none';",
        "connect-src 'self';",
        "default-src 'self';",
        "script-src 'self';",
        "style-src 'self';",
    );

    match rustls::crypto::aws_lc_rs::default_provider().install_default() {
        Ok(r) => r,
        Err(_) => {
            warn!("Cannot install rusttls crypto provider.");
            std::process::exit(1);
        }
    };

    let rusttls_server_config = match application_configuration.load_rustls_config() {
        Ok(c) => c,
        Err(e) => {
            warn!("Cannot load tls certficate : {}", &e);
            std::process::exit(1);
        }
    };

    info!(
        "{} {} ({}) will bind to {}",
        &lmtyas::PROGRAM_NAME,
        &lmtyas::PROGRAM_VERSION,
        &lmtyas::BUILD_TYPE,
        &web_bind_address
    );

    // The app! macro contains all routes that are used to build the service.
    // Creating them this way makes them reusable for testing. Idea taken from
    // https://stackoverflow.com/questions/72415245/actix-web-integration-tests-reusing-the-main-thread-application
    // See answer from Ovidiu Gheorghies.
    HttpServer::new(move || {
        lmtyas::app!(
            application_configuration,
            content_security_policy,
            MAX_FORM_BYTES_LEN
        )
    })
    .keep_alive(std::time::Duration::from_secs(45))
    .bind_rustls_0_23(web_bind_address, rusttls_server_config)?
    .run()
    .await
}
