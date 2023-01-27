use actix_files::Files;
use actix_web::{guard, middleware, web, App, HttpResponse, HttpServer};
use lmtyas::authenticated_user::cleanup_authenticated_users_hashmap;
#[cfg(feature = "ldap-auth")]
use lmtyas::authentication_ldap::LdapAuthConfiguration;
use lmtyas::authentication_middleware::{cleanup_authentication_state_hashmap, CheckAuthentication};
use lmtyas::cli_parser::parse_cli_parameters;
use lmtyas::configuration::ApplicationConfiguration;
use lmtyas::handler_functions::*;
use log::info;
use lmtyas::log_functions::extract_request_path;
use lmtyas::login_user_trait::Login;
use std::io::Write;
use std::path::Path;
use timer::Timer;

// const PROGRAM_NAME: &str = env!("CARGO_PKG_NAME");
// const PROGRAM_VERSION: &str = env!("CARGO_PKG_VERSION");
// const PROGRAM_AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
// const PROGRAM_DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

#[cfg(feature = "ldap-auth")]
type AuthConfiguration = LdapAuthConfiguration;
// #[cfg(feature = "ldap-auth")]
// const AUTH_PAGE: &str = "ldap.html";

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // crate env_logger is configured via the RUST_LOG environment variable
    #[cfg(debug_assertions)]
    std::env::set_var("RUST_LOG", "debug, actix_web=trace");
    #[cfg(not(debug_assertions))]
    std::env::set_var("RUST_LOG", "info, actix_web=trace");
    env_logger::builder()
        .format(|buf, record| writeln!(buf, "{}: {}", record.level(), record.args()))
        .init();

    // parse cli parameters and load the configuration
    let clap_arg_matches = parse_cli_parameters();
    let config_file: String = clap_arg_matches
        .get_one::<String>("configfile")
        .unwrap()
        .to_string();
    let application_configuration =
        ApplicationConfiguration::read_from_file(Path::new(&config_file));
    // make a clone of the web_bind_address since it will be used
    // after moving application_configuration into the webservice
    let web_bind_address = application_configuration
        .configuration_file
        .web_bind_address
        .clone();
    // load ssl keys
    let ssl_acceptor_builder = application_configuration.get_ssl_acceptor_builder();

    // timer that calls a cleanup routine every 15 seconds
    // and removes used or aged authentication requests
    let auth_duration = application_configuration
        .configuration_file
        .max_authrequest_age_seconds;
    let cleanup_authentication_state_hashmap_timer = Timer::new();
    let authentication_state_hashmap = application_configuration.shared_request_data.clone();
    let _cleanup_authentication_state_hashmap_guard = cleanup_authentication_state_hashmap_timer
        .schedule_repeating(chrono::Duration::seconds(15), move || {
            cleanup_authentication_state_hashmap(&authentication_state_hashmap, auth_duration)
        });

    // timer that calls a cleanup routine every 15 seconds
    // and removes expired user sessions
    let cookie_duration = application_configuration
        .configuration_file
        .max_cookie_age_seconds;
    let cleanup_authenticated_users_hashmap_timer = Timer::new();
    let authenticated_users_hashmap = application_configuration.shared_authenticated_users.clone();
    let _cleanup_authenticated_users_hashmap_guard = cleanup_authenticated_users_hashmap_timer
        .schedule_repeating(chrono::Duration::seconds(15), move || {
            cleanup_authenticated_users_hashmap(&authenticated_users_hashmap, cookie_duration)
        });
    // values for the csp-header
    let content_security_policy = concat!(
        "script-src 'self';",
        "style-src 'self' 'unsafe-inline';",
        "connect-src 'self';",
        "default-src 'self';",
        "frame-ancestors 'none';"
    );
    info!(
        "{} {} will bind to {}",
        &lmtyas::PROGRAM_NAME, &lmtyas::PROGRAM_VERSION, &web_bind_address
    );
    HttpServer::new(move || {
        App::new()
            // Enable the logger.
            .wrap(
                middleware::Logger::new("%a %{CUSTOM_REQUEST}xi %s %b %{User-Agent}i %T")
                    // exclude the password from appearing in the log
                    .exclude_regex("/authenticated/sysop/set_password_for_rsa_rivate_key")
                    .exclude_regex("/authenticated/secret/reveal")
                    .custom_request_replace("CUSTOM_REQUEST", |req| {
                        extract_request_path(format!("{} {}", &req.method(), &req.uri()).as_str())
                    }),
            )
            .wrap(
                middleware::DefaultHeaders::new()
                    .add((
                        "Strict-Transport-Security",
                        "max-age=31536000; includeSubDomains",
                    ))
                    .add(("Content-Security-Policy", content_security_policy))
                    .add(("X-Frame-Options", "DENY")),
            )
            // clone of the application configuration
            .app_data(web::Data::new(application_configuration.clone()))
            // set one route without authentication so that monitoring software can check if we are still running
            .service(web::scope("/monitoring").route("/still_alive", web::get().to(still_alive)))
            // routes without authentication to get information about the running server
            .service(
                web::scope("/system")
                    .route("/is_server_ready", web::get().to(is_server_ready))
                    .route("/get/login-hint", web::get().to(get_login_hint))
                    .route("/get/mail-hint", web::get().to(get_mail_hint))
                    .route("/get/imprint-link", web::get().to(get_imprint_link)),
            )
            .service(web::resource("/").route(web::get().to(redirect_to_index)))
            // routes for authenticated administrators only
            .service(
                web::scope("authenticated/sysop")
                    .wrap(CheckAuthentication)
                    .route(
                        "/set_password_for_rsa_rivate_key/{password}",
                        web::post().to(set_password_for_rsa_rivate_key),
                    )
                    // serve files to admins only
                    // for just two files dedicated functions are fine
                    // with more to come a more generic approach must be used
                    .route("/sysop.html", web::get().to(get_sysop_html))
                    .route("/js/sysop.js", web::get().to(get_sysop_js)),
            )
            // routes for authenticated regular users
            .service(
                web::scope("authenticated/secret")
                    .wrap(CheckAuthentication)
                    .route("/tell", web::post().to(store_secret))
                    .route(
                        "/reveal/{encrypted_percent_encoded_url_payload}",
                        web::get().to(reveal_secret),
                    ),
            )
            .service(
                web::scope("authenticated/user")
                    .wrap(CheckAuthentication)
                    .route(
                        "/get/details/from",
                        web::get().to(get_authenticated_user_details),
                    ),
            )
            .service(
                web::scope("authenticated")
                    .wrap(CheckAuthentication)
                    .route("/keep_session_alive", web::get().to(keep_session_alive)),
            )
            .service(
                web::scope("html")
                    .wrap(CheckAuthentication)
                    .service(Files::new("/", "./authenticated/").index_file("tell.html")),
            )
            .service(
                web::scope("authentication")
                    .route(
                        "/login",
                        // the `AuthConfiguration` type is defined by a selected
                        // feature that implements the `Login` trait.
                        web::post().to(<AuthConfiguration as Login>::login_user),
                    )
                    // the `const AUTH_PAGE` is defined by a selected
                    // feature that points to the login page
                    .service(Files::new("/", "./authentication/").index_file(lmtyas::AUTH_PAGE)),
            )
            // serve custom favicon if it exists
            .route("/gfx/favicon.png", web::get().to(get_favicon))
            // serve custom site logo if it exists
            .route("/gfx/company-logo.png", web::get().to(get_company_logo))
            // serve custom colors.css file if it exists
            .route("/css/colors.css", web::get().to(get_colors_css))
            .service(Files::new("/", "./static/").index_file("index.html"))
            .service(
                web::resource("").route(
                    web::route()
                        .guard(guard::Trace())
                        .to(HttpResponse::MethodNotAllowed),
                ),
            )
            .default_service(web::to(not_found_404))
    })
    .keep_alive(std::time::Duration::from_secs(45))
    .bind_openssl(web_bind_address, ssl_acceptor_builder)?
    .run()
    .await
}
