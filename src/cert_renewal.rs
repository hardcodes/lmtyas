#[cfg(feature = "ldap-auth")]
use crate::authentication_ldap::LdapCommonConfiguration;
use crate::authentication_middleware::CheckAuthentication;
#[cfg(feature = "oidc-auth-ldap")]
use crate::authentication_oidc::OidcConfiguration;
use crate::authentication_url;
use crate::configuration::ApplicationConfiguration;
use crate::handler_functions::*;
use crate::log_functions::extract_request_path;
use crate::login_user_trait::Login;
use crate::MAX_FORM_BYTES_LEN;
use actix_files::Files;
use actix_web::dev::ServerHandle;
use actix_web::{guard, middleware, web, App, HttpRequest, HttpResponse, HttpServer};
use log::{debug, info, warn};
#[cfg(not(debug_assertions))]
use std::env;
#[cfg(debug_assertions)]
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

#[cfg(feature = "ldap-auth")]
type AuthConfiguration = LdapCommonConfiguration;
#[cfg(feature = "oidc-auth-ldap")]
type AuthConfiguration = OidcConfiguration;

pub const UNIX_DOMAIN_SOCKET_FILE: &str = "lmtyas-uds.socket";

/// Status of the tls certificate of the tcp/https server
#[derive(PartialEq, Eq)]
pub enum TlsCertStatus {
    /// The tls certificate has not been loaded yet = the tcp/https server is not running
    NotLoaded,
    /// The tls certificate has been loaded, the tcp/https server is starting or running
    HasBeenLoaded,
    /// The unix domain socket server received a request to reload the tls certificate
    ReloadRequested,
}

/// Configuration data for the Unix Domain Socket server.
/// We don't need the whole config of the application
#[derive(Clone)]
pub struct UdsConfiguration {
    // stores the current status of the TLS/SSL certificate
    pub tls_cert_status: Arc<Mutex<TlsCertStatus>>,
    // stores the server handle of the tcp/https server
    pub tcp_server_handle: Arc<Mutex<Option<ServerHandle>>>,
}

impl UdsConfiguration {
    pub fn new(tls_cert_status: Arc<Mutex<TlsCertStatus>>) -> Self {
        UdsConfiguration {
            tls_cert_status,
            tcp_server_handle: Arc::new(Mutex::new(None)),
        }
    }
}

/// Loop that restarts the tcp/https server after certificate reload.
/// Needed because there are no async closures in Rust yet.
pub async fn tcp_server_loop(
    application_configuration: ApplicationConfiguration,
    uds_configuration: UdsConfiguration,
) -> std::io::Result<()> {
    // make a clone of the web_bind_address since it will be used
    // after moving application_configuration into the webservice
    let web_bind_address = application_configuration
        .configuration_file
        .web_bind_address
        .clone();
    // Restart tcp/https server after certificate reload in a loop
    loop {
        let rusttls_server_config = match application_configuration.load_rustls_config().await {
            Ok(c) => c,
            Err(e) => {
                warn!("Cannot load tls certficate : {}", &e);
                std::process::exit(1);
            }
        };
        // values for the csp-header
        let content_security_policy = concat!(
            "form-action 'self';",
            "frame-ancestors 'none';",
            "connect-src 'self';",
            "default-src 'self';",
            "script-src 'self';",
            "style-src 'self';",
        );
        info!(
            "{} {} webservice ({}) will bind to {}",
            &crate::PROGRAM_NAME,
            &crate::PROGRAM_VERSION,
            &crate::BUILD_TYPE,
            &web_bind_address
        );
        let app_conf = application_configuration.clone();
        // HTTPS web server (public facing service)
        let tcp_server = HttpServer::new(move || {
            // The app! macro contains all routes that are used to build the service.
            // Creating them this way makes them reusable for testing. Idea taken from
            // https://stackoverflow.com/questions/72415245/actix-web-integration-tests-reusing-the-main-thread-application
            // See answer from Ovidiu Gheorghies.
            crate::app!(app_conf, content_security_policy, MAX_FORM_BYTES_LEN)
        })
        .keep_alive(std::time::Duration::from_secs(30))
        .bind_rustls_0_23(web_bind_address.clone(), rusttls_server_config.clone())?
        .run();
        // store the tcp/https-server handle, so that the uds server can stop it.
        let https_server_handle = tcp_server.handle();
        {
            let mut tcp_server_handle_lock = uds_configuration.tcp_server_handle.lock().await;
            *tcp_server_handle_lock = Some(https_server_handle);
        }
        tcp_server.await?;
        if TlsCertStatus::ReloadRequested != *application_configuration.tls_cert_status.lock().await
        {
            // This should only happen if the service is stopped.
            info!("https server went down");
            let uds_server_handle_rlock = application_configuration.uds_server_handle.lock().await;
            let handle = match uds_server_handle_rlock.as_ref() {
                None => {
                    // Should never happen
                    warn!("uds server handle missing, cannot stop server");
                    break;
                }
                Some(handle) => handle.clone(),
            };
            debug!("got uds server handle");
            info!("stopping uds server");
            handle.stop(true).await;
            break;
        }
    }
    Ok(())
}

/// Wrapper that starts the Unix Domain Socket server that
/// waits for a command to reload the certificate files.
/// Hack to provide the same return type as `tcp_server_loop`.
pub async fn uds_server(
    application_configuration: ApplicationConfiguration,
    uds_configuration: UdsConfiguration,
) -> std::io::Result<()> {
    // Unix domain socket listening for commands
    // from the Unix system where we run at.
    #[cfg(debug_assertions)]
    let socket_file = Path::new("/tmp").join(UNIX_DOMAIN_SOCKET_FILE);
    #[cfg(not(debug_assertions))]
    let socket_file = env::current_dir()?
        .join("socket")
        .join(UNIX_DOMAIN_SOCKET_FILE);

    info!(
        "{} {} control socket ({}) will bind to unix:{}",
        &crate::PROGRAM_NAME,
        &crate::PROGRAM_VERSION,
        &crate::BUILD_TYPE,
        &socket_file.to_string_lossy()
    );
    let uds_server = HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::new("%a %{User-Agent}i %r %U"))
            // clone of the application configuration
            .app_data(web::Data::new(uds_configuration.clone()))
            .service(web::resource("/reload-cert").to(uds_reload_cert))
            .default_service(web::to(uds_unknown_request))
    })
    .workers(1)
    .bind_uds(socket_file)?
    .run();
    // store the uds server handle, so that the tcp/https-server control thread can stop it.
    let uds_server_handle = uds_server.handle();
    {
        let mut uds_server_handle_lock = application_configuration.uds_server_handle.lock().await;
        *uds_server_handle_lock = Some(uds_server_handle);
    }
    uds_server.await?;
    Ok(())
}
/// Default route for all unknown requests received via unix domain socket server
pub async fn uds_unknown_request(_req: HttpRequest) -> HttpResponse {
    warn!("received unknown request via unix domain socket!");
    HttpResponse::BadRequest().body("unkown request")
}

/// Handle the reload tls certificate request
pub async fn uds_reload_cert(uds_configuration: web::Data<UdsConfiguration>) -> &'static str {
    const OK_MESSAGE: &str = "received reload cert request!";
    const ERROR_MESSAGE: &str = "ERROR, cannot reload cert!";
    info!("received reload cert request via unix domain socket!");
    {
        let mut tls_cert_status_lock = uds_configuration.tls_cert_status.lock().await;
        if *tls_cert_status_lock != TlsCertStatus::HasBeenLoaded {
            // Make sure that we were not called too early, before the server was even started.
            warn!("https server is not ready yet, cannot reload certificate");
            return ERROR_MESSAGE;
        }
        *tls_cert_status_lock = TlsCertStatus::ReloadRequested;
    }

    let tcp_server_handle_rlock = uds_configuration.tcp_server_handle.lock().await;
    let handle = match tcp_server_handle_rlock.as_ref() {
        None => {
            // Should never happen
            warn!("https server handle missing, cannot stop server");
            return ERROR_MESSAGE;
        }
        Some(handle) => handle.clone(),
    };
    debug!("got https server handle");
    info!("stopping https server");
    handle.stop(true).await;

    OK_MESSAGE
}
