use actix_web::dev::ServerHandle;
use actix_web::{web, HttpRequest, HttpResponse};
use log::{debug, info, warn};
use std::sync::{Arc, RwLock};

#[cfg(debug_assertions)]
pub const UNIX_DOMAIN_SOCKET_FILE: &str = "/tmp/lmtyas-uds.socket";
#[cfg(not(debug_assertions))]
pub const BUILD_TYPE: &str = "socket/lmtyas-uds.socket";

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
    pub tls_cert_status: Arc<RwLock<TlsCertStatus>>,
    // stores the server handle of the tcp/https server
    pub tcp_server_handle: Arc<RwLock<Option<ServerHandle>>>,
}

impl UdsConfiguration {
    pub fn new(tls_cert_status: Arc<RwLock<TlsCertStatus>>) -> Self {
        UdsConfiguration {
            tls_cert_status,
            tcp_server_handle: Arc::new(RwLock::new(None)),
        }
    }
}

/// Default route for all unknown requests received via unix domain socket server
pub async fn uds_unknown_request(_req: HttpRequest) -> HttpResponse {
    warn!("received unknown request via unix domain socket!");
    HttpResponse::BadRequest().body("unkown request")
}

/// Handle the reload tls certificate request
pub async fn uds_reload_cert(
    uds_configuration: web::Data<UdsConfiguration>,
) -> &'static str {
    const OK_MESSAGE: &str = "received reload cert request!";
    const ERROR_MESSAGE: &str = "ERROR, cannot reload cert!";
    info!("received reload cert request via unix domain socket!");
    {
        let mut tls_cert_status_rwlock = uds_configuration.tls_cert_status.write().unwrap();
        if *tls_cert_status_rwlock != TlsCertStatus::HasBeenLoaded {
            // Make sure that we were not called too early, before the server was even started.
            warn!("https server is not ready yet, cannot reload certificate");
            return ERROR_MESSAGE;
        }
        *tls_cert_status_rwlock = TlsCertStatus::ReloadRequested;
    }

    let tcp_server_handle_rwlock = uds_configuration.tcp_server_handle.read().unwrap();
    let handle = match tcp_server_handle_rwlock.as_ref() {
        None => {
            // Should never happen
            warn!("https server handle missing, cannot stop server");
            return ERROR_MESSAGE;
        }
        Some(handle) => handle.clone(),
    };
    debug!("got https server handle");
    drop(tcp_server_handle_rwlock);
    info!("stopping https server");
    handle.stop(true).await;

    OK_MESSAGE
}
