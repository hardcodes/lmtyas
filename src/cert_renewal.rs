use crate::configuration::ApplicationConfiguration;
use actix_web::{web, HttpRequest, HttpResponse};
use log::{info, warn};

pub const CERT_TIMER_INTERVAL_SECONDS: i64 = 5;

#[cfg(debug_assertions)]
pub const UNIX_DOMAIN_SOCKET_FILE: &str = "/tmp/lmtyas-uds.socket";
#[cfg(not(debug_assertions))]
pub const BUILD_TYPE: &str = "socket/lmtyas-uds.socket";

#[derive(PartialEq, Eq)]
pub enum TlsCertStatus {
    NotLoaded,
    HasBeenLoaded,
    ReloadRequested,
}

pub async fn uds_unknown_request(_req: HttpRequest) -> HttpResponse {
    warn!("received unknown request via unix domain socket!");
    HttpResponse::BadRequest().body("unkown request")
}

pub async fn uds_reload_cert(
    _req: HttpRequest,
    application_configuration: web::Data<ApplicationConfiguration>,
) -> &'static str {
    const RETURN_MESSAGE: &str = "received reload cert request!";
    let mut tls_cert_status_rwlock = application_configuration.tls_cert_status.write().unwrap();
    *tls_cert_status_rwlock = TlsCertStatus::ReloadRequested;
    info!("received reload cert request via unix domain socket!");

    let tcp_server_handle_rwlock = application_configuration.tcp_server_handle.read().unwrap();
    let handle = match tcp_server_handle_rwlock.as_ref() {
        None => {
            // Should never happen
            warn!("https server handle missing, cannot stop server");
            return RETURN_MESSAGE;
        }
        Some(handle) => handle.clone(),
    };
    drop(tcp_server_handle_rwlock);
    info!("stopping https server");
    handle.stop(true).await;
    
    RETURN_MESSAGE
}
