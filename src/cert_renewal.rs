use actix_web::{web, HttpRequest, HttpResponse, dev::ServerHandle};
use crate::configuration::ApplicationConfiguration;
use log::{info, warn};

pub const CERT_TIMER_INTERVAL_SECONDS: i64 = 5;

#[cfg(debug_assertions)]
pub const UNIX_DOMAIN_SOCKET_FILE: &str = "/tmp/actix-uds.socket";
#[cfg(not(debug_assertions))]
pub const BUILD_TYPE: &str = "socket/actix-uds.socket";

#[derive(PartialEq, Eq)]
pub enum TlsCertStatus{
    NotLoaded,
    HasBeenLoaded,
    ReloadRequested
}

pub async fn uds_unknown_request(_req: HttpRequest) -> HttpResponse {
    warn!("received unknown request via unix domain socket!");
    HttpResponse::BadRequest().body("unkown request")
}

pub async fn uds_reload_cert(_req: HttpRequest, application_configuration: web::Data<ApplicationConfiguration>) -> &'static str {
    let mut tls_cert_status_rwlock = application_configuration.tls_cert_status.write().unwrap();
    *tls_cert_status_rwlock = TlsCertStatus::ReloadRequested;
    info!("received reload cert request via unix domain socket!");
    info!("stopping https server");
    let tcp_server_handle_rwlock = application_configuration.tcp_server_handle.write().unwrap();
    match tcp_server_handle_rwlock{
        None => {
            // Should never happen
            warn!("https server handle missing, cannot stop server!");
        }
        Some(handle) => {
            handle.stop(true).await;
        }
    }
    "received reload cert request!"
}

pub async fn check_cert_reload_requested_timer(application_configuration: &ApplicationConfiguration, server_handle: &ServerHandle) {
    if TlsCertStatus::ReloadRequested == *application_configuration.tls_cert_status.read().unwrap(){
        info!("stopping server to reload certificates");
        server_handle.stop(true).await
    }
}