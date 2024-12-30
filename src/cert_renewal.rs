use actix_web::{web, HttpRequest, HttpResponse};
use crate::configuration::ApplicationConfiguration;
use log::{info, warn};

#[cfg(debug_assertions)]
pub const UNIX_DOMAIN_SOCKET_FILE: &str = "/tmp/actix-uds.socket";
#[cfg(not(debug_assertions))]
pub const BUILD_TYPE: &str = "socket/actix-uds.socket";

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
    "received reload cert request!"
}