use actix_web::HttpRequest;

pub const UNKNOWN_PEER_IP: &str = "unknown peer";

/// Gets the ip address that comes with the `HttpRequest`.
///
/// It is returned as string because that works universal
/// with IPv4 and IPv6.
#[inline(always)]
pub fn get_peer_ip_address(request: &HttpRequest) -> String {
    match request.peer_addr() {
        None => UNKNOWN_PEER_IP.to_string(),
        Some(s) => s.ip().to_string(),
    }
}
