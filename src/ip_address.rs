use actix_web::{dev::ServiceRequest, HttpRequest};

const UNKNOWN_PEER_IP: &str = "unknown peer";

pub trait IpAdressString {
    /// Resturns an IP address as string because that works
    /// universal with IPv4 and IPv6.
    fn get_peer_ip_address(&self) -> String;
}

impl IpAdressString for HttpRequest {
    /// Gets the ip address that comes with the `HttpRequest`.
    #[inline(always)]
    fn get_peer_ip_address(&self) -> String {
        match self.peer_addr() {
            None => UNKNOWN_PEER_IP.to_string(),
            Some(s) => s.ip().to_string(),
        }
    }
}

impl IpAdressString for ServiceRequest {
    /// Gets the ip address that comes with the `ServiceRequest`.
    #[inline(always)]
    fn get_peer_ip_address(&self) -> String {
        match self.peer_addr() {
            None => UNKNOWN_PEER_IP.to_string(),
            Some(s) => s.ip().to_string(),
        }
    }
}
