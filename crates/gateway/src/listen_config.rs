//! Listener configuration. Local verification explicitly uses 127.0.0.1.
use std::net::{IpAddr, SocketAddr};

pub fn parse(bind: Option<&str>, port: Option<&str>) -> Result<SocketAddr, &'static str> {
    let ip: IpAddr = bind
        .unwrap_or("0.0.0.0")
        .parse()
        .map_err(|_| "GATEWAY_BIND_ADDRESS must be an IPv4 or IPv6 address")?;
    let port: u16 = port
        .unwrap_or("8080")
        .parse()
        .map_err(|_| "PORT must be an integer between 0 and 65535")?;
    Ok(SocketAddr::new(ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_listener_is_explicitly_loopback() {
        let addr = parse(Some("127.0.0.1"), Some("18080")).unwrap();
        assert!(addr.ip().is_loopback());
        assert_eq!(addr.port(), 18080);
        assert!(parse(Some("::1"), Some("0")).unwrap().ip().is_loopback());
    }

    #[test]
    fn invalid_configuration_never_falls_back_to_a_public_listener() {
        for ip in ["", "localhost", "127.0.0.1:18080", "256.0.0.1"] {
            assert!(parse(Some(ip), Some("18080")).is_err());
        }
        for port in ["", "no", "-1", "65536"] {
            assert!(parse(Some("127.0.0.1"), Some(port)).is_err());
        }
    }

    #[test]
    fn existing_deployment_default_is_preserved() {
        assert_eq!(parse(None, None).unwrap().to_string(), "0.0.0.0:8080");
    }
}
