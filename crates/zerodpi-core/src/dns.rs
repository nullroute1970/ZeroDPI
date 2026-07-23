//! DNS resolution used by SNI scanning and fixed-SNI startup.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use hickory_resolver::config::{
    LookupIpStrategy, NameServerConfigGroup, ResolverConfig, ResolverOpts,
};
use hickory_resolver::TokioAsyncResolver;

use crate::config::Config;

const DEFAULT_DNS_PORT: u16 = 53;

/// Resolver selected from the application configuration.
#[derive(Clone)]
pub enum DnsResolver {
    /// Delegate hostname resolution to the operating system.
    System,
    /// Send plain DNS queries only to the configured name server.
    Custom(Arc<TokioAsyncResolver>),
}

impl DnsResolver {
    /// Build a resolver from `config`.
    ///
    /// Custom mode deliberately excludes system resolver configuration and
    /// the hosts file, so a custom lookup cannot silently fall back.
    pub fn from_config(config: &Config, timeout: Duration) -> Result<Self> {
        if !config.CUSTOM_DNS_ENABLED {
            return Ok(Self::System);
        }

        let value = config
            .CUSTOM_DNS_SERVER
            .as_deref()
            .context("CUSTOM_DNS_SERVER is required when CUSTOM_DNS_ENABLED is true")?;
        let server = parse_custom_dns_server(value)?;
        let name_servers =
            NameServerConfigGroup::from_ips_clear(&[server.ip()], server.port(), true);
        let resolver_config = ResolverConfig::from_parts(None, Vec::new(), name_servers);
        let mut options = ResolverOpts::default();
        options.timeout = timeout;
        options.ip_strategy = LookupIpStrategy::Ipv4Only;
        options.use_hosts_file = false;

        Ok(Self::Custom(Arc::new(TokioAsyncResolver::tokio(
            resolver_config,
            options,
        ))))
    }

    /// Resolve a hostname to IPv4 addresses.
    pub async fn lookup_ipv4(&self, hostname: &str) -> Result<Vec<Ipv4Addr>> {
        match self {
            Self::System => {
                let addrs = tokio::net::lookup_host((hostname, 0))
                    .await
                    .with_context(|| format!("system DNS lookup for {hostname}"))?;
                Ok(addrs
                    .filter_map(|addr| match addr.ip() {
                        IpAddr::V4(ip) => Some(ip),
                        IpAddr::V6(_) => None,
                    })
                    .collect())
            }
            Self::Custom(resolver) => {
                let response = resolver
                    .lookup_ip(hostname)
                    .await
                    .with_context(|| format!("custom DNS lookup for {hostname}"))?;
                Ok(response
                    .iter()
                    .filter_map(|ip| match ip {
                        IpAddr::V4(ip) => Some(ip),
                        IpAddr::V6(_) => None,
                    })
                    .collect())
            }
        }
    }
}

/// Parse a custom DNS endpoint.
///
/// Literal IPv4 and IPv6 addresses use port 53. An explicit port is accepted
/// as `IPv4:port` or `[IPv6]:port`.
pub fn parse_custom_dns_server(value: &str) -> Result<SocketAddr> {
    let value = value.trim();
    if value.is_empty() {
        anyhow::bail!("CUSTOM_DNS_SERVER must not be empty");
    }

    if let Ok(addr) = value.parse::<SocketAddr>() {
        if addr.port() == 0 {
            anyhow::bail!("CUSTOM_DNS_SERVER port must be greater than 0");
        }
        return Ok(addr);
    }

    if let Ok(ip) = value.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, DEFAULT_DNS_PORT));
    }

    anyhow::bail!("CUSTOM_DNS_SERVER '{value}' must be a literal IP address with an optional port")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};

    #[test]
    fn parses_ipv4_with_default_port() {
        assert_eq!(
            parse_custom_dns_server("1.1.1.1").unwrap(),
            "1.1.1.1:53".parse().unwrap()
        );
    }

    #[test]
    fn parses_ipv4_with_custom_port() {
        assert_eq!(
            parse_custom_dns_server("1.1.1.1:5353").unwrap(),
            "1.1.1.1:5353".parse().unwrap()
        );
    }

    #[test]
    fn parses_ipv6_with_default_and_custom_ports() {
        assert_eq!(
            parse_custom_dns_server("2606:4700:4700::1111").unwrap(),
            "[2606:4700:4700::1111]:53".parse().unwrap()
        );
        assert_eq!(
            parse_custom_dns_server("[2606:4700:4700::1111]:5353").unwrap(),
            "[2606:4700:4700::1111]:5353".parse().unwrap()
        );
    }

    #[test]
    fn rejects_hostnames_empty_values_and_zero_ports() {
        assert!(parse_custom_dns_server("").is_err());
        assert!(parse_custom_dns_server("dns.example.com").is_err());
        assert!(parse_custom_dns_server("1.1.1.1:0").is_err());
    }

    #[tokio::test]
    async fn custom_resolver_uses_configured_server() {
        let (server, server_task) = mock_dns_server(Some(Ipv4Addr::new(203, 0, 113, 7))).await;
        let config: Config = toml::from_str(&format!(
            r#"
            LISTEN_HOST = "127.0.0.1"
            LISTEN_PORT = 44444
            CUSTOM_DNS_ENABLED = true
            CUSTOM_DNS_SERVER = "{server}"
            "#
        ))
        .unwrap();
        let resolver = DnsResolver::from_config(&config, Duration::from_secs(1)).unwrap();

        let result = resolver.lookup_ipv4("custom.test").await.unwrap();

        assert_eq!(result, vec![Ipv4Addr::new(203, 0, 113, 7)]);
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn custom_resolver_does_not_fall_back_to_system_dns() {
        let (server, server_task) = mock_dns_server(None).await;
        let config: Config = toml::from_str(&format!(
            r#"
            LISTEN_HOST = "127.0.0.1"
            LISTEN_PORT = 44444
            CUSTOM_DNS_ENABLED = true
            CUSTOM_DNS_SERVER = "{server}"
            "#
        ))
        .unwrap();
        let resolver = DnsResolver::from_config(&config, Duration::from_secs(1)).unwrap();

        let result = resolver
            .lookup_ipv4("example.com")
            .await
            .unwrap_or_default();
        assert!(
            result.is_empty(),
            "custom resolver unexpectedly returned system result: {result:?}"
        );
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn custom_resolver_retries_truncated_udp_response_over_tcp() {
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = udp.local_addr().unwrap();
        let tcp = TcpListener::bind(addr).await.unwrap();
        let server_task = tokio::spawn(async move {
            let mut udp_request = [0u8; 512];
            let (request_len, peer) = udp.recv_from(&mut udp_request).await.unwrap();
            let truncated = dns_truncated_response(&udp_request[..request_len]);
            udp.send_to(&truncated, peer).await.unwrap();

            let (mut stream, _) = tcp.accept().await.unwrap();
            let request_len = stream.read_u16().await.unwrap() as usize;
            let mut tcp_request = vec![0u8; request_len];
            stream.read_exact(&mut tcp_request).await.unwrap();
            let response = dns_response(&tcp_request, Some(Ipv4Addr::new(198, 51, 100, 11)));
            stream.write_u16(response.len() as u16).await.unwrap();
            stream.write_all(&response).await.unwrap();
        });
        let config: Config = toml::from_str(&format!(
            r#"
            LISTEN_HOST = "127.0.0.1"
            LISTEN_PORT = 44444
            CUSTOM_DNS_ENABLED = true
            CUSTOM_DNS_SERVER = "{addr}"
            "#
        ))
        .unwrap();
        let resolver = DnsResolver::from_config(&config, Duration::from_secs(1)).unwrap();

        let result = resolver.lookup_ipv4("truncated.test").await.unwrap();

        assert_eq!(result, vec![Ipv4Addr::new(198, 51, 100, 11)]);
        server_task.await.unwrap();
    }

    async fn mock_dns_server(
        answer: Option<Ipv4Addr>,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = socket.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut request = [0u8; 512];
            let (request_len, peer) = socket.recv_from(&mut request).await.unwrap();
            let response = dns_response(&request[..request_len], answer);
            socket.send_to(&response, peer).await.unwrap();
        });
        (addr, task)
    }

    fn dns_response(request: &[u8], answer: Option<Ipv4Addr>) -> Vec<u8> {
        assert!(request.len() >= 12);
        let mut question_end = 12;
        while request[question_end] != 0 {
            question_end += request[question_end] as usize + 1;
        }
        question_end += 5;

        let mut response = Vec::with_capacity(question_end + 16);
        response.extend_from_slice(&request[0..2]);
        response.extend_from_slice(if answer.is_some() {
            &[0x81, 0x80]
        } else {
            &[0x81, 0x83]
        });
        response.extend_from_slice(&[0x00, 0x01]);
        response.extend_from_slice(if answer.is_some() {
            &[0x00, 0x01]
        } else {
            &[0x00, 0x00]
        });
        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        response.extend_from_slice(&request[12..question_end]);

        if let Some(ip) = answer {
            response.extend_from_slice(&[
                0xc0, 0x0c, // compressed owner name
                0x00, 0x01, // A
                0x00, 0x01, // IN
                0x00, 0x00, 0x00, 0x3c, // 60-second TTL
                0x00, 0x04,
            ]);
            response.extend_from_slice(&ip.octets());
        }
        response
    }

    fn dns_truncated_response(request: &[u8]) -> Vec<u8> {
        assert!(request.len() >= 12);
        let mut response = Vec::with_capacity(12);
        response.extend_from_slice(&request[0..2]);
        response.extend_from_slice(&[0x83, 0x80]);
        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        response
    }
}
