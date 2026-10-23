use super::test_support::TestDnsServer;
use super::*;

fn config(servers: &[SocketAddr]) -> Config {
    toml::from_str(&format!(
        "LISTEN_HOST = \"127.0.0.1\"\nLISTEN_PORT = 44444\nCUSTOM_DNS_ENABLED = true\nCUSTOM_DNS_SERVER = {:?}\nCUSTOM_DNS_SERVERS = {:?}",
        servers[0].to_string(),
        servers.iter().map(ToString::to_string).collect::<Vec<_>>()
    ))
    .unwrap()
}

#[tokio::test]
async fn first_success_does_not_contact_later_dns_servers() {
    let first = TestDnsServer::start(0, Some(Ipv4Addr::LOCALHOST), Some(Duration::ZERO)).await;
    let second = TestDnsServer::start(0, None, None).await;
    let resolver =
        DnsResolver::from_config(&config(&[first.addr, second.addr]), Duration::from_secs(1))
            .unwrap();
    assert_eq!(
        resolver.lookup_ipv4("first.test").await.unwrap(),
        vec![Ipv4Addr::LOCALHOST]
    );
    assert!(first.requests() > 0);
    assert_eq!(second.requests(), 0);
}

#[tokio::test]
async fn dns_errors_and_empty_answers_try_the_next_server() {
    for rcode in [0, 2, 3, 5] {
        let first = TestDnsServer::start(rcode, None, Some(Duration::ZERO)).await;
        let second =
            TestDnsServer::start(0, Some(Ipv4Addr::new(203, 0, 113, 7)), Some(Duration::ZERO))
                .await;
        let resolver = DnsResolver::from_config(
            &config(&[first.addr, second.addr]),
            Duration::from_millis(200),
        )
        .unwrap();
        assert_eq!(
            resolver.lookup_ipv4("fallback.test").await.unwrap(),
            vec![Ipv4Addr::new(203, 0, 113, 7)],
            "rcode {rcode}"
        );
        assert!(first.requests() > 0);
        assert!(second.requests() > 0);
    }
}

#[tokio::test]
async fn each_dns_gets_an_independent_timeout() {
    let first = TestDnsServer::start(0, None, None).await;
    let second = TestDnsServer::start(
        0,
        Some(Ipv4Addr::LOCALHOST),
        Some(Duration::from_millis(100)),
    )
    .await;
    let budget = Duration::from_millis(250);
    let resolver = DnsResolver::from_config(&config(&[first.addr, second.addr]), budget).unwrap();
    let start = tokio::time::Instant::now();
    let result = tokio::time::timeout(budget * 4, resolver.lookup_ipv4("timeout.test"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result, vec![Ipv4Addr::LOCALHOST]);
    assert!(start.elapsed() > budget);
    assert!(start.elapsed() < budget * 3);
}

#[tokio::test]
async fn fallback_skips_two_failures_and_restarts_from_first_for_each_hostname() {
    let first = TestDnsServer::start(3, None, Some(Duration::ZERO)).await;
    let second = TestDnsServer::start(5, None, Some(Duration::ZERO)).await;
    let third = TestDnsServer::start(0, Some(Ipv4Addr::LOCALHOST), Some(Duration::ZERO)).await;
    let resolver = DnsResolver::from_config(
        &config(&[first.addr, second.addr, third.addr]),
        Duration::from_millis(200),
    )
    .unwrap();
    for name in ["one.test", "two.test"] {
        let before = first.requests();
        assert_eq!(
            resolver.lookup_ipv4(name).await.unwrap(),
            vec![Ipv4Addr::LOCALHOST]
        );
        assert!(first.requests() > before);
    }
    assert!(second.requests() >= 2);
    assert!(third.requests() >= 2);
}

#[tokio::test]
async fn all_dns_failures_report_hostname_and_each_server_without_system_fallback() {
    let first = TestDnsServer::start(3, None, Some(Duration::ZERO)).await;
    let second = TestDnsServer::start(0, None, None).await;
    let resolver = DnsResolver::from_config(
        &config(&[first.addr, second.addr]),
        Duration::from_millis(100),
    )
    .unwrap();
    let error = resolver.lookup_ipv4("example.com").await.unwrap_err();
    let message = format!("{error:#}");
    assert!(message.contains("example.com"), "{message}");
    assert!(message.contains(&first.addr.to_string()), "{message}");
    assert!(message.contains(&second.addr.to_string()), "{message}");
    assert!(message.contains("timed out"), "{message}");
}
