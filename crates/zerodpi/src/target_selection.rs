//! Target-specific TTL admission without changing the interceptor's shared TTL.
use std::future::Future;
use zerodpi_core::target_pool::Target;

pub async fn discover_pool_ttls<F, Fut>(
    candidates: Vec<Target>,
    previous: &[Target],
    startup_fallback: Option<u8>,
    mut discover: F,
) -> Vec<Target>
where
    F: FnMut(Target) -> Fut,
    Fut: Future<Output = Option<u8>>,
{
    let mut admitted = Vec::new();
    for mut target in candidates {
        if let Some(ttl) = discover(target.clone()).await {
            target.low_ttl = Some(ttl);
        } else if let Some(old) = previous
            .iter()
            .find(|old| old.ip == target.ip && old.sni == target.sni)
        {
            target.low_ttl = old.low_ttl;
        } else if let Some(ttl) = startup_fallback {
            target.low_ttl = Some(ttl);
        } else {
            continue;
        }
        admitted.push(target);
    }
    admitted
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn startup_uses_configured_fallback_when_discovery_fails() {
        let target = Target::sni("first.example", Ipv4Addr::new(192, 0, 2, 1), 90);
        let targets = discover_pool_ttls(vec![target], &[], Some(5), |_| async { None }).await;
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].low_ttl, Some(5));
    }

    #[tokio::test]
    async fn rescan_retains_prior_ttl_but_requires_success_for_new_targets() {
        let mut old = Target::sni("old.example", Ipv4Addr::new(192, 0, 2, 1), 90);
        old.low_ttl = Some(5);
        let failing = Target::sni("failed.example", Ipv4Addr::new(192, 0, 2, 2), 80);
        let working = Target::sni("working.example", Ipv4Addr::new(192, 0, 2, 3), 70);
        let admitted = discover_pool_ttls(
            vec![old.clone(), failing, working],
            &[old.clone()],
            None,
            |target| async move { (target.sni.as_deref() == Some("working.example")).then_some(9) },
        )
        .await;
        assert_eq!(admitted.len(), 2);
        assert_eq!(admitted[0].sni.as_deref(), Some("old.example"));
        assert_eq!(admitted[0].low_ttl, Some(5));
        assert_eq!(admitted[1].sni.as_deref(), Some("working.example"));
        assert_eq!(admitted[1].low_ttl, Some(9));
        assert_eq!(old.low_ttl, Some(5));
    }
}
