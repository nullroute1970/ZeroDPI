//! Flow-tracking types shared between the proxy task and the packet-intercept
//! backend. The flow table maps a 4-tuple to per-connection state and a
//! signal channel used to wake the proxy task when the bypass is complete.

use std::future::Future;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::Arc;

use dashmap::DashMap;
use parking_lot::Mutex;
use tokio::sync::Notify;

/// `(src_ip, src_port, dst_ip, dst_port)` identifying a single TCP flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
}

impl FlowKey {
    /// The reverse-direction key (source ↔ destination swapped).
    pub fn reversed(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            src_port: self.dst_port,
            dst_ip: self.src_ip,
            dst_port: self.src_port,
        }
    }
}

/// Outcome reported by the intercept thread back to the proxy task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BypassOutcome {
    /// Fake-data ACK observed; bypass complete.
    FakeDataAcked,
    /// Some unexpected packet caused us to abort the flow.
    UnexpectedClose,
}

/// Per-flow state mutated from the intercept thread; the proxy task only
/// reads it after `notify` has been signalled.
#[derive(Debug)]
pub struct FlowState {
    /// True while the intercept thread should track this flow. The proxy task
    /// flips this to `false` to release the flow.
    pub monitor: bool,
    /// Sequence number observed in the client's SYN (set on the first
    /// outbound SYN). `None` until seen.
    pub syn_seq: Option<u32>,
    /// Sequence number observed in the server's SYN-ACK. `None` until seen.
    pub syn_ack_seq: Option<u32>,
    /// True once we've replaced the first outbound bare ACK with a fake
    /// ClientHello.
    pub fake_sent: bool,
    /// True when the active bypass method returned `PassThrough` on the
    /// handshake-complete ACK, or requested a second stage after fake
    /// injection, and is waiting to intercept the first outbound data packet.
    pub waiting_for_data: bool,
    /// True once the first outbound data packet has been modified by a
    /// first-data-stage method.
    pub first_data_modified: bool,
    /// True while a data-stage method emitted a modified first data packet
    /// with `complete_immediately = false` and we are waiting for the
    /// server's ACK of that packet's payload before finishing the flow.
    pub waiting_for_first_data_ack: bool,
    /// True when a data-stage method (currently `ip_frag` with
    /// `IP_FRAG_ONLY_FIRST_PACKET = false`) requested fragment-all mode: the
    /// bypass outcome was already signalled but the flow stays monitored and
    /// every subsequent outbound data packet is re-staged.
    pub fragment_all_data: bool,
    /// Final outcome, set when [`Self::notify`] fires.
    pub outcome: Option<BypassOutcome>,
    /// Spoofed TLS ClientHello payload to inject. Built once per flow.
    pub fake_data: Vec<u8>,
    /// Per-flow `low_ttl` stamp override carried by `LOW_TTL_DISCOVER` probe
    /// flows. `None` for user flows: they use the shared live handle. The
    /// `low_ttl` method prefers this value over the handle at emission time,
    /// so discovery probes never mutate the live handle.
    pub low_ttl_override: Option<u8>,
}

impl FlowState {
    pub fn new(fake_data: Vec<u8>, low_ttl_override: Option<u8>) -> Self {
        Self {
            monitor: true,
            syn_seq: None,
            syn_ack_seq: None,
            fake_sent: false,
            waiting_for_data: false,
            first_data_modified: false,
            waiting_for_first_data_ack: false,
            fragment_all_data: false,
            outcome: None,
            fake_data,
            low_ttl_override,
        }
    }
}

/// Shared, per-flow record stored in the flow table.
#[derive(Debug)]
pub struct FlowEntry {
    pub state: Mutex<FlowState>,
    pub ready_for_data: Notify,
    pub notify: Notify,
}

impl FlowEntry {
    pub fn new(fake_data: Vec<u8>, low_ttl_override: Option<u8>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(FlowState::new(fake_data, low_ttl_override)),
            ready_for_data: Notify::new(),
            notify: Notify::new(),
        })
    }

    /// Mark the flow finished with the given outcome and wake any waiter.
    /// Idempotent: only the first call sets `outcome` and notifies.
    pub fn finish(&self, outcome: BypassOutcome) {
        let mut s = self.state.lock();
        if s.outcome.is_none() {
            s.outcome = Some(outcome);
            s.monitor = false;
            self.notify.notify_waiters();
        }
    }

    /// Mark the bypass phase complete with the given outcome and wake any
    /// waiter, without stopping flow monitoring. Used by fragment-all data-
    /// stage methods that keep rewriting packets after the initial
    /// ClientHello. Idempotent on `outcome`: only the first call sets it and
    /// notifies.
    pub fn signal_outcome(&self, outcome: BypassOutcome) {
        let mut s = self.state.lock();
        if s.outcome.is_none() {
            s.outcome = Some(outcome);
            self.notify.notify_waiters();
        }
    }
}

/// Concurrent map keyed on the *outbound-direction* [`FlowKey`].
pub type FlowTable = Arc<DashMap<FlowKey, Arc<FlowEntry>>>;

pub fn new_flow_table() -> FlowTable {
    Arc::new(DashMap::new())
}

/// Future returned while a flow controller makes a flow visible to the
/// packet handler. Remote implementations complete this only after the helper
/// acknowledges registration, preserving register-before-connect ordering.
pub type FlowRegistrationFuture<'a> =
    Pin<Box<dyn Future<Output = anyhow::Result<Arc<FlowEntry>>> + Send + 'a>>;

/// Data-plane view of flow registration. Desktop builds use
/// [`LocalFlowController`]; Android privilege separation supplies a remote
/// implementation backed by the root-helper protocol.
pub trait FlowController: Send + Sync {
    /// Register a flow with the packet handler. `low_ttl_override` is the
    /// per-flow `low_ttl` stamp used by `LOW_TTL_DISCOVER` probe flows so
    /// probing never mutates the shared live handle; pass `None` for user
    /// flows (they use the live handle).
    fn register_flow(
        &self,
        key: FlowKey,
        fake_data: Vec<u8>,
        low_ttl_override: Option<u8>,
    ) -> FlowRegistrationFuture<'_>;

    /// Whether a flow with this key is already registered (live user flow or
    /// another probe). Used by discovery to avoid clobbering an existing
    /// flow locally and to avoid the helper's duplicate-flow-key rejection
    /// remotely.
    fn flow_exists(&self, key: FlowKey) -> bool;

    /// Idempotently release a flow. Implementations must make this safe to
    /// call from a cancellation/drop guard.
    fn remove_flow(&self, key: FlowKey);
}

#[derive(Debug, Clone)]
pub struct LocalFlowController {
    flows: FlowTable,
}

impl LocalFlowController {
    pub fn new(flows: FlowTable) -> Self {
        Self { flows }
    }

    pub fn flows(&self) -> FlowTable {
        self.flows.clone()
    }
}

impl FlowController for LocalFlowController {
    fn register_flow(
        &self,
        key: FlowKey,
        fake_data: Vec<u8>,
        low_ttl_override: Option<u8>,
    ) -> FlowRegistrationFuture<'_> {
        Box::pin(async move {
            let entry = FlowEntry::new(fake_data, low_ttl_override);
            self.flows.insert(key, entry.clone());
            Ok(entry)
        })
    }

    fn flow_exists(&self, key: FlowKey) -> bool {
        self.flows.contains_key(&key)
    }

    fn remove_flow(&self, key: FlowKey) {
        self.flows.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_entry_carries_low_ttl_override() {
        let with_override = FlowEntry::new(vec![1], Some(7));
        assert_eq!(with_override.state.lock().low_ttl_override, Some(7));
        let without_override = FlowEntry::new(vec![1], None);
        assert_eq!(without_override.state.lock().low_ttl_override, None);
    }

    #[test]
    fn flow_state_fragment_all_data_defaults_false() {
        let entry = FlowEntry::new(vec![1], None);
        assert!(!entry.state.lock().fragment_all_data);
    }

    #[test]
    fn signal_outcome_sets_outcome_without_stopping_monitoring() {
        let entry = FlowEntry::new(vec![1], None);
        entry.signal_outcome(BypassOutcome::FakeDataAcked);
        {
            let s = entry.state.lock();
            assert_eq!(s.outcome, Some(BypassOutcome::FakeDataAcked));
            assert!(s.monitor);
        }
        // Idempotent: a second signal does not overwrite the first outcome.
        entry.signal_outcome(BypassOutcome::UnexpectedClose);
        assert_eq!(
            entry.state.lock().outcome,
            Some(BypassOutcome::FakeDataAcked)
        );
    }

    #[tokio::test]
    async fn local_flow_controller_tracks_registration_and_removal() {
        let controller = LocalFlowController::new(new_flow_table());
        let key = FlowKey {
            src_ip: Ipv4Addr::LOCALHOST,
            src_port: 1234,
            dst_ip: Ipv4Addr::new(1, 1, 1, 1),
            dst_port: 443,
        };
        assert!(!controller.flow_exists(key));
        let entry = controller
            .register_flow(key, vec![1], Some(5))
            .await
            .unwrap();
        assert!(controller.flow_exists(key));
        assert_eq!(entry.state.lock().low_ttl_override, Some(5));
        controller.remove_flow(key);
        assert!(!controller.flow_exists(key));
    }
}
