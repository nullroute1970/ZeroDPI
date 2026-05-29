//! Flow-tracking types shared between the proxy task and the packet-intercept
//! backend. The flow table maps a 4-tuple to per-connection state and a
//! signal channel used to wake the proxy task when the bypass is complete.

use std::net::Ipv4Addr;
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
    /// Final outcome, set when [`Self::notify`] fires.
    pub outcome: Option<BypassOutcome>,
    /// Spoofed TLS ClientHello payload to inject. Built once per flow.
    pub fake_data: Vec<u8>,
}

impl FlowState {
    pub fn new(fake_data: Vec<u8>) -> Self {
        Self {
            monitor: true,
            syn_seq: None,
            syn_ack_seq: None,
            fake_sent: false,
            waiting_for_data: false,
            first_data_modified: false,
            outcome: None,
            fake_data,
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
    pub fn new(fake_data: Vec<u8>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(FlowState::new(fake_data)),
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
}

/// Concurrent map keyed on the *outbound-direction* [`FlowKey`].
pub type FlowTable = Arc<DashMap<FlowKey, Arc<FlowEntry>>>;

pub fn new_flow_table() -> FlowTable {
    Arc::new(DashMap::new())
}
