use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use serde::Serialize;

pub const CONTRACT_VERSION: u8 = 1;

#[derive(Clone, Debug, Default)]
pub struct RuntimeEventEmitter {
    writer: Option<Arc<Mutex<io::Stdout>>>,
}

impl RuntimeEventEmitter {
    pub fn new(enabled: bool) -> Self {
        if enabled {
            Self {
                writer: Some(Arc::new(Mutex::new(io::stdout()))),
            }
        } else {
            Self::default()
        }
    }

    pub fn enabled(&self) -> bool {
        self.writer.is_some()
    }

    pub fn emit(&self, event: RuntimeEvent) {
        let Some(writer) = &self.writer else {
            return;
        };
        let Ok(mut writer) = writer.lock() else {
            return;
        };

        if serde_json::to_writer(&mut *writer, &event).is_ok() {
            let _ = writer.write_all(b"\n");
            let _ = writer.flush();
        }
    }
}

// The four network_* variants are constructed by MainRecoveryEnv in Task 12.
// Remove this allow when that wiring lands.
#[allow(dead_code)]
#[derive(Debug, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum RuntimeEvent {
    Startup {
        contract_version: u8,
        version: String,
        pid: u32,
        uid: u32,
    },
    HelperAuthenticated {
        pid: u32,
        uid: u32,
        protocol_major: u16,
        protocol_minor: u16,
        capabilities: Vec<String>,
    },
    ConfigLoaded {
        path: String,
        mode: String,
        bypass_method: String,
        listen_host: String,
        listen_port: u16,
        auto_select: bool,
        no_tui: bool,
        root_required: bool,
    },
    ScanStarted {
        scan: ScanKind,
        path: Option<String>,
        total: Option<usize>,
    },
    ScanProgress {
        scan: ScanKind,
        phase: Option<String>,
        completed: usize,
        total: Option<usize>,
        sni: Option<String>,
        ip: Option<String>,
        score: Option<u8>,
    },
    ScanCompleted {
        scan: ScanKind,
        results: usize,
    },
    NextScanScheduled {
        scan: ScanKind,
        interval_secs: u64,
    },
    RescanStarted {
        scan: ScanKind,
    },
    RescanFinished {
        scan: ScanKind,
        found: usize,
        best_score: Option<u8>,
        duration_ms: u64,
        switched: bool,
    },
    SelectedTarget {
        target: TargetKind,
        sni: Option<String>,
        ip: String,
        score: Option<u8>,
    },
    ListenerStarted {
        mode: String,
        listen_addr: String,
    },
    ConnectionAccepted {
        peer: String,
        src_port: u16,
    },
    BypassFinished {
        src_port: u16,
        status: BypassStatus,
    },
    RelayBytes {
        src_port: u16,
        c2s_bytes: u64,
        s2c_bytes: u64,
        #[serde(rename = "final")]
        is_final: bool,
    },
    ActiveTargetChanged {
        target: TargetKind,
        sni: Option<String>,
        ip: String,
        score: Option<u8>,
    },
    RootRequired {
        mode: String,
        bypass_method: String,
        message: String,
        rootless_alternatives: Vec<String>,
    },
    NetworkUnavailable {
        message: String,
    },
    NetworkChanged {
        source: zerodpi_core::net::NetworkChangeSource,
        interface_ip: String,
    },
    NetworkRecoveryFailed {
        attempt: u32,
        next_retry_ms: u64,
        message: String,
    },
    NetworkRecovered {
        interface_ip: String,
        target_verified: bool,
        target_switched: bool,
    },
    FatalError {
        message: String,
    },
    GracefulShutdown {
        reason: String,
    },
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanKind {
    Sni,
    Ip,
    Proxy,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    Sni,
    Ip,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BypassStatus {
    Completed,
    Failed,
}

#[cfg(test)]
mod tests {
    use super::{RuntimeEvent, ScanKind};

    #[test]
    fn serializes_next_scan_schedule() {
        let json = serde_json::to_string(&RuntimeEvent::NextScanScheduled {
            scan: ScanKind::Sni,
            interval_secs: 300,
        })
        .unwrap();

        assert_eq!(
            json,
            r#"{"event":"next_scan_scheduled","scan":"sni","interval_secs":300}"#,
        );
    }

    #[test]
    fn serializes_rescan_started() {
        let json = serde_json::to_string(&RuntimeEvent::RescanStarted {
            scan: ScanKind::Sni,
        })
        .unwrap();

        assert_eq!(json, r#"{"event":"rescan_started","scan":"sni"}"#);
    }

    #[test]
    fn serializes_rescan_finished_summary() {
        let json = serde_json::to_string(&RuntimeEvent::RescanFinished {
            scan: ScanKind::Ip,
            found: 4,
            best_score: Some(91),
            duration_ms: 2_300,
            switched: true,
        })
        .unwrap();

        assert_eq!(
            json,
            r#"{"event":"rescan_finished","scan":"ip","found":4,"best_score":91,"duration_ms":2300,"switched":true}"#,
        );
    }

    #[test]
    fn serializes_network_unavailable() {
        let json = serde_json::to_string(&RuntimeEvent::NetworkUnavailable {
            message: "no route".to_owned(),
        })
        .unwrap();
        assert_eq!(
            json,
            r#"{"event":"network_unavailable","message":"no route"}"#
        );
    }

    #[test]
    fn serializes_network_changed() {
        let json = serde_json::to_string(&RuntimeEvent::NetworkChanged {
            source: zerodpi_core::net::NetworkChangeSource::Address,
            interface_ip: "192.0.2.10".to_owned(),
        })
        .unwrap();
        assert_eq!(
            json,
            r#"{"event":"network_changed","source":"address","interface_ip":"192.0.2.10"}"#
        );
    }

    #[test]
    fn serializes_network_recovery_failed() {
        let json = serde_json::to_string(&RuntimeEvent::NetworkRecoveryFailed {
            attempt: 2,
            next_retry_ms: 4_000,
            message: "open packet interceptor".to_owned(),
        })
        .unwrap();
        assert_eq!(
            json,
            r#"{"event":"network_recovery_failed","attempt":2,"next_retry_ms":4000,"message":"open packet interceptor"}"#
        );
    }

    #[test]
    fn serializes_network_recovered() {
        let json = serde_json::to_string(&RuntimeEvent::NetworkRecovered {
            interface_ip: "192.0.2.10".to_owned(),
            target_verified: true,
            target_switched: false,
        })
        .unwrap();
        assert_eq!(
            json,
            r#"{"event":"network_recovered","interface_ip":"192.0.2.10","target_verified":true,"target_switched":false}"#
        );
    }
}
