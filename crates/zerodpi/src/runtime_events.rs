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
}
