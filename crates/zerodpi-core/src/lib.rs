//! ZeroDPI core: platform-independent logic.
//!
//! - [`config`]: load/validate `config.toml`.
//! - [`dns`]: system and custom DNS resolution for SNI hostnames.
//! - [`tls_template`]: byte-exact port of upstream's `ClientHelloMaker`.
//! - [`flow`]: flow keys, per-connection state, the shared flow table.
//! - [`interceptor`]: traits that platform packet-interception backends implement.
//! - [`methods`]: pluggable bypass methods.
//! - [`net`]: small networking helpers (default-interface IP discovery).
//! - [`proxy`]: tokio TCP listener + bidirectional relay driving the bypass.
//! - [`sni_scanner`]: DNS/TCP/TLS/HTTP probe + ranking for SNI candidates.
//! - [`ip_scanner`]: 3-phase IP scanner (TCP→TLS→TTFB) used in `ip_bypass` mode.

pub mod config;
pub mod dns;
pub mod flow;
pub mod handler;
pub mod interceptor;
pub mod ip_fragment;
pub mod ip_scanner;
pub mod low_ttl_discover;
pub mod methods;
pub mod net;
pub mod proxy;
pub mod proxy_tester;
mod scanner_http;
pub mod sni_scanner;
pub mod tcp_segment;
pub mod tls_template;
