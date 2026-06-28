# Repository Guidelines

## What ZeroDPI Does

ZeroDPI is a cross-platform DPI bypass proxy for upstream VPN clients. It listens locally, scans candidate SNI hostnames or relay IPs, selects a working target, then relays VPN traffic while applying bypass methods such as wrong TCP sequence, wrong checksum, TLS record fragmentation, or TCP segmentation. Linux/Android interception uses NFQUEUE; Windows uses WinDivert.

## Project Structure & Module Organization

ZeroDPI is a Rust 2021 workspace. Source lives under `crates/`:

- `crates/zerodpi-core/`: platform-independent logic, configuration, TLS templates, flow tracking, scanners, proxy testing, and bypass methods.
- `crates/zerodpi-platform/`: packet interception backends, including Linux/Android NFQUEUE and Windows WinDivert.
- `crates/zerodpi/`: CLI entry point, runtime wiring, and ratatui TUI.

Runtime files include `config.toml`, `sni_list.txt`, and `ip_list.txt`. Windows assets live in `windivert/`; generated output belongs in `target/` or `dist/`.

## Build, Test, and Development Commands

- `cargo fmt --all -- --check`: verify Rust formatting.
- `cargo clippy --workspace --all-targets -- -D warnings`: run lint checks with warnings treated as errors.
- `cargo test --workspace`: run unit tests across all crates.
- `cargo build --workspace --release`: build optimized binaries.
- `cargo run --bin zerodpi -- --config ./config.toml`: run locally with the repository config.
- `python build.py --platform windows|linux|termux`: use the packaging and cross-build helper.

Linux builds require `libnetfilter-queue-dev`. Windows GNU builds require MSYS2, `stable-x86_64-pc-windows-gnu`, and the repo-local `windivert/` files. Android SDK is located at `~/Android/Sdk/`.

## Coding Style & Naming Conventions

Use `rustfmt` formatting and 4-space indentation. Keep modules and files in `snake_case`; use `PascalCase` for types and traits, `snake_case` for functions and variables, and `SCREAMING_SNAKE_CASE` only for constants or config fields. Prefer `anyhow` at application boundaries and `thiserror` inside reusable crates.

## Testing Guidelines

Tests are primarily inline `#[cfg(test)]` modules beside the code they cover. Name tests by behavior, for example `parses_ipv4_cidr` or `rejects_invalid_timeout`. Add focused tests for config parsing, packet-building logic, scanners, and bypass methods.

## Commit & Pull Request Guidelines

Recent commits use concise conventional prefixes such as `feat:`, `bugfix:`, and `refactor:`. Keep subjects imperative and scoped, for example `feat: add tls record fragment option`.

Pull requests should describe the behavioral change, list test commands run, link related issues, and include screenshots or terminal output for TUI, CLI, or packaging changes. Call out platform impact for Linux NFQUEUE, Windows WinDivert, and Termux builds.

## Security & Configuration Tips

Do not commit private proxy endpoints, production SNI lists, credentials, or machine-specific paths. Document new `config.toml` options in `README.md`.
