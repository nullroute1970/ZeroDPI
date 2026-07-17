#[cfg(any(target_os = "linux", target_os = "android"))]
mod unix;

#[cfg(any(target_os = "linux", target_os = "android"))]
fn main() -> anyhow::Result<()> {
    unix::run()
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn main() {
    eprintln!("zerodpi-root-helper is only supported on Linux/Android");
    std::process::exit(2);
}
