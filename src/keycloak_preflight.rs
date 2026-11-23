//! Host-only KC110 diagnostic entry point; never linked into authority providers.
use std::path::Path;
use std::process::{Command, Stdio};

pub fn command(args: &[String]) -> i32 {
    let helper = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("scripts/keycloak/preflight.py");
    if !helper.is_file() {
        eprintln!("Keycloak preflight helper is missing from the build checkout.");
        return 2;
    }
    // No shell, credential strings, or guest-controlled helper selection.
    // The Python supervisor bounds its worker and OpenSSL subprocess group.
    match Command::new("python3")
        .arg("-I")
        .arg(helper)
        .args(args)
        .stdin(Stdio::null())
        .status()
    {
        Ok(status) => status.code().unwrap_or(2),
        Err(_) => {
            eprintln!("Cannot start Keycloak preflight; Python 3.9+ is required.");
            2
        }
    }
}
