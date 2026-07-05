use serde::Serialize;

/// Exit codes for the slip CLI.
///
/// Every command MUST exit with one of these codes.
/// The `--json` flag changes output format but NOT the exit code.
pub const OK: i32 = 0;
pub const GENERIC: i32 = 1;
pub const USAGE: i32 = 2;
pub const AUTH: i32 = 3;
pub const NOT_FOUND: i32 = 4;
pub const DEPLOY_FAILED: i32 = 5;
pub const TIMEOUT: i32 = 6;

/// JSON output for unimplemented commands (Phase 2 stubs).
#[derive(Debug, Serialize)]
pub struct NotImplemented {
    pub status: String,
    pub command: String,
}

/// Print a prescriptive error to stderr and exit with the given code.
///
/// # Example
///
/// ```ignore
/// output::fail(output::NOT_FOUND, "app 'poi' not found", "run `slip apply` to register it");
/// ```
pub fn fail(code: i32, message: &str, remedy: &str) -> ! {
    eprintln!("error: {message}");
    eprintln!("  → {remedy}");
    std::process::exit(code);
}

/// Print a "not yet implemented" message and exit non-zero.
///
/// When `--json` is active, emits a JSON object on stdout instead of
/// the human-readable message on stderr.  Either way the process exits
/// with [`GENERIC`].
pub fn not_implemented(command: &str, json: bool) -> ! {
    if json {
        let msg = NotImplemented {
            status: "not_implemented".into(),
            command: command.into(),
        };
        println!("{}", serde_json::to_string(&msg).unwrap());
    } else {
        eprintln!("error: `slip {command}` is not yet implemented (Phase 2)");
    }
    std::process::exit(GENERIC);
}
