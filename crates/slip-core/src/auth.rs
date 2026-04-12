//! HMAC-SHA256 signature verification for deploy webhooks.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Verify an HMAC-SHA256 signature.
///
/// `header` is the raw X-Slip-Signature value: "sha256=abcdef1234..."
/// `body` is the raw request body bytes.
/// `secret` is the HMAC key.
///
/// Returns true if valid.
pub fn verify_signature(header: &str, body: &[u8], secret: &str) -> bool {
    let hex_sig = match header.strip_prefix("sha256=") {
        Some(s) => s,
        None => return false,
    };

    let sig_bytes = match hex::decode(hex_sig) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(body);
    let computed = mac.finalize().into_bytes();

    computed.as_slice().ct_eq(&sig_bytes).into()
}

/// Compute an HMAC-SHA256 signature for a payload.
/// Returns the hex-encoded signature string (without "sha256=" prefix).
pub fn compute_signature(body: &[u8], secret: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(body);
    let result = mac.finalize().into_bytes();
    hex::encode(result)
}

/// Resolve the HMAC secret for a given app.
/// Uses per-app secret if set, otherwise falls back to global secret.
pub fn resolve_secret<'a>(app_secret: Option<&'a str>, global_secret: &'a str) -> &'a str {
    app_secret.unwrap_or(global_secret)
}

/// Constant-time comparison of two byte slices.
///
/// Uses the `subtle` crate to prevent timing attacks.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "test-secret";
    const BODY: &[u8] = b"hello world";

    fn make_header(sig: &str) -> String {
        format!("sha256={}", sig)
    }

    #[test]
    fn valid_signature_returns_true() {
        let sig = compute_signature(BODY, SECRET);
        let header = make_header(&sig);
        assert!(verify_signature(&header, BODY, SECRET));
    }

    #[test]
    fn wrong_secret_returns_false() {
        let sig = compute_signature(BODY, SECRET);
        let header = make_header(&sig);
        assert!(!verify_signature(&header, BODY, "wrong-secret"));
    }

    #[test]
    fn missing_prefix_returns_false() {
        let sig = compute_signature(BODY, SECRET);
        // No "sha256=" prefix
        assert!(!verify_signature(&sig, BODY, SECRET));
    }

    #[test]
    fn invalid_hex_returns_false() {
        let header = "sha256=notvalidhex!!";
        assert!(!verify_signature(header, BODY, SECRET));
    }

    #[test]
    fn empty_body_with_valid_signature_returns_true() {
        let empty: &[u8] = b"";
        let sig = compute_signature(empty, SECRET);
        let header = make_header(&sig);
        assert!(verify_signature(&header, empty, SECRET));
    }

    #[test]
    fn compute_signature_round_trips_with_verify() {
        let body = b"payload bytes for round-trip test";
        let sig = compute_signature(body, SECRET);
        let header = make_header(&sig);
        assert!(verify_signature(&header, body, SECRET));
    }

    #[test]
    fn resolve_secret_uses_app_secret_when_present() {
        assert_eq!(
            resolve_secret(Some("app-secret"), "global-secret"),
            "app-secret"
        );
    }

    #[test]
    fn resolve_secret_falls_back_to_global() {
        assert_eq!(resolve_secret(None, "global-secret"), "global-secret");
    }
}
