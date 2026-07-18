//! Parsed, canonical, non-empty set of accepted HTTP status codes.
//!
//! `expect_status` grammar (RFC 9110 §15 status codes; RFC 9110 §5.6.1 `#rule`
//! comma-list syntax):
//!
//! ```text
//! expect_status = 1#status_item
//! status_item   = status_code [ "-" status_code ]
//! status_code   = 3DIGIT       ; 100-599
//! ```
//!
//! - Comma-separated list of single codes (`"200"`), inclusive ranges
//!   (`"200-299"`), or any mix (`"200-299,503"`).
//! - Optional whitespace (spaces/tabs) around `,` and `-` is ignored.
//! - Codes must be in `100..=599`. Out-of-range, empty, reversed ranges, and
//!   trailing garbage are hard parse errors.
//! - Duplicates and overlapping ranges are merged canonically at parse time so
//!   the canonical form is stable across round-trips (used by `--json`).
//!
//! `Option<StatusExpectation>` serializes as `null` when absent and as the
//! canonical string when present. Absent ↔ `null` is stable, so adding the
//! field to configs that don't set it produces no diff drift.

use std::ops::RangeInclusive;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Parsed, canonical, non-empty set of accepted status codes.
///
/// Internally a sorted, merged, non-overlapping, non-empty list of inclusive
/// `u16` ranges. The default (`200-399`, Kubernetes-compatible) is applied at
/// probe time when the config field is `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusExpectation(Box<[RangeInclusive<u16>]>);

/// Errors that can occur while parsing an `expect_status` string.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StatusParseError {
    /// Empty string (or only whitespace/commas).
    #[error("expect_status {raw:?} invalid: at least one status code is required")]
    Empty { raw: String },

    /// Code outside the registered HTTP status range (100-599, RFC 9110 §15).
    #[error("expect_status {raw:?} invalid: HTTP status codes must be in 100-599 (RFC 9110 §15)")]
    OutOfRange { raw: String },

    /// Range with `lo > hi` (a typo — never silently swapped).
    #[error("expect_status {raw:?} invalid: range start must be ≤ end")]
    Reversed { raw: String },

    /// Non-numeric garbage where a code was expected.
    #[error("expect_status {raw:?} invalid: non-numeric")]
    NonNumeric { raw: String },

    /// Trailing characters after a code or range (`"200abc"`, `"200-"`, `"200,,"`).
    #[error("expect_status {raw:?} invalid: trailing garbage")]
    TrailingGarbage { raw: String },
}

impl StatusExpectation {
    /// Parse an `expect_status` spec.
    ///
    /// See the module docs for the grammar. The returned value is canonical:
    /// sorted, merged, non-overlapping, non-empty. Single-code ranges are
    /// collapsed (`200-200` → `200`).
    pub fn parse(s: &str) -> Result<Self, StatusParseError> {
        // Split on comma. Each item is either `code` or `lo-hi`.
        let mut ranges: Vec<RangeInclusive<u16>> = Vec::new();

        // Empty string → Empty (do not accept "accept everything").
        // Track whether at least one non-empty item was produced.
        let mut saw_item = false;

        for item in s.split(',') {
            // Trim OWS around the whole item first.
            let item = item.trim();
            if item.is_empty() {
                // Skip empty items that arise from leading/trailing/double commas
                // — but only if at least one real item is seen. If *every* item
                // is empty, we reject with Empty below.
                continue;
            }
            saw_item = true;

            // Split on the first `-` to find a range. We trim OWS around the
            // dash, so `"200 - 299"` parses the same as `"200-299"`.
            let (lo_str, hi_str) = match item.split_once('-') {
                Some((lo, hi)) => (lo.trim(), hi.trim()),
                None => (item.trim(), item.trim()),
            };

            // Reject empty halves (`"200-"`, `"-200"`).
            if lo_str.is_empty() || hi_str.is_empty() {
                return Err(StatusParseError::TrailingGarbage { raw: s.to_string() });
            }

            let lo = parse_code(lo_str)
                .map_err(|_| StatusParseError::NonNumeric { raw: s.to_string() })?;
            // Reject trailing garbage after the low code: `"200abc"` (single) or
            // `"200abc-299"` (range low). parse_code already rejects non-numeric,
            // but it parses by `u16::from_str` which rejects trailing garbage —
            // so we surface NonNumeric for that. For `"200-"` we already errored
            // above.
            let _ = lo_str;

            let hi = if lo_str == hi_str {
                lo
            } else {
                parse_code(hi_str)
                    .map_err(|_| StatusParseError::NonNumeric { raw: s.to_string() })?
            };

            // Range checks on both ends.
            if !(100..=599).contains(&lo) || !(100..=599).contains(&hi) {
                return Err(StatusParseError::OutOfRange { raw: s.to_string() });
            }

            if lo > hi {
                return Err(StatusParseError::Reversed { raw: s.to_string() });
            }

            ranges.push(lo..=hi);
        }

        if !saw_item || ranges.is_empty() {
            return Err(StatusParseError::Empty { raw: s.to_string() });
        }

        Ok(Self::merge(ranges))
    }

    /// Returns true if `code` is accepted by this expectation.
    pub fn accepts(&self, code: u16) -> bool {
        self.0.iter().any(|r| r.contains(&code))
    }

    /// Canonical, stable string form.
    ///
    /// - Single code → `"200"`.
    /// - Multiple codes → `"200,204"`.
    /// - Range (≥ 2 codes) → `"200-299"`.
    /// - Mixed → `"200-299,503"`.
    ///
    /// Round-trips: `parse(canonical(x)) == x`.
    pub fn canonical(&self) -> String {
        let parts: Vec<String> = self
            .0
            .iter()
            .map(|r| {
                let (lo, hi) = (*r.start(), *r.end());
                if lo == hi {
                    lo.to_string()
                } else {
                    format!("{lo}-{hi}")
                }
            })
            .collect();
        parts.join(",")
    }

    /// Merge a list of ranges into sorted, non-overlapping, non-adjacent form.
    ///
    /// Adjacent ranges are coalesced (`200-299` + `300-399` → `200-399`).
    fn merge(mut ranges: Vec<RangeInclusive<u16>>) -> Self {
        // Sort by start, then by end.
        ranges.sort_by_key(|r| (*r.start(), *r.end()));
        let mut out: Vec<RangeInclusive<u16>> = Vec::new();
        for r in ranges {
            match out.last_mut() {
                Some(last) if *r.start() <= last.end().checked_add(1).unwrap_or(u16::MAX) => {
                    // Overlap or adjacency: extend the last range if needed.
                    if *r.end() > *last.end() {
                        let lo = *last.start();
                        let hi = *r.end();
                        *last = lo..=hi;
                    }
                }
                _ => out.push(r),
            }
        }
        // Collapse `200-200` to `200-200` — canonical() handles the rendering.
        Self(out.into_boxed_slice())
    }
}

impl Default for StatusExpectation {
    /// Default expectation: `200-399` (Kubernetes-compatible: any code ≥ 200
    /// and < 400 counts as healthy). Accepts `307` — preserves the prior
    /// "redirect resolves to success" behavior under the no-redirect probe.
    fn default() -> Self {
        Self::parse("200-399").expect("default is valid")
    }
}

impl std::fmt::Display for StatusExpectation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.canonical())
    }
}

// ─── Custom serde (string in TOML/JSON, canonical form) ───────────────────────

impl Serialize for StatusExpectation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.canonical())
    }
}

impl<'de> Deserialize<'de> for StatusExpectation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Parse a single 3-digit status code from a trimmed string. Returns Err on
/// any non-numeric input.
fn parse_code(s: &str) -> Result<u16, ()> {
    s.parse::<u16>().map_err(|_| ())
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> StatusExpectation {
        StatusExpectation::parse(s).expect("should parse")
    }

    // ── Single code ────────────────────────────────────────────────────────────

    #[test]
    fn single_code_accepts_only_that_code() {
        let e = parse("200");
        assert!(e.accepts(200));
        assert!(!e.accepts(199));
        assert!(!e.accepts(201));
        assert!(!e.accepts(307));
        assert!(!e.accepts(500));
        assert_eq!(e.canonical(), "200");
    }

    // ── List ───────────────────────────────────────────────────────────────────

    #[test]
    fn list_accepts_all_listed_codes() {
        let e = parse("200,204");
        assert!(e.accepts(200));
        assert!(e.accepts(204));
        assert!(!e.accepts(201));
        assert_eq!(e.canonical(), "200,204");
    }

    // ── Range ───────────────────────────────────────────────────────────────────

    #[test]
    fn range_accepts_all_in_range() {
        let e = parse("200-299");
        assert!(e.accepts(200));
        assert!(e.accepts(204));
        assert!(e.accepts(299));
        assert!(!e.accepts(199));
        assert!(!e.accepts(300));
        assert_eq!(e.canonical(), "200-299");
    }

    // ── Mixed ──────────────────────────────────────────────────────────────────

    #[test]
    fn mixed_range_and_single() {
        let e = parse("200-299,503");
        assert!(e.accepts(200));
        assert!(e.accepts(204));
        assert!(e.accepts(299));
        assert!(e.accepts(503));
        assert!(!e.accepts(300));
        assert!(!e.accepts(500));
        assert_eq!(e.canonical(), "200-299,503");
    }

    // ── Whitespace ─────────────────────────────────────────────────────────────

    #[test]
    fn whitespace_around_commas_and_dash_ignored() {
        let a = parse(" 200 , 204 ");
        let b = parse("200,204");
        assert_eq!(a, b);
        assert_eq!(a.canonical(), "200,204");
    }

    #[test]
    fn whitespace_around_dash_ignored() {
        let a = parse("200 - 299");
        let b = parse("200-299");
        assert_eq!(a, b);
    }

    // ── Duplicates / overlaps merged ───────────────────────────────────────────

    #[test]
    fn duplicates_are_merged() {
        let e = parse("200,200");
        assert_eq!(e.canonical(), "200");
    }

    #[test]
    fn overlapping_ranges_are_merged() {
        let e = parse("200-299,250-302");
        assert_eq!(e.canonical(), "200-302");
    }

    #[test]
    fn adjacent_ranges_are_coalesced() {
        let e = parse("200-299,300-399");
        assert_eq!(e.canonical(), "200-399");
    }

    #[test]
    fn single_code_range_normalizes_to_single() {
        let e = parse("200-200");
        assert_eq!(e.canonical(), "200");
    }

    // ── Errors ─────────────────────────────────────────────────────────────────

    #[test]
    fn empty_string_errors() {
        let err = StatusExpectation::parse("").unwrap_err();
        assert!(matches!(err, StatusParseError::Empty { .. }));
    }

    #[test]
    fn only_commas_and_whitespace_errors() {
        let err = StatusExpectation::parse(" , , ").unwrap_err();
        assert!(matches!(err, StatusParseError::Empty { .. }));
    }

    #[test]
    fn out_of_range_low_errors() {
        let err = StatusExpectation::parse("99").unwrap_err();
        assert!(matches!(err, StatusParseError::OutOfRange { .. }));
    }

    #[test]
    fn out_of_range_high_errors() {
        let err = StatusExpectation::parse("600").unwrap_err();
        assert!(matches!(err, StatusParseError::OutOfRange { .. }));
    }

    #[test]
    fn out_of_range_zero_errors() {
        let err = StatusExpectation::parse("0").unwrap_err();
        assert!(matches!(err, StatusParseError::OutOfRange { .. }));
    }

    #[test]
    fn out_of_range_in_range_high_errors() {
        let err = StatusExpectation::parse("200-999").unwrap_err();
        assert!(matches!(err, StatusParseError::OutOfRange { .. }));
    }

    #[test]
    fn reversed_range_errors() {
        let err = StatusExpectation::parse("400-200").unwrap_err();
        assert!(matches!(err, StatusParseError::Reversed { .. }));
    }

    #[test]
    fn trailing_garbage_after_code_errors() {
        let err = StatusExpectation::parse("200abc").unwrap_err();
        assert!(matches!(err, StatusParseError::NonNumeric { .. }));
    }

    #[test]
    fn dangling_dash_errors() {
        let err = StatusExpectation::parse("200-").unwrap_err();
        assert!(matches!(err, StatusParseError::TrailingGarbage { .. }));
    }

    #[test]
    fn non_numeric_errors() {
        let err = StatusExpectation::parse("abc").unwrap_err();
        assert!(matches!(err, StatusParseError::NonNumeric { .. }));
    }

    // ── Canonical round-trip ───────────────────────────────────────────────────

    #[test]
    fn canonical_round_trips_single() {
        let e = parse("200");
        let e2 = parse(&e.canonical());
        assert_eq!(e, e2);
    }

    #[test]
    fn canonical_round_trips_list() {
        let e = parse("200,204,301");
        let e2 = parse(&e.canonical());
        assert_eq!(e, e2);
    }

    #[test]
    fn canonical_round_trips_range() {
        let e = parse("200-299");
        let e2 = parse(&e.canonical());
        assert_eq!(e, e2);
    }

    #[test]
    fn canonical_round_trips_mixed_with_overlap() {
        let e = parse("200-299,250-302,503");
        let canon = e.canonical();
        assert_eq!(canon, "200-302,503");
        let e2 = parse(&canon);
        assert_eq!(e, e2);
    }

    // ── Default ────────────────────────────────────────────────────────────────

    #[test]
    fn default_is_200_399_and_accepts_307() {
        let e = StatusExpectation::default();
        assert_eq!(e.canonical(), "200-399");
        assert!(e.accepts(200));
        assert!(e.accepts(307));
        assert!(e.accepts(399));
        assert!(!e.accepts(199));
        assert!(!e.accepts(400));
        assert!(!e.accepts(500));
    }

    #[test]
    fn display_matches_canonical() {
        let e = parse("200-299,503");
        assert_eq!(e.to_string(), e.canonical());
    }

    // ── Serde round-trip ───────────────────────────────────────────────────────

    #[test]
    fn serde_round_trips_canonical_string() {
        #[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize)]
        struct Wrapper {
            expect: StatusExpectation,
        }
        let w = Wrapper {
            expect: parse("200,307"),
        };
        let json = serde_json::to_string(&w).unwrap();
        assert_eq!(json, r#"{"expect":"200,307"}"#);
        let back: Wrapper = serde_json::from_str(&json).unwrap();
        assert_eq!(back, w);
    }

    #[test]
    fn serde_option_none_serializes_null() {
        #[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize)]
        struct Wrapper {
            #[serde(default, skip_serializing_if = "Option::is_none")]
            expect: Option<StatusExpectation>,
        }
        let w = Wrapper { expect: None };
        let json = serde_json::to_string(&w).unwrap();
        assert_eq!(json, r#"{}"#);
        let back: Wrapper = serde_json::from_str(&json).unwrap();
        assert_eq!(back, w);
    }

    #[test]
    fn serde_invalid_spec_fails_deserialize() {
        let result: Result<StatusExpectation, _> = serde_json::from_str("\"400-200\"");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("range start must be"), "got: {err}");
    }
}
