//! REM protocol v1 wire primitives and RFC 9421 request verification.
//!
//! **Draft — not approved for distribution.** This module implements the server-owned profile
//! vendored byte-for-byte under `tests/fixtures/protocol/v1` (see `PROVENANCE.txt`). The profile
//! itself is a normative draft: task 3.4's independent security review must approve it before any
//! reporter build that speaks it is distributed. Nothing in this crate listens on or sends this
//! protocol yet; the executable consumers are the network-free protocol demonstrations.
//!
//! Every parser is strict and fails closed:
//!
//! - [`b64u`]: canonical unpadded base64url with exact or bounded decoded lengths.
//! - [`transcript`]: the bounded `REM-TRANSCRIPT` length-delimited encoding and exact decoder.
//! - [`canonical_json`]: exact `rem-canonical-json-v1` byte-form checks.
//! - [`jwk`]: exact canonical P-256 public JWKs, on-curve validation, and RFC 7638 thumbprints.
//! - [`content_digest`]: the single-member RFC 9530 `sha-256` `Content-Digest` form.
//! - [`signature`]: 64-byte IEEE P1363 low-S ECDSA P-256/SHA-256 verification.
//! - [`sas`]: exact six-byte interactive SAS derivation, caller-resource word-list validation,
//!   alternating Even/Odd rendering, strict ASCII parsing, and constant-time verification.
//! - [`routes`]: route lookup from the vendored route manifest, with exact target and query forms.
//! - [`http_signature`]: canonical IDNA2008 authority checks and the narrow
//!   `reporter-rfc9421-v1` and `control-rfc9421-v1` profiles.
//!
//! Stateful replay protection (nonce stores, sequence tracking, single-use challenges) is out of
//! scope here. [`http_signature::VerifiedIdentity`] retains the exact admitted request, its
//! length-delimited SHA-256 hash, and the stable principal selected by the trusted key binding for
//! later replay and exact-retry logic.
//!
//! Errors carry only an [`ErrorClass`]: no request input, identifier, or key material is ever
//! attached to a failure.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

pub mod b64u;
pub mod canonical_json;
pub mod content_digest;
pub mod http_signature;
pub mod jwk;
pub mod routes;
pub mod sas;
pub mod signature;
pub mod transcript;

/// The closed set of protocol v1 problem codes (`schemas/problem.schema.json`).
///
/// A failure is reported only as its class so that no request input can leak through diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorClass {
    /// `invalid_request` (400): malformed target, header, body, digest, or canonical form.
    InvalidRequest,
    /// `authentication_required` (401): signature, key, profile, or freshness failure.
    AuthenticationRequired,
    /// `authorization_denied` (403).
    AuthorizationDenied,
    /// `not_found` (404): unknown path.
    NotFound,
    /// `method_not_allowed` (405): known path, other method.
    MethodNotAllowed,
    /// `request_timeout` (408).
    RequestTimeout,
    /// `conflict` (409).
    Conflict,
    /// `snapshot_required` (409).
    SnapshotRequired,
    /// `stale_snapshot` (410).
    StaleSnapshot,
    /// `operation_result_expired` (410).
    OperationResultExpired,
    /// `request_body_too_large` (413).
    RequestBodyTooLarge,
    /// `target_too_long` (414): request target over 256 bytes.
    TargetTooLong,
    /// `unsupported_media_type` (415): wrong or parameterized `Content-Type`, or any encoding.
    UnsupportedMediaType,
    /// `rate_limited` (429).
    RateLimited,
    /// `headers_too_large` (431).
    HeadersTooLarge,
    /// `internal_error` (500).
    InternalError,
    /// `overloaded` (503).
    Overloaded,
}

impl ErrorClass {
    /// The exact wire `code` member for this class.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::AuthenticationRequired => "authentication_required",
            Self::AuthorizationDenied => "authorization_denied",
            Self::NotFound => "not_found",
            Self::MethodNotAllowed => "method_not_allowed",
            Self::RequestTimeout => "request_timeout",
            Self::Conflict => "conflict",
            Self::SnapshotRequired => "snapshot_required",
            Self::StaleSnapshot => "stale_snapshot",
            Self::OperationResultExpired => "operation_result_expired",
            Self::RequestBodyTooLarge => "request_body_too_large",
            Self::TargetTooLong => "target_too_long",
            Self::UnsupportedMediaType => "unsupported_media_type",
            Self::RateLimited => "rate_limited",
            Self::HeadersTooLarge => "headers_too_large",
            Self::InternalError => "internal_error",
            Self::Overloaded => "overloaded",
        }
    }

    /// The fixed HTTP status for this class.
    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            Self::InvalidRequest => 400,
            Self::AuthenticationRequired => 401,
            Self::AuthorizationDenied => 403,
            Self::NotFound => 404,
            Self::MethodNotAllowed => 405,
            Self::RequestTimeout => 408,
            Self::Conflict | Self::SnapshotRequired => 409,
            Self::StaleSnapshot | Self::OperationResultExpired => 410,
            Self::RequestBodyTooLarge => 413,
            Self::TargetTooLong => 414,
            Self::UnsupportedMediaType => 415,
            Self::RateLimited => 429,
            Self::HeadersTooLarge => 431,
            Self::InternalError => 500,
            Self::Overloaded => 503,
        }
    }
}

impl Display for ErrorClass {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for ErrorClass {}

/// Parse a canonical unsigned decimal `uint64`: no sign, no leading zero except `0`.
pub(crate) fn parse_canonical_u64(text: &[u8]) -> Option<u64> {
    match text {
        [] => None,
        [b'0'] => Some(0),
        [b'0', ..] => None,
        digits => {
            let mut value: u64 = 0;
            for &digit in digits {
                if !digit.is_ascii_digit() {
                    return None;
                }
                value = value
                    .checked_mul(10)?
                    .checked_add(u64::from(digit - b'0'))?;
            }
            Some(value)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_u64_rejects_sign_leading_zero_and_overflow() {
        assert_eq!(parse_canonical_u64(b"0"), Some(0));
        assert_eq!(parse_canonical_u64(b"18446744073709551615"), Some(u64::MAX));
        for rejected in [
            b"".as_slice(),
            b"00",
            b"01",
            b"+1",
            b"-1",
            b"1 ",
            b"18446744073709551616",
        ] {
            assert_eq!(parse_canonical_u64(rejected), None);
        }
    }

    #[test]
    fn every_class_has_its_fixed_code_status_and_display() {
        assert_eq!(ErrorClass::InvalidRequest.code(), "invalid_request");
        assert_eq!(ErrorClass::InvalidRequest.to_string(), "invalid_request");
        assert_eq!(ErrorClass::AuthenticationRequired.status(), 401);
        assert_eq!(ErrorClass::HeadersTooLarge.status(), 431);
    }
}
