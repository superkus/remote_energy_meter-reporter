//! The exact single-member RFC 9530 `Content-Digest` form (wire profile section 7).
//!
//! Only `sha-256=:<canonical padded standard base64 of 32 bytes>:` is accepted: one member, the
//! lowercase algorithm key, no parameters, no surrounding whitespace, at most 256 bytes. Comparison
//! against a received body is constant time.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::ErrorClass;
use super::b64u::{decode_standard_exact, encode_standard};

/// Maximum `Content-Digest` header value length (`routes.json` limits).
pub const CONTENT_DIGEST_HEADER_MAX_BYTES: usize = 256;

const PREFIX: &str = "sha-256=:";
const SUFFIX: &str = ":";

/// A SHA-256 content digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ContentDigest {
    sha256: [u8; 32],
}

impl ContentDigest {
    /// The digest of the exact `body` bytes.
    #[must_use]
    pub fn for_body(body: &[u8]) -> Self {
        Self {
            sha256: Sha256::digest(body).into(),
        }
    }

    /// Accept only the exact canonical single-member form.
    ///
    /// # Errors
    /// [`ErrorClass::InvalidRequest`] for any other algorithm, member count, spelling, padding,
    /// whitespace, or an over-long value.
    pub fn parse_exact(text: &str) -> Result<Self, ErrorClass> {
        if text.len() > CONTENT_DIGEST_HEADER_MAX_BYTES {
            return Err(ErrorClass::InvalidRequest);
        }
        let encoded = text
            .strip_prefix(PREFIX)
            .and_then(|rest| rest.strip_suffix(SUFFIX))
            .ok_or(ErrorClass::InvalidRequest)?;
        let sha256 = decode_standard_exact::<32>(encoded).ok_or(ErrorClass::InvalidRequest)?;
        Ok(Self { sha256 })
    }

    /// The canonical header value.
    #[must_use]
    pub fn render(&self) -> String {
        format!("{PREFIX}{}{SUFFIX}", encode_standard(&self.sha256))
    }

    /// The raw 32-byte SHA-256 value.
    #[must_use]
    pub const fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    /// Check, in constant time, that `body` has this digest.
    ///
    /// # Errors
    /// [`ErrorClass::InvalidRequest`] on mismatch.
    pub fn verify(&self, body: &[u8]) -> Result<(), ErrorClass> {
        let actual = Self::for_body(body);
        if bool::from(actual.sha256.as_slice().ct_eq(self.sha256.as_slice())) {
            Ok(())
        } else {
            Err(ErrorClass::InvalidRequest)
        }
    }
}
