//! Exact canonical P-256 public JWKs and RFC 7638 thumbprints (wire profile sections 1 and 5).
//!
//! The profile admits exactly one byte form:
//! `{"crv":"P-256","kty":"EC","x":<b64u32>,"y":<b64u32>}` with members in that order and no
//! whitespace. Because that form is also the RFC 7638 thumbprint input, the accepted bytes are the
//! canonical bytes. Any duplicate, extra, or private (`d`) member, other order, whitespace,
//! compressed point, off-curve point, or coordinate outside the field is rejected.

use p256::ecdsa::VerifyingKey;
use sha2::{Digest, Sha256};

use super::ErrorClass;
use super::b64u::{B64u, encode_b64u};

const PREFIX: &[u8] = br#"{"crv":"P-256","kty":"EC","x":""#;
const MIDDLE: &[u8] = br#"","y":""#;
const SUFFIX: &[u8] = br#""}"#;
const COORDINATE_TEXT_LEN: usize = 43;
const CANONICAL_LEN: usize =
    PREFIX.len() + COORDINATE_TEXT_LEN + MIDDLE.len() + COORDINATE_TEXT_LEN + SUFFIX.len();

/// A validated P-256 public key in its exact canonical JWK form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P256PublicJwk {
    canonical: Vec<u8>,
    thumbprint: B64u<32>,
    key: VerifyingKey,
}

impl P256PublicJwk {
    /// Accept only the exact canonical JWK bytes of a valid, on-curve P-256 public key.
    ///
    /// # Errors
    /// [`ErrorClass::InvalidRequest`] for any other byte form or an invalid point.
    pub fn parse_exact(bytes: &[u8]) -> Result<Self, ErrorClass> {
        if bytes.len() != CANONICAL_LEN {
            return Err(ErrorClass::InvalidRequest);
        }
        let rest = bytes
            .strip_prefix(PREFIX)
            .ok_or(ErrorClass::InvalidRequest)?;
        let (x, rest) = rest.split_at(COORDINATE_TEXT_LEN);
        let rest = rest
            .strip_prefix(MIDDLE)
            .ok_or(ErrorClass::InvalidRequest)?;
        let (y, rest) = rest.split_at(COORDINATE_TEXT_LEN);
        if rest != SUFFIX {
            return Err(ErrorClass::InvalidRequest);
        }
        let coordinate = |text: &[u8]| {
            std::str::from_utf8(text)
                .map_err(|_| ErrorClass::InvalidRequest)
                .and_then(B64u::<32>::parse)
        };
        let (x, y) = (coordinate(x)?, coordinate(y)?);
        Self::from_coordinates(x.as_array(), y.as_array())
    }

    /// Build the canonical JWK of an uncompressed affine point, validating it is on the curve.
    ///
    /// # Errors
    /// [`ErrorClass::InvalidRequest`] when a coordinate is outside the field or the point is not
    /// on the curve.
    pub fn from_coordinates(x: &[u8; 32], y: &[u8; 32]) -> Result<Self, ErrorClass> {
        let mut sec1 = [0_u8; 65];
        sec1[0] = 0x04;
        sec1[1..33].copy_from_slice(x);
        sec1[33..].copy_from_slice(y);
        let key = VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| ErrorClass::InvalidRequest)?;

        let mut canonical = Vec::with_capacity(CANONICAL_LEN);
        canonical.extend_from_slice(PREFIX);
        canonical.extend_from_slice(encode_b64u(x).as_bytes());
        canonical.extend_from_slice(MIDDLE);
        canonical.extend_from_slice(encode_b64u(y).as_bytes());
        canonical.extend_from_slice(SUFFIX);
        let thumbprint = B64u::from_bytes(Sha256::digest(&canonical).into());
        Ok(Self {
            canonical,
            thumbprint,
            key,
        })
    }

    /// Build the canonical JWK of a verifying key (for example one derived from a signing key).
    #[must_use]
    pub fn from_verifying_key(key: &VerifyingKey) -> Self {
        let point = key.to_sec1_point(false);
        let (Some(x), Some(y)) = (point.x(), point.y()) else {
            unreachable!("an uncompressed SEC1 point of a verifying key has both coordinates")
        };
        let (mut x_bytes, mut y_bytes) = ([0_u8; 32], [0_u8; 32]);
        x_bytes.copy_from_slice(x);
        y_bytes.copy_from_slice(y);
        Self::from_coordinates(&x_bytes, &y_bytes)
            .unwrap_or_else(|_| unreachable!("a verifying key is a valid curve point"))
    }

    /// The exact RFC 7638 canonical bytes (identical to the accepted input).
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    /// The 32-byte RFC 7638 SHA-256 thumbprint.
    #[must_use]
    pub fn thumbprint(&self) -> &[u8] {
        self.thumbprint.as_bytes()
    }

    /// The thumbprint as canonical `b64u32` (the protocol `keyid` / `reporter_id` form).
    #[must_use]
    pub const fn thumbprint_b64u(&self) -> &B64u<32> {
        &self.thumbprint
    }

    pub(crate) const fn verifying_key(&self) -> &VerifyingKey {
        &self.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_point_at_infinity_and_coordinates_outside_the_field() {
        assert_eq!(
            P256PublicJwk::from_coordinates(&[0; 32], &[0; 32]),
            Err(ErrorClass::InvalidRequest)
        );
        assert_eq!(
            P256PublicJwk::from_coordinates(&[0xff; 32], &[0xff; 32]),
            Err(ErrorClass::InvalidRequest)
        );
    }

    #[test]
    fn rejects_trailing_or_truncated_bytes_without_panicking() {
        let canonical = br#"{"crv":"P-256","kty":"EC","x":"qXlTk75KQKYN-PBJPDM4qHw8tYKgDLaqixcHrthpc_U","y":"tdXohmn4d0O78ACF989uLrxgHWAryPJteiOQIvBjRDo"}"#;
        assert!(P256PublicJwk::parse_exact(canonical).is_ok());
        for end in 0..canonical.len() {
            assert!(P256PublicJwk::parse_exact(&canonical[..end]).is_err());
        }
        let mut longer = canonical.to_vec();
        longer.push(b' ');
        assert!(P256PublicJwk::parse_exact(&longer).is_err());
    }
}
