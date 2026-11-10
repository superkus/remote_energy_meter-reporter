//! 64-byte IEEE P1363 low-S ECDSA P-256/SHA-256 verification (wire profile section 6).
//!
//! A signature is exactly `r || s`, each a 32-byte big-endian scalar. Verifiers reject any other
//! length, `r` or `s` equal to zero or not below the group order `n`, and `s > n/2` (high-S).
//! DER is never accepted. The message is the exact signed bytes; SHA-256 is applied here.

use p256::ecdsa::Signature;
use p256::ecdsa::signature::Verifier;
use p256::elliptic_curve::scalar::IsHigh;

use super::ErrorClass;
use super::jwk::P256PublicJwk;

/// Encoded P1363 signature length.
pub const P1363_SIGNATURE_BYTES: usize = 64;

/// Verify a low-S P1363 signature over `message` under `key`.
///
/// # Errors
/// [`ErrorClass::AuthenticationRequired`] for a malformed, out-of-range, high-S, or invalid
/// signature.
pub fn verify_p1363_low_s(
    key: &P256PublicJwk,
    message: &[u8],
    signature: &[u8],
) -> Result<(), ErrorClass> {
    if signature.len() != P1363_SIGNATURE_BYTES {
        return Err(ErrorClass::AuthenticationRequired);
    }
    // `from_slice` rejects r or s equal to zero or not below n.
    let signature =
        Signature::from_slice(signature).map_err(|_| ErrorClass::AuthenticationRequired)?;
    if bool::from(signature.s().is_high()) {
        return Err(ErrorClass::AuthenticationRequired);
    }
    key.verifying_key()
        .verify(message, &signature)
        .map_err(|_| ErrorClass::AuthenticationRequired)
}

#[cfg(test)]
mod tests {
    use super::*;

    const JWK: &[u8] = br#"{"crv":"P-256","kty":"EC","x":"qXlTk75KQKYN-PBJPDM4qHw8tYKgDLaqixcHrthpc_U","y":"tdXohmn4d0O78ACF989uLrxgHWAryPJteiOQIvBjRDo"}"#;
    /// P-256 group order n.
    const ORDER: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];
    /// floor(n/2), the largest accepted S scalar.
    const HALF_ORDER: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31,
        0x92, 0xa8,
    ];

    #[test]
    fn low_s_boundary_includes_half_order_and_excludes_the_next_scalar() {
        let mut bytes = [0_u8; 64];
        bytes[31] = 1;
        bytes[32..].copy_from_slice(&HALF_ORDER);
        let at_boundary = Signature::from_slice(&bytes).unwrap();
        assert!(!bool::from(at_boundary.s().is_high()));

        bytes[63] += 1;
        let above_boundary = Signature::from_slice(&bytes).unwrap();
        assert!(bool::from(above_boundary.s().is_high()));
    }

    #[test]
    fn scalars_at_or_above_the_order_are_rejected_before_verification() {
        let key = P256PublicJwk::parse_exact(JWK).unwrap();
        let mut signature = [0x01_u8; 64];
        signature[..32].copy_from_slice(&ORDER);
        assert_eq!(
            verify_p1363_low_s(&key, b"m", &signature),
            Err(ErrorClass::AuthenticationRequired)
        );
        let mut signature = [0x01_u8; 64];
        signature[32..].copy_from_slice(&ORDER);
        assert_eq!(
            verify_p1363_low_s(&key, b"m", &signature),
            Err(ErrorClass::AuthenticationRequired)
        );
        assert_eq!(
            verify_p1363_low_s(&key, b"m", &[0x01; 65]),
            Err(ErrorClass::AuthenticationRequired)
        );
    }
}
