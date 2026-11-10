//! Canonical base64 encodings (RFC 4648).
//!
//! Protocol values use unpadded base64url (`b64u<n>`, `opaque128`, `opaque256`). A decoder accepts
//! only the single canonical spelling: no padding, no whitespace, no standard-alphabet `+` or `/`,
//! and zero unused trailing bits. Lengths are checked on the text before any decoding allocation.
//!
//! The padded standard alphabet is used only inside RFC 8941 byte sequences (`Content-Digest`,
//! `Signature`); it is crate-private and equally canonical.

use std::fmt;
use std::hash::{Hash, Hasher};

use subtle::ConstantTimeEq;

use super::ErrorClass;

const URL_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const STANDARD_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Exact length of the unpadded encoding of `bytes` bytes.
const fn unpadded_len(bytes: usize) -> usize {
    (bytes * 4).div_ceil(3)
}

fn encode(bytes: &[u8], alphabet: &[u8; 64], padded: bool) -> String {
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (u32::from(chunk.get(1).copied().unwrap_or(0)) << 8)
            | u32::from(chunk.get(2).copied().unwrap_or(0));
        let digits = [
            alphabet[((value >> 18) & 63) as usize],
            alphabet[((value >> 12) & 63) as usize],
            alphabet[((value >> 6) & 63) as usize],
            alphabet[(value & 63) as usize],
        ];
        let kept = chunk.len() + 1;
        for &digit in &digits[..kept] {
            output.push(char::from(digit));
        }
        if padded {
            for _ in kept..4 {
                output.push('=');
            }
        }
    }
    output
}

fn digit(byte: u8, alphabet: &[u8; 64]) -> Option<u32> {
    alphabet
        .iter()
        .position(|candidate| *candidate == byte)
        .and_then(|index| u32::try_from(index).ok())
}

/// Decode unpadded digits, then require that re-encoding reproduces the input exactly.
fn decode_canonical(text: &str, alphabet: &[u8; 64], padded: bool) -> Option<Vec<u8>> {
    let digits = if padded {
        if !text.len().is_multiple_of(4) {
            return None;
        }
        text.strip_suffix("==")
            .or_else(|| text.strip_suffix('='))
            .unwrap_or(text)
    } else {
        text
    };
    if digits.len() % 4 == 1 {
        return None;
    }
    let mut output = Vec::with_capacity(digits.len() / 4 * 3 + 2);
    for chunk in digits.as_bytes().chunks(4) {
        let mut value = 0_u32;
        for &byte in chunk {
            value = (value << 6) | digit(byte, alphabet)?;
        }
        value <<= 6 * (4 - chunk.len());
        let [_, first, second, third] = value.to_be_bytes();
        output.push(first);
        if chunk.len() >= 3 {
            output.push(second);
        }
        if chunk.len() == 4 {
            output.push(third);
        }
    }
    (encode(&output, alphabet, padded) == text).then_some(output)
}

/// Canonical unpadded base64url text of `bytes`.
#[must_use]
pub fn encode_b64u(bytes: &[u8]) -> String {
    encode(bytes, URL_ALPHABET, false)
}

/// Canonical padded standard base64 text of `bytes` (RFC 8941 byte-sequence content).
pub(crate) fn encode_standard(bytes: &[u8]) -> String {
    encode(bytes, STANDARD_ALPHABET, true)
}

/// Decode canonical padded standard base64 of exactly `N` bytes.
pub(crate) fn decode_standard_exact<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N.div_ceil(3) * 4 {
        return None;
    }
    decode_canonical(text, STANDARD_ALPHABET, true)?
        .try_into()
        .ok()
}

/// A canonical `b64u<N>` value: exactly `N` decoded bytes.
///
/// `Debug` prints only the length, so a value holding a secret (for example a pairing secret) is
/// never written to diagnostics. Equality compares the fixed-size decoded bytes in constant time.
#[derive(Clone)]
pub struct B64u<const N: usize> {
    bytes: [u8; N],
    text: String,
}

impl<const N: usize> PartialEq for B64u<N> {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.bytes.ct_eq(&other.bytes))
    }
}

impl<const N: usize> Eq for B64u<N> {}

impl<const N: usize> Hash for B64u<N> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}

impl<const N: usize> B64u<N> {
    /// Parse the canonical encoding of exactly `N` bytes.
    ///
    /// # Errors
    /// [`ErrorClass::InvalidRequest`] for any other length, alphabet, padding, whitespace, or
    /// non-zero unused trailing bits.
    pub fn parse(text: &str) -> Result<Self, ErrorClass> {
        if N == 0 || text.len() != unpadded_len(N) {
            return Err(ErrorClass::InvalidRequest);
        }
        let bytes = decode_canonical(text, URL_ALPHABET, false)
            .and_then(|bytes| <[u8; N]>::try_from(bytes).ok())
            .ok_or(ErrorClass::InvalidRequest)?;
        Ok(Self {
            bytes,
            text: text.to_owned(),
        })
    }

    /// Encode raw bytes canonically.
    #[must_use]
    pub fn from_bytes(bytes: [u8; N]) -> Self {
        let text = encode_b64u(&bytes);
        Self { bytes, text }
    }

    /// The decoded bytes (always `N` long).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The decoded bytes as a fixed-size array.
    #[must_use]
    pub const fn as_array(&self) -> &[u8; N] {
        &self.bytes
    }

    /// The canonical text form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl<const N: usize> fmt::Debug for B64u<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "B64u<{N}>(..)")
    }
}

/// A canonical `opaque<MAX>` value: 1 to `MAX` decoded bytes, content opaque to the receiver.
///
/// `Debug` prints only the decoded length. Equality compares equal-length decoded values in
/// constant time; encoded length is public.
#[derive(Clone)]
pub struct OpaqueB64u<const MAX: usize> {
    bytes: Vec<u8>,
    text: String,
}

impl<const MAX: usize> PartialEq for OpaqueB64u<MAX> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes.len() == other.bytes.len() && bool::from(self.bytes.ct_eq(&other.bytes))
    }
}

impl<const MAX: usize> Eq for OpaqueB64u<MAX> {}

impl<const MAX: usize> Hash for OpaqueB64u<MAX> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}

impl<const MAX: usize> OpaqueB64u<MAX> {
    /// Parse the canonical encoding of 1 to `MAX` bytes (inclusive).
    ///
    /// # Errors
    /// [`ErrorClass::InvalidRequest`] when empty, too long, or not canonical.
    pub fn parse(text: &str) -> Result<Self, ErrorClass> {
        if text.is_empty() || text.len() > unpadded_len(MAX) {
            return Err(ErrorClass::InvalidRequest);
        }
        let bytes =
            decode_canonical(text, URL_ALPHABET, false).ok_or(ErrorClass::InvalidRequest)?;
        if bytes.is_empty() || bytes.len() > MAX {
            return Err(ErrorClass::InvalidRequest);
        }
        Ok(Self {
            bytes,
            text: text.to_owned(),
        })
    }

    /// The decoded bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The canonical text form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl<const MAX: usize> fmt::Debug for OpaqueB64u<MAX> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "OpaqueB64u<{MAX}>({} bytes)", self.bytes.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn final_character_classes_match_the_profile_table() {
        // 16 bytes end in [AQgw]; 32 bytes end in [AEIMQUYcgkosw048].
        let mut ends16 = std::collections::BTreeSet::new();
        let mut ends32 = std::collections::BTreeSet::new();
        for byte in 0..=255_u8 {
            let mut sixteen = [0_u8; 16];
            sixteen[15] = byte;
            ends16.insert(B64u::from_bytes(sixteen).as_str().as_bytes()[21]);
            let mut thirty_two = [0_u8; 32];
            thirty_two[31] = byte;
            ends32.insert(B64u::from_bytes(thirty_two).as_str().as_bytes()[42]);
        }
        assert_eq!(ends16.into_iter().collect::<Vec<_>>(), b"AQgw");
        assert_eq!(ends32.into_iter().collect::<Vec<_>>(), b"048AEIMQUYcgkosw");
    }

    #[test]
    fn standard_padded_form_is_canonical_and_exact_length() {
        let digest = [0xd2_u8; 32];
        let text = encode_standard(&digest);
        assert_eq!(text.len(), 44);
        assert_eq!(decode_standard_exact::<32>(&text), Some(digest));
        assert_eq!(
            decode_standard_exact::<32>(text.trim_end_matches('=')),
            None
        );
        assert_eq!(decode_standard_exact::<64>(&text), None);
        let mut nonzero_bits = text.into_bytes();
        nonzero_bits[42] = b'1';
        assert_eq!(
            decode_standard_exact::<32>(std::str::from_utf8(&nonzero_bits).unwrap()),
            None
        );
    }

    #[test]
    fn debug_never_prints_value_bytes() {
        let value = B64u::from_bytes([0x41_u8; 16]);
        assert_eq!(format!("{value:?}"), "B64u<16>(..)");
        let opaque = OpaqueB64u::<128>::parse("QUFB").unwrap();
        assert_eq!(format!("{opaque:?}"), "OpaqueB64u<128>(3 bytes)");
    }
}
