//! Exact six-byte interactive SAS derivation, rendering, parsing, and verification.
//!
//! The production library deliberately contains no PGP Word List data. Callers load the separately
//! distributed, GFDL-1.2-only Even and Odd data files through [`SasWordLists::load`]. The loader
//! pins their exact bytes and validates their structure before any rendering or parsing. This keeps
//! the MIT Rust code and the GFDL data boundary explicit.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::ErrorClass;

const SAS_LENGTH: usize = 6;
const NONCE_LENGTH: usize = 32;
const MAX_TRANSCRIPT_LENGTH: usize = 4096;
const MAX_SAS_PHRASE_LENGTH: usize = 65;
const SAS_INFO: &[u8] = b"rem-interactive-enroll-sas-v1";
const EVEN_LENGTH: usize = 2024;
const ODD_LENGTH: usize = 2407;
const EVEN_SHA256: [u8; 32] = [
    0x37, 0xa6, 0x5f, 0x88, 0x51, 0x24, 0x67, 0xed, 0xd1, 0x2a, 0x1a, 0xb3, 0xee, 0xb5, 0xf4, 0x32,
    0x82, 0x30, 0xe8, 0x67, 0x11, 0xa8, 0xef, 0xde, 0x63, 0x33, 0x36, 0x1c, 0xe1, 0x0f, 0x4f, 0xcf,
];
const ODD_SHA256: [u8; 32] = [
    0xc2, 0xf2, 0x3c, 0x22, 0x33, 0xd4, 0xd7, 0x29, 0x11, 0x07, 0xe8, 0xf7, 0x96, 0xc3, 0x74, 0xd0,
    0xcb, 0x1f, 0xb3, 0x0c, 0x13, 0x91, 0xbc, 0xb4, 0xf6, 0x48, 0x02, 0x43, 0xde, 0x8e, 0xbf, 0x5a,
];

/// Validated, borrowed PGP Even and Odd Word Lists.
///
/// The borrowed bytes remain caller-owned and are not compiled into this library. Callers must
/// distribute the two data files with their adjacent GFDL-1.2 license and attribution notice.
#[derive(Clone, Debug)]
pub struct SasWordLists<'a> {
    even: Vec<&'a str>,
    odd: Vec<&'a str>,
}

impl<'a> SasWordLists<'a> {
    /// Load the exact pinned Even and Odd data files from caller-provided bytes.
    ///
    /// The accepted files contain 256 unique ASCII alphabetic words in zero-based order, separated
    /// by LF, with exactly one final LF. Their exact lengths and SHA-256 hashes are checked before
    /// UTF-8 decoding or entry parsing.
    ///
    /// # Errors
    /// [`ErrorClass::InvalidRequest`] when either resource differs from the pinned protocol data or
    /// violates its structural invariants.
    pub fn load(even: &'a [u8], odd: &'a [u8]) -> Result<Self, ErrorClass> {
        let even = load_list(even, EVEN_LENGTH, &EVEN_SHA256)?;
        let odd = load_list(odd, ODD_LENGTH, &ODD_SHA256)?;
        Ok(Self { even, odd })
    }

    fn words(&self, position: usize) -> &[&'a str] {
        if position.is_multiple_of(2) {
            &self.even
        } else {
            &self.odd
        }
    }
}

fn load_list<'a>(
    raw: &'a [u8],
    expected_length: usize,
    expected_sha256: &[u8; 32],
) -> Result<Vec<&'a str>, ErrorClass> {
    if raw.len() != expected_length || Sha256::digest(raw).as_slice() != expected_sha256 {
        return Err(ErrorClass::InvalidRequest);
    }
    let text = std::str::from_utf8(raw).map_err(|_| ErrorClass::InvalidRequest)?;
    let body = text.strip_suffix('\n').ok_or(ErrorClass::InvalidRequest)?;
    if body.ends_with('\n') || body.contains('\r') {
        return Err(ErrorClass::InvalidRequest);
    }
    let words: Vec<_> = body.split('\n').collect();
    if words.len() != 256 {
        return Err(ErrorClass::InvalidRequest);
    }
    for (index, word) in words.iter().enumerate() {
        if word.is_empty()
            || !word.bytes().all(|byte| byte.is_ascii_alphabetic())
            || words[..index].contains(word)
        {
            return Err(ErrorClass::InvalidRequest);
        }
    }
    Ok(words)
}

/// Derive the exact six authentication bytes for an interactive-enrollment transcript.
///
/// This computes `HKDF-SHA-256` with `SHA-256(transcript)` as the salt,
/// `reporter_nonce || core_nonce` as the input keying material, the fixed info string
/// `rem-interactive-enroll-sas-v1`, and output length six.
///
/// # Errors
/// [`ErrorClass::InvalidRequest`] when the transcript is empty or longer than 4096 bytes, or either
/// nonce is not exactly 32 bytes.
pub fn derive_interactive_sas(
    transcript: &[u8],
    reporter_nonce: &[u8],
    core_nonce: &[u8],
) -> Result<[u8; SAS_LENGTH], ErrorClass> {
    if transcript.is_empty()
        || transcript.len() > MAX_TRANSCRIPT_LENGTH
        || reporter_nonce.len() != NONCE_LENGTH
        || core_nonce.len() != NONCE_LENGTH
    {
        return Err(ErrorClass::InvalidRequest);
    }

    let salt = Sha256::digest(transcript);
    let mut input_keying_material = [0_u8; NONCE_LENGTH * 2];
    input_keying_material[..NONCE_LENGTH].copy_from_slice(reporter_nonce);
    input_keying_material[NONCE_LENGTH..].copy_from_slice(core_nonce);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &input_keying_material);
    let mut output = [0_u8; SAS_LENGTH];
    hkdf.expand(SAS_INFO, &mut output)
        .map_err(|_| ErrorClass::InvalidRequest)?;
    Ok(output)
}

/// Render six bytes as `Even[b0] Odd[b1] Even[b2] Odd[b3] Even[b4] Odd[b5]`.
///
/// The six exact ASCII words are joined by one U+0020 SPACE. This profile extends RFC 6189's
/// two-word B256 display to six bytes and six words; it does not claim that the extension is an
/// RFC 6189 protocol.
///
/// # Errors
/// [`ErrorClass::InvalidRequest`] when `value` is not exactly six bytes.
pub fn render_sas(lists: &SasWordLists<'_>, value: &[u8]) -> Result<String, ErrorClass> {
    if value.len() != SAS_LENGTH {
        return Err(ErrorClass::InvalidRequest);
    }
    let mut phrase = String::with_capacity(MAX_SAS_PHRASE_LENGTH);
    for (position, index) in value.iter().copied().enumerate() {
        if position != 0 {
            phrase.push(' ');
        }
        phrase.push_str(lists.words(position)[usize::from(index)]);
    }
    debug_assert!(phrase.is_ascii() && phrase.len() <= MAX_SAS_PHRASE_LENGTH);
    Ok(phrase)
}

/// Parse one exact canonical six-word ASCII SAS phrase without normalization.
///
/// The 65-byte cap is applied before splitting. Case, punctuation, Unicode, tabs, newlines,
/// leading or trailing spaces, repeated spaces, and words from the wrong parity list are rejected.
///
/// # Errors
/// [`ErrorClass::InvalidRequest`] for any non-canonical phrase.
pub fn parse_sas(lists: &SasWordLists<'_>, phrase: &str) -> Result<[u8; SAS_LENGTH], ErrorClass> {
    if phrase.len() > MAX_SAS_PHRASE_LENGTH || !phrase.is_ascii() {
        return Err(ErrorClass::InvalidRequest);
    }

    let mut output = [0_u8; SAS_LENGTH];
    let mut words = phrase.split(' ');
    for (position, slot) in output.iter_mut().enumerate() {
        let word = words.next().ok_or(ErrorClass::InvalidRequest)?;
        let index = lists
            .words(position)
            .iter()
            .position(|candidate| *candidate == word)
            .ok_or(ErrorClass::InvalidRequest)?;
        *slot = u8::try_from(index).map_err(|_| ErrorClass::InvalidRequest)?;
    }
    if words.next().is_some() {
        return Err(ErrorClass::InvalidRequest);
    }
    Ok(output)
}

/// Verify a canonical SAS phrase against expected authentication bytes.
///
/// The authentication bytes are compared in constant time after strict parsing.
///
/// # Errors
/// [`ErrorClass::InvalidRequest`] when `expected` is not six bytes or `phrase` is malformed;
/// [`ErrorClass::AuthenticationRequired`] when a well-formed phrase represents different bytes.
pub fn verify_sas(
    lists: &SasWordLists<'_>,
    expected: &[u8],
    phrase: &str,
) -> Result<(), ErrorClass> {
    if expected.len() != SAS_LENGTH {
        return Err(ErrorClass::InvalidRequest);
    }
    let supplied = parse_sas(lists, phrase)?;
    if bool::from(expected.ct_eq(&supplied)) {
        Ok(())
    } else {
        Err(ErrorClass::AuthenticationRequired)
    }
}
