//! The bounded `REM-TRANSCRIPT` length-delimited encoding (wire profile section 3).
//!
//! ```text
//! "REM-TRANSCRIPT" || 0x01 || u16be(len(purpose)) || purpose
//!   || for each field: u16be(len(name)) || name || u32be(len(value)) || value
//! ```
//!
//! [`encode_transcript`] requires the purpose and every field name to be non-empty visible ASCII
//! and at most `u16::MAX` bytes. [`TranscriptField::new`] only constructs a candidate and does not
//! validate its name. Values are raw bytes (an absent optional value is the zero-length value). The
//! encoder rejects duplicate names and any output over the caller's cap before allocating it, so
//! every encoding it returns is the single canonical form.

use super::ErrorClass;

const MAGIC: &[u8; 14] = b"REM-TRANSCRIPT";
const VERSION: u8 = 0x01;

/// One named transcript field.
#[derive(Clone, Copy, Debug)]
pub struct TranscriptField<'a> {
    name: &'a str,
    value: &'a [u8],
}

impl<'a> TranscriptField<'a> {
    /// Construct a candidate field with raw value bytes.
    ///
    /// [`encode_transcript`] validates `name` as a non-empty visible-ASCII label of at most
    /// `u16::MAX` bytes.
    #[must_use]
    pub const fn new(name: &'a str, value: &'a [u8]) -> Self {
        Self { name, value }
    }
}

/// One field decoded from an exact transcript.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedTranscriptField<'a> {
    name: &'a str,
    value: &'a [u8],
}

impl<'a> DecodedTranscriptField<'a> {
    /// The field name exactly as received.
    #[must_use]
    pub const fn name(&self) -> &'a str {
        self.name
    }

    /// The raw field value exactly as received.
    #[must_use]
    pub const fn value(&self) -> &'a [u8] {
        self.value
    }
}

fn is_label(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= usize::from(u16::MAX)
        && text.bytes().all(|byte| byte.is_ascii_graphic())
}

/// Encode `fields` under `purpose`, refusing any result longer than `max_bytes`.
///
/// # Errors
/// [`ErrorClass::InvalidRequest`] when the purpose or a name is not a non-empty visible-ASCII label
/// of at most `u16::MAX` bytes, a name is duplicated, a value is longer than `u32::MAX`, or the
/// encoding is longer than `max_bytes`.
pub fn encode_transcript(
    purpose: &str,
    fields: &[TranscriptField<'_>],
    max_bytes: usize,
) -> Result<Vec<u8>, ErrorClass> {
    if !is_label(purpose) {
        return Err(ErrorClass::InvalidRequest);
    }
    let mut total = MAGIC.len() + 1 + 2 + purpose.len();
    if total > max_bytes {
        return Err(ErrorClass::InvalidRequest);
    }
    for (index, field) in fields.iter().enumerate() {
        if !is_label(field.name)
            || u32::try_from(field.value.len()).is_err()
            || fields[..index]
                .iter()
                .any(|earlier| earlier.name == field.name)
        {
            return Err(ErrorClass::InvalidRequest);
        }
        total = total
            .checked_add(2 + field.name.len() + 4)
            .and_then(|total| total.checked_add(field.value.len()))
            .ok_or(ErrorClass::InvalidRequest)?;
        // Stop as soon as the cap is exceeded. This also bounds the quadratic duplicate-name
        // check above when a caller supplies an attacker-controlled field list.
        if total > max_bytes {
            return Err(ErrorClass::InvalidRequest);
        }
    }

    let mut output = Vec::with_capacity(total);
    output.extend_from_slice(MAGIC);
    output.push(VERSION);
    push_u16_prefixed(&mut output, purpose.as_bytes());
    for field in fields {
        push_u16_prefixed(&mut output, field.name.as_bytes());
        // Both lengths were bounded above, so these conversions cannot fail.
        let length = u32::try_from(field.value.len()).map_err(|_| ErrorClass::InvalidRequest)?;
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(field.value);
    }
    debug_assert_eq!(output.len(), total);
    Ok(output)
}

/// Decode a bounded transcript against one exact purpose and ordered field-name list.
///
/// Unknown, duplicate, omitted, reordered, overlong, truncated, or non-canonical fields are
/// rejected. Values remain borrowed from `raw`; no attacker-controlled value allocation occurs.
///
/// # Errors
/// [`ErrorClass::InvalidRequest`] for any byte sequence other than the one exact transcript form.
pub fn decode_transcript<'a>(
    raw: &'a [u8],
    purpose: &str,
    expected_fields: &[&str],
    max_bytes: usize,
) -> Result<Vec<DecodedTranscriptField<'a>>, ErrorClass> {
    if raw.len() > max_bytes
        || !is_label(purpose)
        || expected_fields
            .iter()
            .enumerate()
            .any(|(index, name)| !is_label(name) || expected_fields[..index].contains(name))
    {
        return Err(ErrorClass::InvalidRequest);
    }

    let mut cursor = 0;
    let take = |cursor: &mut usize, length: usize| -> Result<&'a [u8], ErrorClass> {
        let end = cursor
            .checked_add(length)
            .filter(|end| *end <= raw.len())
            .ok_or(ErrorClass::InvalidRequest)?;
        let value = &raw[*cursor..end];
        *cursor = end;
        Ok(value)
    };

    if take(&mut cursor, MAGIC.len())? != MAGIC || take(&mut cursor, 1)? != [VERSION] {
        return Err(ErrorClass::InvalidRequest);
    }
    let purpose_length = usize::from(u16::from_be_bytes(
        take(&mut cursor, 2)?
            .try_into()
            .map_err(|_| ErrorClass::InvalidRequest)?,
    ));
    if take(&mut cursor, purpose_length)? != purpose.as_bytes() {
        return Err(ErrorClass::InvalidRequest);
    }

    let mut decoded = Vec::with_capacity(expected_fields.len());
    for expected_name in expected_fields {
        let name_length = usize::from(u16::from_be_bytes(
            take(&mut cursor, 2)?
                .try_into()
                .map_err(|_| ErrorClass::InvalidRequest)?,
        ));
        let name_bytes = take(&mut cursor, name_length)?;
        if name_bytes != expected_name.as_bytes() {
            return Err(ErrorClass::InvalidRequest);
        }
        let value_length = usize::try_from(u32::from_be_bytes(
            take(&mut cursor, 4)?
                .try_into()
                .map_err(|_| ErrorClass::InvalidRequest)?,
        ))
        .map_err(|_| ErrorClass::InvalidRequest)?;
        let value = take(&mut cursor, value_length)?;
        let name = std::str::from_utf8(name_bytes).map_err(|_| ErrorClass::InvalidRequest)?;
        decoded.push(DecodedTranscriptField { name, value });
    }
    if cursor != raw.len() {
        return Err(ErrorClass::InvalidRequest);
    }
    Ok(decoded)
}

fn push_u16_prefixed(output: &mut Vec<u8>, text: &[u8]) {
    let length = u16::try_from(text.len()).unwrap_or(u16::MAX);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(text);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_value_is_zero_length_and_empty_names_are_rejected() {
        let encoded = encode_transcript("p", &[TranscriptField::new("a", b"")], 64).unwrap();
        assert_eq!(&encoded[encoded.len() - 7..], b"\x00\x01a\x00\x00\x00\x00");
        assert_eq!(
            encode_transcript("", &[], 64),
            Err(ErrorClass::InvalidRequest)
        );
        assert_eq!(
            encode_transcript("p", &[], MAGIC.len() + VERSION as usize),
            Err(ErrorClass::InvalidRequest)
        );
        assert_eq!(
            encode_transcript("p", &[TranscriptField::new("", b"x")], 64),
            Err(ErrorClass::InvalidRequest)
        );
        assert_eq!(
            encode_transcript("p q", &[], 64),
            Err(ErrorClass::InvalidRequest)
        );
    }
}
