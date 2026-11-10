//! Exact `rem-canonical-json-v1` byte-form checks (wire profile section 2).
//!
//! The profile admits exactly one byte form per value, so a receiver verifies canonical form and
//! then keeps the received bytes; it never re-serializes. Accepted:
//!
//! - UTF-8 without BOM, no insignificant whitespace, nesting depth at most 8, any top-level JSON
//!   value, at most 64 KiB (the largest route cap);
//! - object member names that are ASCII and strictly increasing in byte order (so no duplicates);
//! - strings with only the canonical escapes (`\"`, `\\`, `\b \t \n \f \r`, and lowercase `\u00xx`
//!   for other code points below U+0020) and every other code point literal;
//! - `true`, `false`, `null`;
//! - non-negative integers in canonical decimal within the `uint64` range, optionally followed by a
//!   1–6 digit fraction whose last digit is not `0` (`rem-decimal-3` / `rem-decimal-6`).
//!
//! Signs, exponents, `-0`, NaN and infinities never occur. Field-specific ranges and the narrower
//! per-field fraction limits belong to schema validation, which is not part of this module.

use std::{fmt, ops::Range};

use super::ErrorClass;

/// Largest canonical JSON value accepted (the 64 KiB roster success-body cap).
pub const MAX_CANONICAL_JSON_BYTES: usize = 64 * 1024;
/// Maximum container nesting depth.
pub const MAX_DEPTH: usize = 8;
const MAX_FRACTION_DIGITS: usize = 6;

/// A value whose bytes are exactly the canonical profile encoding.
#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalJson {
    bytes: Vec<u8>,
    /// Source-name and value byte ranges of the top-level object members.
    top_level: Vec<(Range<usize>, Range<usize>)>,
}

impl fmt::Debug for CanonicalJson {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalJson")
            .field("bytes_len", &self.bytes.len())
            .finish()
    }
}

impl CanonicalJson {
    /// Accept `bytes` only when they are already the canonical encoding.
    ///
    /// # Errors
    /// [`ErrorClass::InvalidRequest`] for any non-canonical, malformed, oversized, or too deeply
    /// nested input.
    pub fn parse_exact(bytes: &[u8]) -> Result<Self, ErrorClass> {
        if bytes.len() > MAX_CANONICAL_JSON_BYTES || std::str::from_utf8(bytes).is_err() {
            return Err(ErrorClass::InvalidRequest);
        }
        let mut parser = Parser {
            bytes,
            at: 0,
            top_level: Vec::new(),
        };
        parser.value(0).ok_or(ErrorClass::InvalidRequest)?;
        if parser.at != bytes.len() {
            return Err(ErrorClass::InvalidRequest);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            top_level: parser.top_level,
        })
    }

    /// The exact canonical bytes (identical to the accepted input).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The raw canonical bytes of top-level member `name`, if the value is an object holding it.
    #[must_use]
    pub fn top_level_member(&self, name: &str) -> Option<&[u8]> {
        name.is_ascii().then_some(())?;
        self.top_level
            .iter()
            .find(|(member, _)| {
                decode_ascii_name(&self.bytes[member.clone()]).as_deref() == Some(name.as_bytes())
            })
            .map(|(_, value)| &self.bytes[value.clone()])
    }
}

fn decode_ascii_name(source: &[u8]) -> Option<Vec<u8>> {
    let mut decoded = Vec::with_capacity(source.len());
    let mut at = 0;
    while let Some(&byte) = source.get(at) {
        if byte != b'\\' {
            if !byte.is_ascii() {
                return None;
            }
            decoded.push(byte);
            at += 1;
            continue;
        }

        match source.get(at + 1).copied()? {
            b'"' => decoded.push(b'"'),
            b'\\' => decoded.push(b'\\'),
            b'b' => decoded.push(0x08),
            b't' => decoded.push(0x09),
            b'n' => decoded.push(0x0a),
            b'f' => decoded.push(0x0c),
            b'r' => decoded.push(0x0d),
            b'u' => {
                let [b'0', b'0', high @ (b'0' | b'1'), low] = *source.get(at + 2..at + 6)? else {
                    return None;
                };
                let low = match low {
                    b'0'..=b'9' => low - b'0',
                    b'a'..=b'f' => low - b'a' + 10,
                    _ => return None,
                };
                decoded.push(((high - b'0') << 4) | low);
                at += 4;
            }
            _ => return None,
        }
        at += 2;
    }
    Some(decoded)
}

struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
    top_level: Vec<(Range<usize>, Range<usize>)>,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn eat(&mut self, expected: u8) -> Option<()> {
        (self.peek()? == expected).then(|| self.at += 1)
    }

    fn value(&mut self, depth: usize) -> Option<()> {
        match self.peek()? {
            b'{' => self.object(depth + 1),
            b'[' => self.array(depth + 1),
            b'"' => self.string().map(|_| ()),
            b't' => self.literal(b"true"),
            b'f' => self.literal(b"false"),
            b'n' => self.literal(b"null"),
            b'0'..=b'9' => self.number(),
            _ => None,
        }
    }

    fn literal(&mut self, literal: &[u8]) -> Option<()> {
        let end = self.at.checked_add(literal.len())?;
        (self.bytes.get(self.at..end)? == literal).then(|| self.at = end)
    }

    fn number(&mut self) -> Option<()> {
        let start = self.at;
        while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.at += 1;
        }
        // Canonical uint64 integer part.
        super::parse_canonical_u64(&self.bytes[start..self.at])?;
        if self.peek() == Some(b'.') {
            self.at += 1;
            let fraction = self.at;
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.at += 1;
            }
            let digits = &self.bytes[fraction..self.at];
            if digits.is_empty() || digits.len() > MAX_FRACTION_DIGITS || digits.ends_with(b"0") {
                return None;
            }
        }
        // Exponents and any other continuation are rejected by the caller's grammar.
        Some(())
    }

    /// Parse a canonical string; returns the byte range of its raw (escaped) content.
    fn string(&mut self) -> Option<Range<usize>> {
        self.eat(b'"')?;
        let start = self.at;
        loop {
            match self.peek()? {
                b'"' => {
                    let range = start..self.at;
                    self.at += 1;
                    return Some(range);
                }
                b'\\' => {
                    self.at += 1;
                    match self.peek()? {
                        b'"' | b'\\' | b'b' | b't' | b'n' | b'f' | b'r' => self.at += 1,
                        b'u' => {
                            let end = self.at.checked_add(5)?;
                            let escape = self.bytes.get(self.at + 1..end)?;
                            let [b'0', b'0', high @ (b'0' | b'1'), low] = *escape else {
                                return None;
                            };
                            let low = match low {
                                b'0'..=b'9' => low - b'0',
                                b'a'..=b'f' => low - b'a' + 10,
                                _ => return None,
                            };
                            let code = ((high - b'0') << 4) | low;
                            // These five have short escapes, which are the canonical form.
                            if matches!(code, 0x08 | 0x09 | 0x0a | 0x0c | 0x0d) {
                                return None;
                            }
                            self.at = end;
                        }
                        _ => return None,
                    }
                }
                0x00..=0x1f => return None,
                _ => self.at += 1,
            }
        }
    }

    fn array(&mut self, depth: usize) -> Option<()> {
        if depth > MAX_DEPTH {
            return None;
        }
        self.eat(b'[')?;
        if self.eat(b']').is_some() {
            return Some(());
        }
        loop {
            self.value(depth)?;
            match self.peek()? {
                b',' => self.at += 1,
                b']' => {
                    self.at += 1;
                    return Some(());
                }
                _ => return None,
            }
        }
    }

    fn object(&mut self, depth: usize) -> Option<()> {
        if depth > MAX_DEPTH {
            return None;
        }
        self.eat(b'{')?;
        if self.eat(b'}').is_some() {
            return Some(());
        }
        let mut previous: Option<Vec<u8>> = None;
        loop {
            let name = self.string()?;
            let decoded_name = decode_ascii_name(&self.bytes[name.clone()])?;
            if let Some(previous) = &previous
                && previous >= &decoded_name
            {
                return None;
            }
            self.eat(b':')?;
            let value_start = self.at;
            self.value(depth)?;
            if depth == 1 {
                self.top_level.push((name, value_start..self.at));
            }
            previous = Some(decoded_name);
            match self.peek()? {
                b',' => self.at += 1,
                b'}' => {
                    self.at += 1;
                    return Some(());
                }
                _ => return None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rejects(bytes: &[u8]) {
        assert_eq!(
            CanonicalJson::parse_exact(bytes),
            Err(ErrorClass::InvalidRequest),
            "{}",
            String::from_utf8_lossy(bytes)
        );
    }

    #[test]
    fn string_escapes_are_only_the_canonical_forms() {
        // U+007F is not a control below U+0020, so it must be literal rather than escaped.
        rejects(br#"{"a":"\u007f"}"#);
        let accepted = "{\"a\":\"\\\"\\\\\\b\\t\\n\\f\\r\\u0000\\u001f\u{7f}é\"}";
        assert!(CanonicalJson::parse_exact(accepted.as_bytes()).is_ok());
        for rejected in [
            br#"{"a":"\/"}"#.as_slice(),
            br#"{"a":"\u0041"}"#,
            br#"{"a":"\u000a"}"#,
            br#"{"a":"\u001F"}"#,
            b"{\"a\":\"\x01\"}",
            br#"{"a":"\x"}"#,
        ] {
            rejects(rejected);
        }
    }

    #[test]
    fn numbers_follow_the_bounded_decimal_grammar() {
        for accepted in [
            br#"[0,12,12.5,0.001,18446744073709551615,1.000001]"#.as_slice(),
            br#"{"":0}"#,
        ] {
            assert!(CanonicalJson::parse_exact(accepted).is_ok());
        }
        for rejected in [
            b"[-1]".as_slice(),
            b"[-0]",
            b"[+1]",
            b"[1.]",
            b"[.5]",
            b"[1.0]",
            b"[1.0000001]",
            b"[1e3]",
            b"[18446744073709551616]",
            b"[NaN]",
        ] {
            rejects(rejected);
        }
    }

    #[test]
    fn structure_depth_names_and_trailing_bytes_are_exact() {
        assert!(CanonicalJson::parse_exact(b"[[[[[[[[0]]]]]]]]").is_ok());
        assert!(CanonicalJson::parse_exact(br#""top""#).is_ok());
        assert!(CanonicalJson::parse_exact(b"0").is_ok());
        for rejected in [
            b"[[[[[[[[[0]]]]]]]]]".as_slice(),
            b"{}\n",
            b"{} ",
            b"[1,]",
            b"{\"a\":1,}",
            b"{\"b\":1,\"a\":2}",
            b"{\"a\":1,\"a\":1}",
            "{\"é\":1}".as_bytes(),
            b"{\"\\u0061\":1}",
            b"",
            b"[\xff]",
        ] {
            rejects(rejected);
        }
        rejects(&vec![b' '; MAX_CANONICAL_JSON_BYTES + 1]);
    }

    #[test]
    fn canonical_size_cap_accepts_the_boundary_and_rejects_one_byte_over() {
        let mut at_limit = br#"{"a":""#.to_vec();
        at_limit.extend(std::iter::repeat_n(
            b'a',
            MAX_CANONICAL_JSON_BYTES - br#"{"a":""#.len() - br#""}"#.len(),
        ));
        at_limit.extend_from_slice(br#""}"#);
        assert_eq!(at_limit.len(), MAX_CANONICAL_JSON_BYTES);
        assert!(CanonicalJson::parse_exact(&at_limit).is_ok());

        at_limit.insert(at_limit.len() - 2, b'a');
        assert_eq!(at_limit.len(), MAX_CANONICAL_JSON_BYTES + 1);
        rejects(&at_limit);
    }

    #[test]
    fn top_level_member_returns_raw_value_bytes() {
        let json = CanonicalJson::parse_exact(br#"{"mode":"managed","n":{"mode":"x"}}"#).unwrap();
        assert_eq!(
            json.top_level_member("mode"),
            Some(br#""managed""#.as_slice())
        );
        assert_eq!(
            json.top_level_member("n"),
            Some(br#"{"mode":"x"}"#.as_slice())
        );
        assert_eq!(json.top_level_member("x"), None);
    }
}
