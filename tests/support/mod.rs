#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub const FIXTURE_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/protocol/v1");

pub fn fixture(relative: &str) -> Vec<u8> {
    fs::read(Path::new(FIXTURE_ROOT).join(relative))
        .expect("vendored protocol fixture must be readable")
}

pub fn fixture_text(relative: &str) -> String {
    String::from_utf8(fixture(relative)).expect("protocol fixtures are UTF-8")
}

pub fn fixture_files() -> Vec<String> {
    fn visit(root: &Path, directory: &Path, output: &mut Vec<String>) {
        let mut entries: Vec<_> = fs::read_dir(directory)
            .expect("fixture directory must be readable")
            .map(|entry| entry.expect("fixture entry must be readable"))
            .collect();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            if path.is_dir() {
                visit(root, &path, output);
            } else {
                output.push(
                    path.strip_prefix(root)
                        .expect("fixture must remain under root")
                        .to_string_lossy()
                        .replace('\\', "/"),
                );
            }
        }
    }

    let root = PathBuf::from(FIXTURE_ROOT);
    let mut output = Vec::new();
    visit(&root, &root, &mut output);
    output
}

pub fn hex_decode(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "hex fixture has odd length");
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).expect("hex high nibble");
            let low = (pair[1] as char).to_digit(16).expect("hex low nibble");
            ((high << 4) | low) as u8
        })
        .collect()
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

const BASE64_STANDARD_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE64_URL_SAFE_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Base64Alphabet {
    Standard,
    UrlSafe,
}

impl Base64Alphabet {
    const fn bytes(self) -> &'static [u8; 64] {
        match self {
            Self::Standard => BASE64_STANDARD_ALPHABET,
            Self::UrlSafe => BASE64_URL_SAFE_ALPHABET,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Base64Padding {
    Padded,
    Unpadded,
}

pub fn base64url_encode_unpadded(bytes: &[u8]) -> String {
    encode_base64(bytes, Base64Alphabet::UrlSafe, Base64Padding::Unpadded)
}

pub fn base64_standard_encode_padded(bytes: &[u8]) -> String {
    encode_base64(bytes, Base64Alphabet::Standard, Base64Padding::Padded)
}

fn encode_base64(bytes: &[u8], alphabet: Base64Alphabet, padding: Base64Padding) -> String {
    let alphabet = alphabet.bytes();
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        output.push(alphabet[((value >> 18) & 63) as usize] as char);
        output.push(alphabet[((value >> 12) & 63) as usize] as char);
        if chunk.len() >= 2 {
            output.push(alphabet[((value >> 6) & 63) as usize] as char);
        } else if padding == Base64Padding::Padded {
            output.push('=');
        }
        if chunk.len() == 3 {
            output.push(alphabet[(value & 63) as usize] as char);
        } else if padding == Base64Padding::Padded {
            output.push('=');
        }
    }
    output
}

pub fn base64url_decode(text: &str) -> Vec<u8> {
    decode_base64(text, Base64Alphabet::UrlSafe)
}

pub fn base64_standard_decode(text: &str) -> Vec<u8> {
    decode_base64(text, Base64Alphabet::Standard)
}

fn decode_base64(text: &str, alphabet: Base64Alphabet) -> Vec<u8> {
    fn digit(byte: u8, alphabet: Base64Alphabet) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'-' if alphabet == Base64Alphabet::UrlSafe => Some(62),
            b'_' if alphabet == Base64Alphabet::UrlSafe => Some(63),
            b'+' if alphabet == Base64Alphabet::Standard => Some(62),
            b'/' if alphabet == Base64Alphabet::Standard => Some(63),
            _ => None,
        }
    }

    let bytes = text.trim_end_matches('=').as_bytes();
    assert_ne!(bytes.len() % 4, 1, "invalid base64 fixture length");
    let mut output = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut value = 0_u32;
        for &byte in chunk {
            value = (value << 6) | u32::from(digit(byte, alphabet).expect("base64 digit"));
        }
        value <<= 6 * (4 - chunk.len());
        output.push((value >> 16) as u8);
        if chunk.len() >= 3 {
            output.push((value >> 8) as u8);
        }
        if chunk.len() == 4 {
            output.push(value as u8);
        }
    }
    output
}

pub fn sha256(input: &[u8]) -> [u8; 32] {
    const INITIAL: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let bit_len = (input.len() as u64) * 8;
    let mut padded = input.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut state = INITIAL;
    for block in padded.as_chunks::<64>().0 {
        let mut words = [0_u32; 64];
        for (index, chunk) in block.as_chunks::<4>().0.iter().enumerate() {
            words[index] = u32::from_be_bytes(*chunk);
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let sigma1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let first = h
                .wrapping_add(sigma1)
                .wrapping_add(choose)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let sigma0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let second = sigma0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(first);
            d = c;
            c = b;
            b = a;
            a = first.wrapping_add(second);
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }

    let mut output = [0_u8; 32];
    for (chunk, word) in output.as_chunks_mut::<4>().0.iter_mut().zip(state) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    output
}

#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Json>),
    Object(BTreeMap<String, Json>),
}

impl Json {
    pub fn object(&self) -> &BTreeMap<String, Json> {
        match self {
            Self::Object(value) => value,
            _ => panic!("expected JSON object"),
        }
    }

    pub fn array(&self) -> &[Json] {
        match self {
            Self::Array(value) => value,
            _ => panic!("expected JSON array"),
        }
    }

    pub fn string(&self) -> &str {
        match self {
            Self::String(value) => value,
            _ => panic!("expected JSON string"),
        }
    }

    pub fn member(&self, name: &str) -> &Json {
        self.object()
            .get(name)
            .unwrap_or_else(|| panic!("missing JSON member {name}"))
    }
}

struct JsonParser<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> JsonParser<'a> {
    fn whitespace(&mut self) {
        while self.bytes.get(self.at).is_some_and(u8::is_ascii_whitespace) {
            self.at += 1;
        }
    }
    fn value(&mut self) -> Json {
        self.whitespace();
        match self
            .bytes
            .get(self.at)
            .copied()
            .expect("unexpected end of JSON")
        {
            b'n' => {
                self.literal(b"null");
                Json::Null
            }
            b't' => {
                self.literal(b"true");
                Json::Bool(true)
            }
            b'f' => {
                self.literal(b"false");
                Json::Bool(false)
            }
            b'"' => Json::String(self.string()),
            b'[' => self.array(),
            b'{' => self.object(),
            b'-' | b'0'..=b'9' => self.number(),
            byte => panic!("unexpected JSON byte {byte:#x} at {}", self.at),
        }
    }
    fn literal(&mut self, value: &[u8]) {
        assert_eq!(&self.bytes[self.at..self.at + value.len()], value);
        self.at += value.len();
    }
    fn string(&mut self) -> String {
        assert_eq!(self.bytes[self.at], b'"');
        self.at += 1;
        let mut output = String::new();
        loop {
            let start = self.at;
            while !matches!(self.bytes[self.at], b'"' | b'\\') {
                self.at += 1;
            }
            output.push_str(
                std::str::from_utf8(&self.bytes[start..self.at]).expect("UTF-8 JSON string"),
            );
            match self.bytes[self.at] {
                b'"' => {
                    self.at += 1;
                    return output;
                }
                b'\\' => {
                    self.at += 1;
                    match self.bytes[self.at] {
                        b'"' => output.push('"'),
                        b'\\' => output.push('\\'),
                        b'/' => output.push('/'),
                        b'b' => output.push('\u{0008}'),
                        b'f' => output.push('\u{000c}'),
                        b'n' => output.push('\n'),
                        b'r' => output.push('\r'),
                        b't' => output.push('\t'),
                        b'u' => {
                            let code = u16::from_str_radix(
                                std::str::from_utf8(&self.bytes[self.at + 1..self.at + 5])
                                    .expect("Unicode escape"),
                                16,
                            )
                            .expect("Unicode escape digits");
                            output.push(
                                char::from_u32(u32::from(code)).expect("scalar Unicode escape"),
                            );
                            self.at += 4;
                        }
                        byte => panic!("unsupported JSON escape {byte:#x}"),
                    }
                    self.at += 1;
                }
                _ => unreachable!(),
            }
        }
    }
    fn number(&mut self) -> Json {
        let start = self.at;
        while self
            .bytes
            .get(self.at)
            .is_some_and(|byte| matches!(byte, b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9'))
        {
            self.at += 1;
        }
        Json::Number(
            std::str::from_utf8(&self.bytes[start..self.at])
                .expect("ASCII JSON number")
                .to_owned(),
        )
    }
    fn array(&mut self) -> Json {
        self.at += 1;
        let mut output = Vec::new();
        loop {
            self.whitespace();
            if self.bytes[self.at] == b']' {
                self.at += 1;
                return Json::Array(output);
            }
            output.push(self.value());
            self.whitespace();
            match self.bytes[self.at] {
                b',' => self.at += 1,
                b']' => {}
                _ => panic!("array separator"),
            }
        }
    }
    fn object(&mut self) -> Json {
        self.at += 1;
        let mut output = BTreeMap::new();
        loop {
            self.whitespace();
            if self.bytes[self.at] == b'}' {
                self.at += 1;
                return Json::Object(output);
            }
            let key = self.string();
            self.whitespace();
            assert_eq!(self.bytes[self.at], b':');
            self.at += 1;
            assert!(
                output.insert(key, self.value()).is_none(),
                "duplicate JSON member in fixture"
            );
            self.whitespace();
            match self.bytes[self.at] {
                b',' => self.at += 1,
                b'}' => {}
                _ => panic!("object separator"),
            }
        }
    }
}

pub fn parse_json(bytes: &[u8]) -> Json {
    let mut parser = JsonParser { bytes, at: 0 };
    let value = parser.value();
    parser.whitespace();
    assert_eq!(parser.at, bytes.len(), "trailing JSON bytes");
    value
}

pub fn named_value<'a>(case: &'a Json, section: &str, name: &str) -> &'a str {
    case.member(section)
        .array()
        .iter()
        .find(|item| item.member("name").string() == name)
        .unwrap_or_else(|| panic!("missing {section} named value {name}"))
        .member("value")
        .string()
}

pub fn optional_named_value<'a>(case: &'a Json, section: &str, name: &str) -> Option<&'a str> {
    case.member(section)
        .array()
        .iter()
        .find(|item| item.member("name").string() == name)
        .map(|item| item.member("value").string())
}

pub fn vector_case<'a>(set: &'a Json, id: &str) -> &'a Json {
    set.member("cases")
        .array()
        .iter()
        .find(|case| case.member("id").string() == id)
        .unwrap_or_else(|| panic!("missing vector case {id}"))
}
