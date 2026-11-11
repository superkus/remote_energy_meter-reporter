//! Network-free Rust side of the pinned protocol-v1 SAS parity demonstration.
//!
//! The two GFDL-1.2-only PGP Word List files remain caller-provided resources and are never
//! embedded in the MIT production library binary.

use std::env;
use std::fs::File;
use std::io::Read;
use std::process::ExitCode;

use remote_energy_meter_reporter::protocol_v1::sas::{
    SasWordLists, derive_interactive_sas, render_sas,
};
use remote_energy_meter_reporter::protocol_v1::transcript::{TranscriptField, encode_transcript};

const PUBLIC_JWK: &[u8] = br#"{"crv":"P-256","kty":"EC","x":"qXlTk75KQKYN-PBJPDM4qHw8tYKgDLaqixcHrthpc_U","y":"tdXohmn4d0O78ACF989uLrxgHWAryPJteiOQIvBjRDo"}"#;
const INTERACTIVE_PURPOSE: &str = "rem-interactive-enroll-v1";
const REPORTER_NONCE: [u8; 32] = [0x11; 32];
const CORE_NONCE: [u8; 32] = [0x22; 32];
const MAX_WORD_LIST_LENGTH: usize = 2407;

fn decode_hex<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), N * 2);
    let mut output = [0_u8; N];
    let (pairs, remainder) = text.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty());
    for (slot, pair) in output.iter_mut().zip(pairs) {
        let digit = |byte: u8| match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("fixed vector contains invalid hex"),
        };
        *slot = (digit(pair[0]) << 4) | digit(pair[1]);
    }
    output
}

fn vector_transcript() -> Vec<u8> {
    let schema_version = [1_u8];
    let trust_anchor = [0xa5_u8; 32];
    let thumbprint =
        decode_hex::<32>("5ef5d38f326668a5c96967e9b15f66507e0ad8fa4017a4a35a385b70237d7485");
    let reporter_commitment =
        decode_hex::<32>("cfd78a510b6c515f45e12942998dbc9dfc507d2c253211d543661bcfda4479ce");
    let core_commitment =
        decode_hex::<32>("4a0233d29a62d7bc471abd46d964d8ebc42b19d8170b570dfd35f4c2862b07d7");
    let expires_at = 1_767_226_200_u64.to_be_bytes();
    encode_transcript(
        INTERACTIVE_PURPOSE,
        &[
            TranscriptField::new("schema_version", &schema_version),
            TranscriptField::new("purpose", INTERACTIVE_PURPOSE.as_bytes()),
            TranscriptField::new("instance_id", b"instance-a"),
            TranscriptField::new("server_identity", b"https://ha.example.com:58443"),
            TranscriptField::new("trust_mode", b"ca-spki-sha256"),
            TranscriptField::new("trust_anchor_spki_sha256", &trust_anchor),
            TranscriptField::new("proposed_reporter_jwk", PUBLIC_JWK),
            TranscriptField::new("proposed_reporter_thumbprint", &thumbprint),
            TranscriptField::new("reporter_commitment", &reporter_commitment),
            TranscriptField::new("core_commitment", &core_commitment),
            TranscriptField::new("reporter_nonce", &REPORTER_NONCE),
            TranscriptField::new("core_nonce", &CORE_NONCE),
            TranscriptField::new("expires_at", &expires_at),
        ],
        4096,
    )
    .expect("the fixed published transcript must encode")
}

fn read_word_list_from(mut reader: impl Read) -> Result<Vec<u8>, &'static str> {
    let mut raw = Vec::with_capacity(MAX_WORD_LIST_LENGTH + 1);
    reader
        .by_ref()
        .take((MAX_WORD_LIST_LENGTH + 1) as u64)
        .read_to_end(&mut raw)
        .map_err(|_| "word-list-read-failed")?;
    if raw.len() > MAX_WORD_LIST_LENGTH {
        return Err("word-list-validation-failed");
    }
    Ok(raw)
}

fn read_word_list(path: impl AsRef<std::path::Path>) -> Result<Vec<u8>, &'static str> {
    let file = File::open(path).map_err(|_| "word-list-read-failed")?;
    read_word_list_from(file)
}

fn run() -> Result<(), &'static str> {
    let mut arguments = env::args_os().skip(1);
    let even_path = arguments.next().ok_or("usage")?;
    let odd_path = arguments.next().ok_or("usage")?;
    if arguments.next().is_some() {
        return Err("usage");
    }
    let even = read_word_list(even_path)?;
    let odd = read_word_list(odd_path)?;
    let lists = SasWordLists::load(&even, &odd).map_err(|_| "word-list-validation-failed")?;
    let transcript = vector_transcript();
    let sas = derive_interactive_sas(&transcript, &REPORTER_NONCE, &CORE_NONCE)
        .map_err(|_| "sas-derivation-failed")?;
    let phrase = render_sas(&lists, &sas).map_err(|_| "sas-render-failed")?;
    let mut hex = String::with_capacity(12);
    for byte in sas {
        use std::fmt::Write as _;
        write!(hex, "{byte:02x}").map_err(|_| "output-format-failed")?;
    }
    println!("{hex}");
    println!("{phrase}");
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err("usage") => {
            eprintln!("usage: protocol_v1_sas_demo EVEN_WORDS ODD_WORDS");
            ExitCode::from(64)
        }
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_interactive_transcript_is_exact() {
        assert_eq!(vector_transcript().len(), 722);
    }

    #[test]
    fn word_list_reader_rejects_input_beyond_the_largest_pinned_resource() {
        let oversized = vec![0_u8; MAX_WORD_LIST_LENGTH + 1];
        assert_eq!(
            read_word_list_from(&oversized[..]),
            Err("word-list-validation-failed")
        );
    }
}
