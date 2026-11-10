//! Demonstration only: sign one canonical `reporter-rfc9421-v1` report request and verify it.
//!
//! ```text
//! cargo run --locked --example protocol_v1_sign_demo
//! ```
//!
//! Stdout is one canonical JSON object containing only public verification material and exact
//! request bytes encoded as lowercase hex. The P-256 private key exists only as an ephemeral
//! in-memory `SigningKey`; it is never serialized, printed, logged, or written to disk.
//!
//! **This is not how a reporter holds its identity.** A persistent macOS reporter identity must be
//! a non-exportable P-256 key in the System Keychain, used by a Developer ID-signed and notarized
//! daemon. Software keys like this one are for demonstrations and tests only.
//!
//! The protocol profile is a draft that is not approved for distribution. This example opens no
//! listener and sends nothing over the network. All names are RFC 2606 documentation values.

use std::io::{self, Write};
use std::process::ExitCode;

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::Generate;
use remote_energy_meter_reporter::protocol_v1::canonical_json::CanonicalJson;
use remote_energy_meter_reporter::protocol_v1::content_digest::ContentDigest;
use remote_energy_meter_reporter::protocol_v1::http_signature::{
    HeaderField, RawRequest, VerificationContext, VerificationKey, render_signature,
    render_signature_input, signature_material, verify_request,
};
use remote_energy_meter_reporter::protocol_v1::jwk::P256PublicJwk;

/// RFC 2606 documentation authority.
const AUTHORITY: &str = "ha.example.com:58443";
const ROUTE: &str = "reporter.report.create";
/// Documentation session ID (16 zero bytes), not a server-issued session.
const SESSION_ID: &str = "AAAAAAAAAAAAAAAAAAAAAA";
const BODY: &[u8] = br#"{"state":"available","watts":12.5}"#;

fn field(name: &str, value: &str) -> HeaderField {
    HeaderField {
        name: name.as_bytes().to_vec(),
        value: value.as_bytes().to_vec(),
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn json_string(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{0008}' => output.push_str("\\b"),
            '\u{0009}' => output.push_str("\\t"),
            '\u{000a}' => output.push_str("\\n"),
            '\u{000c}' => output.push_str("\\f"),
            '\u{000d}' => output.push_str("\\r"),
            '\u{0000}'..='\u{001f}' => {
                use std::fmt::Write as _;
                write!(output, "\\u00{:02x}", character as u32)
                    .expect("writing to a String cannot fail");
            }
            _ => output.push(character),
        }
    }
    output.push('"');
    output
}

struct Demo {
    json: String,
    #[cfg(test)]
    request: RawRequest,
    #[cfg(test)]
    context: VerificationContext,
    #[cfg(test)]
    signature_base: Vec<u8>,
}

fn build_demo() -> Result<Demo, &'static str> {
    // Ephemeral, in-memory only. Never log, serialize, clone, or persist `signing_key`.
    let signing_key = SigningKey::try_generate().map_err(|_| "the system CSPRNG is unavailable")?;
    let jwk = P256PublicJwk::from_verifying_key(signing_key.verifying_key());

    let mut request = RawRequest {
        method: b"POST".to_vec(),
        authority: AUTHORITY.as_bytes().to_vec(),
        target: b"/api/v1/reports".to_vec(),
        headers: vec![
            field("rem-purpose", "rem-report-v1"),
            field("rem-session-id", SESSION_ID),
            field("rem-sequence", "1"),
            field("content-type", "application/json"),
            field("content-digest", &ContentDigest::for_body(BODY).render()),
        ],
        body: BODY.to_vec(),
    };

    let material = signature_material(&request, "rem", jwk.thumbprint_b64u(), None)
        .map_err(|_| "request was not admitted for signing")?;
    let signature: Signature = signing_key.sign(material.signature_base());
    let p1363: [u8; 64] = signature.normalize_s().to_bytes().into();
    drop(signing_key);

    let signature_input = render_signature_input(&[("rem", &material)]);
    let signature = render_signature(&[("rem", &p1363)]);
    request
        .headers
        .push(field("signature-input", &signature_input));
    request.headers.push(field("signature", &signature));

    let context = VerificationContext {
        expected_route_id: ROUTE,
        expected_authority: AUTHORITY.as_bytes().to_vec(),
        // Reporter signatures carry no client clock; receipt time does not affect verification.
        received_at: 0,
        keys: vec![VerificationKey {
            stable_principal_id: jwk.thumbprint_b64u().clone(),
            label: b"rem".to_vec(),
            jwk: jwk.clone(),
            generation: None,
        }],
    };
    let verified = verify_request(&request, &context).map_err(|_| "self-verification failed")?;
    if verified.identity().created().is_some()
        || verified.signature_base("rem") != Some(material.signature_base())
    {
        return Err("self-verification returned inconsistent public material");
    }

    let headers = request
        .headers
        .iter()
        .map(|header| {
            format!(
                "{{\"name_hex\":{},\"value_hex\":{}}}",
                json_string(&hex(&header.name)),
                json_string(&hex(&header.value))
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let public_jwk = std::str::from_utf8(jwk.canonical_bytes())
        .map_err(|_| "canonical public JWK was not UTF-8")?;
    let json = format!(
        concat!(
            "{{\"public_jwk\":{},",
            "\"request\":{{\"authority_hex\":{},\"body_hex\":{},\"headers\":[{}],",
            "\"method_hex\":{},\"target_hex\":{}}},",
            "\"route\":{},\"signature\":{},\"signature_base_hex\":{},",
            "\"signature_input\":{},\"stable_identity\":{}}}"
        ),
        public_jwk,
        json_string(&hex(&request.authority)),
        json_string(&hex(&request.body)),
        headers,
        json_string(&hex(&request.method)),
        json_string(&hex(&request.target)),
        json_string(ROUTE),
        json_string(&signature),
        json_string(&hex(material.signature_base())),
        json_string(&signature_input),
        json_string(jwk.thumbprint_b64u().as_str()),
    );
    CanonicalJson::parse_exact(json.as_bytes()).map_err(|_| "output was not canonical JSON")?;

    Ok(Demo {
        json,
        #[cfg(test)]
        request,
        #[cfg(test)]
        context,
        #[cfg(test)]
        signature_base: material.signature_base().to_vec(),
    })
}

fn main() -> ExitCode {
    let demo = match build_demo() {
        Ok(demo) => demo,
        Err(message) => {
            eprintln!("protocol_v1_sign_demo: {message}");
            return ExitCode::FAILURE;
        }
    };
    if io::stdout().write_all(demo.json.as_bytes()).is_err() {
        eprintln!("protocol_v1_sign_demo: stdout write failed");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_is_closed_canonical_public_schema_without_private_material() {
        let demo = build_demo().unwrap();
        let document = CanonicalJson::parse_exact(demo.json.as_bytes()).unwrap();
        for member in [
            "public_jwk",
            "request",
            "route",
            "signature",
            "signature_base_hex",
            "signature_input",
            "stable_identity",
        ] {
            assert!(
                document.top_level_member(member).is_some(),
                "missing {member}"
            );
        }
        assert_eq!(
            P256PublicJwk::parse_exact(document.top_level_member("public_jwk").unwrap())
                .unwrap()
                .canonical_bytes(),
            document.top_level_member("public_jwk").unwrap()
        );
        let request =
            CanonicalJson::parse_exact(document.top_level_member("request").unwrap()).unwrap();
        for member in [
            "authority_hex",
            "body_hex",
            "headers",
            "method_hex",
            "target_hex",
        ] {
            assert!(
                request.top_level_member(member).is_some(),
                "missing request.{member}"
            );
        }
        for forbidden in ["d", "private_jwk", "private_key", "signing_key"] {
            assert!(document.top_level_member(forbidden).is_none());
            assert!(!demo.json.contains(&format!("\"{forbidden}\":")));
        }
        assert!(!demo.json.contains(";created="));
    }

    #[test]
    fn generated_request_self_verifies_with_the_emitted_signature_base() {
        let demo = build_demo().unwrap();
        let verified = verify_request(&demo.request, &demo.context).unwrap();
        assert_eq!(verified.identity().route_id(), ROUTE);
        assert_eq!(verified.identity().created(), None);
        assert_eq!(
            verified.signature_base("rem"),
            Some(demo.signature_base.as_slice())
        );
    }
}
