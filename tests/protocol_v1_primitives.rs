mod support;

use remote_energy_meter_reporter::protocol_v1::{
    ErrorClass,
    b64u::{B64u, OpaqueB64u},
    canonical_json::CanonicalJson,
    content_digest::ContentDigest,
    jwk::P256PublicJwk,
    routes::{SignatureProfile, Surface, lookup_route},
    signature::verify_p1363_low_s,
    transcript::{TranscriptField, decode_transcript, encode_transcript},
};
use support::{
    Json, base64_standard_encode_padded, base64url_decode, base64url_encode_unpadded, fixture,
    hex_decode, named_value, parse_json, vector_case,
};

const PUBLIC_JWK: &[u8] = br#"{"crv":"P-256","kty":"EC","x":"qXlTk75KQKYN-PBJPDM4qHw8tYKgDLaqixcHrthpc_U","y":"tdXohmn4d0O78ACF989uLrxgHWAryPJteiOQIvBjRDo"}"#;
const REPORT_PUBLIC_JWK: &[u8] = br#"{"crv":"P-256","kty":"EC","x":"_hfKxOxXb6sOWAQQCBwUqxlJmUGfRogWTLA67NpCyFc","y":"9tMUTcWQVfk6ceWxltzEOS0E6r1bjVibVG229XQ39Hs"}"#;
const REPORT_SIGNATURE_BASE: &[u8] = b"\"@method\": POST\n\"@authority\": ha.example.com:58443\n\"@path\": /api/v1/reports\n\"@query\": ?\n\"rem-purpose\": rem-report-v1\n\"rem-session-id\": Dw8PDw8PDw8PDw8PDw8PDw\n\"rem-sequence\": 42\n\"content-type\": application/json\n\"content-digest\": sha-256=:0kxpPrj5n3JB2UP9HDOUSY3rZ0PaDU+raWZlU4EZ730=:\n\"@signature-params\": (\"@method\" \"@authority\" \"@path\" \"@query\" \"rem-purpose\" \"rem-session-id\" \"rem-sequence\" \"content-type\" \"content-digest\");keyid=\"tJUxkgrEY2PEpSLzSOPtHkPvJfSndZ2h-ZmWzKoa3ao\";alg=\"ecdsa-p256-sha256\";tag=\"rem-report-v1\"";

fn invalid<T: std::fmt::Debug>(result: Result<T, ErrorClass>) {
    assert_eq!(result.unwrap_err(), ErrorClass::InvalidRequest);
}

fn unauthenticated<T: std::fmt::Debug>(result: Result<T, ErrorClass>) {
    assert_eq!(result.unwrap_err(), ErrorClass::AuthenticationRequired);
}

#[test]
fn strict_typed_base64url_accepts_only_canonical_exact_lengths() {
    for bytes in [vec![0x11; 16], vec![0x22; 32], vec![0x33; 64]] {
        let encoded = base64url_encode_unpadded(&bytes);
        match bytes.len() {
            16 => assert_eq!(B64u::<16>::parse(&encoded).unwrap().as_bytes(), bytes),
            32 => assert_eq!(B64u::<32>::parse(&encoded).unwrap().as_bytes(), bytes),
            64 => assert_eq!(B64u::<64>::parse(&encoded).unwrap().as_bytes(), bytes),
            _ => unreachable!(),
        }
    }

    invalid(B64u::<16>::parse(""));
    invalid(B64u::<16>::parse("ERERERERERERERERERERE"));
    invalid(B64u::<16>::parse("ERERERERERERERERERERERE"));
    invalid(B64u::<16>::parse("ERERERERERERERERERERER=="));
    invalid(B64u::<16>::parse("ERERERERERERERERERERER")); // non-zero unused trailing bits
    invalid(B64u::<16>::parse("ERERERERERERERERERER+Q"));
    invalid(B64u::<16>::parse("ERERERERERERERERERER Q"));
}

#[test]
fn opaque_base64url_enforces_inclusive_decoded_byte_bounds() {
    for length in [1, 128] {
        let text = base64url_encode_unpadded(&vec![0x5a; length]);
        assert_eq!(
            OpaqueB64u::<128>::parse(&text).unwrap().as_bytes().len(),
            length
        );
    }
    for length in [1, 256] {
        let text = base64url_encode_unpadded(&vec![0xa5; length]);
        assert_eq!(
            OpaqueB64u::<256>::parse(&text).unwrap().as_bytes().len(),
            length
        );
    }

    invalid(OpaqueB64u::<128>::parse(""));
    invalid(OpaqueB64u::<128>::parse(&base64url_encode_unpadded(
        &[0_u8; 129],
    )));
    invalid(OpaqueB64u::<256>::parse(&base64url_encode_unpadded(
        &[0_u8; 257],
    )));
    invalid(OpaqueB64u::<128>::parse("AA=="));
}

#[test]
fn transcript_encoding_matches_exact_vector_bytes_and_cap() {
    let nonce = [0x11; 32];
    let encoded = encode_transcript(
        "rem-interactive-commit-v1",
        &[
            TranscriptField::new("role", b"reporter"),
            TranscriptField::new("nonce", &nonce),
        ],
        4096,
    )
    .unwrap();
    assert_eq!(
        encoded,
        hex_decode(concat!(
            "52454d2d5452414e53435249505401",
            "001972656d2d696e7465726163746976652d636f6d6d69742d7631",
            "0004726f6c65000000087265706f72746572",
            "00056e6f6e636500000020",
            "1111111111111111111111111111111111111111111111111111111111111111"
        ))
    );
    assert_eq!(encoded.len(), 103);

    let exact = encode_transcript("p", &[TranscriptField::new("a", &vec![0; 4071])], 4096).unwrap();
    assert_eq!(exact.len(), 4096);
    let decoded = decode_transcript(&exact, "p", &["a"], 4096).unwrap();
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].value(), vec![0; 4071]);
    invalid(decode_transcript(&exact, "p", &["a"], 4095));
    invalid(encode_transcript(
        "p",
        &[TranscriptField::new("a", &vec![0; 4072])],
        4096,
    ));
    invalid(encode_transcript(
        "p",
        &[
            TranscriptField::new("a", b"1"),
            TranscriptField::new("a", b"2"),
        ],
        4096,
    ));
    invalid(encode_transcript("é", &[], 4096));
    invalid(encode_transcript(
        "p",
        &[TranscriptField::new("é", b"x")],
        4096,
    ));
}

#[test]
fn common_transcript_decoder_executes_every_declared_structural_mutation() {
    let case = vector_case(
        &parse_json(&fixture("vectors/common.json")),
        "common.transcript-encoding",
    )
    .clone();
    let purpose = named_value(&case, "inputs", "purpose");
    let expected_fields = ["role", "nonce"];
    let transcript = hex_decode(output_value(&case, "transcript"));
    let decoded = decode_transcript(&transcript, purpose, &expected_fields, 4096).unwrap();
    assert_eq!(decoded[0].name(), "role");
    assert_eq!(decoded[0].value(), b"reporter");
    assert_eq!(decoded[1].name(), "nonce");
    assert_eq!(decoded[1].value(), &[0x11; 32]);

    let header = hex_decode(named_value(
        &case,
        "intermediates",
        "transcript.encoded.header",
    ));
    let domain = hex_decode(named_value(
        &case,
        "intermediates",
        "transcript.encoded.purpose",
    ));
    let role = hex_decode(named_value(
        &case,
        "intermediates",
        "transcript.encoded.role",
    ));
    let nonce = hex_decode(named_value(
        &case,
        "intermediates",
        "transcript.encoded.nonce",
    ));

    let mut wrong_header = transcript.clone();
    wrong_header[header.len() - 1] ^= 1;
    let mut wrong_purpose = transcript.clone();
    wrong_purpose[header.len() + domain.len() - 1] ^= 1;
    let duplicate_role = [
        header.as_slice(),
        domain.as_slice(),
        role.as_slice(),
        role.as_slice(),
        nonce.as_slice(),
    ]
    .concat();
    let omitted_nonce = [header.as_slice(), domain.as_slice(), role.as_slice()].concat();
    let reordered = [
        header.as_slice(),
        domain.as_slice(),
        nonce.as_slice(),
        role.as_slice(),
    ]
    .concat();
    let mut wrong_nonce_length = transcript.clone();
    let nonce_length_at = header.len() + domain.len() + role.len() + 2 + "nonce".len();
    wrong_nonce_length[nonce_length_at..nonce_length_at + 4].copy_from_slice(&33_u32.to_be_bytes());

    let malformed = [
        wrong_header,
        wrong_purpose,
        duplicate_role,
        omitted_nonce,
        reordered,
        wrong_nonce_length,
    ];
    let mutation_ids: Vec<_> = case
        .member("mutations")
        .array()
        .iter()
        .map(|mutation| mutation.member("id").string())
        .collect();
    assert_eq!(
        mutation_ids,
        [
            "common.transcript-encoding.m00",
            "common.transcript-encoding.m01",
            "common.transcript-encoding.m02",
            "common.transcript-encoding.m03",
            "common.transcript-encoding.m04",
            "common.transcript-encoding.m05",
        ]
    );
    for (id, raw) in mutation_ids.into_iter().zip(malformed) {
        assert_eq!(
            decode_transcript(&raw, purpose, &expected_fields, 4096),
            Err(ErrorClass::InvalidRequest),
            "{id}"
        );
    }
}

#[test]
fn p256_public_jwk_is_exact_canonical_on_curve_and_has_rfc7638_identity() {
    let jwk = P256PublicJwk::parse_exact(PUBLIC_JWK).unwrap();
    assert_eq!(jwk.canonical_bytes(), PUBLIC_JWK);
    assert_eq!(
        jwk.thumbprint(),
        hex_decode("5ef5d38f326668a5c96967e9b15f66507e0ad8fa4017a4a35a385b70237d7485")
    );
    assert_eq!(
        jwk.thumbprint_b64u().as_str(),
        "XvXTjzJmaKXJaWfpsV9mUH4K2PpAF6SjWjhbcCN9dIU"
    );
}

#[test]
fn every_common_jwk_mutation_executes_against_the_primitive_result() {
    let case = vector_case(
        &parse_json(&fixture("vectors/common.json")),
        "common.jwk-thumbprint",
    )
    .clone();
    let canonical = named_value(&case, "intermediates", "jwk.canonical");
    let parsed = P256PublicJwk::parse_exact(canonical.as_bytes()).unwrap();
    let x = named_value(&case, "inputs", "jwk.x");
    let y = named_value(&case, "inputs", "jwk.y");

    let mut consumed = Vec::new();
    for mutation in case.member("mutations").array() {
        let id = mutation.member("id").string();
        match id {
            "common.jwk-thumbprint.m00" => {
                let changed = canonical.replacen(x, substitute_value(&case, "jwk.x"), 1);
                invalid(P256PublicJwk::parse_exact(changed.as_bytes()));
            }
            "common.jwk-thumbprint.m01" => {
                let mut changed_y = base64url_decode(y);
                *changed_y.last_mut().unwrap() ^= 1;
                let changed = canonical.replacen(y, &base64url_encode_unpadded(&changed_y), 1);
                invalid(P256PublicJwk::parse_exact(changed.as_bytes()));
            }
            "common.jwk-thumbprint.m02" => invalid(P256PublicJwk::parse_exact(
                substitute_value(&case, "jwk.canonical").as_bytes(),
            )),
            "common.jwk-thumbprint.m03" => {
                let changed =
                    format!("{{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"{x}\",\"y\":\"{y}\"}}");
                invalid(P256PublicJwk::parse_exact(changed.as_bytes()));
            }
            "common.jwk-thumbprint.m04" => {
                let mut changed =
                    hex_decode(named_value(&case, "intermediates", "thumbprint.sha256"));
                *changed.last_mut().unwrap() ^= 1;
                assert_ne!(parsed.thumbprint(), changed);
            }
            _ => panic!("unconsumed common JWK mutation {id}"),
        }
        consumed.push(id);
    }
    assert_eq!(consumed.len(), 5);
}

#[test]
fn p256_public_jwk_rejects_duplicate_extra_private_noncanonical_and_off_curve_forms() {
    let duplicate = br#"{"crv":"P-256","kty":"EC","x":"qXlTk75KQKYN-PBJPDM4qHw8tYKgDLaqixcHrthpc_U","x":"qXlTk75KQKYN-PBJPDM4qHw8tYKgDLaqixcHrthpc_U","y":"tdXohmn4d0O78ACF989uLrxgHWAryPJteiOQIvBjRDo"}"#;
    let extra = br#"{"crv":"P-256","kid":"fixture","kty":"EC","x":"qXlTk75KQKYN-PBJPDM4qHw8tYKgDLaqixcHrthpc_U","y":"tdXohmn4d0O78ACF989uLrxgHWAryPJteiOQIvBjRDo"}"#;
    let private = br#"{"crv":"P-256","d":"AA","kty":"EC","x":"qXlTk75KQKYN-PBJPDM4qHw8tYKgDLaqixcHrthpc_U","y":"tdXohmn4d0O78ACF989uLrxgHWAryPJteiOQIvBjRDo"}"#;
    let whitespace = br#"{"crv": "P-256", "kty": "EC", "x": "qXlTk75KQKYN-PBJPDM4qHw8tYKgDLaqixcHrthpc_U", "y": "tdXohmn4d0O78ACF989uLrxgHWAryPJteiOQIvBjRDo"}"#;
    let wrong_order = br#"{"kty":"EC","crv":"P-256","x":"qXlTk75KQKYN-PBJPDM4qHw8tYKgDLaqixcHrthpc_U","y":"tdXohmn4d0O78ACF989uLrxgHWAryPJteiOQIvBjRDo"}"#;
    for rejected in [
        duplicate.as_slice(),
        extra.as_slice(),
        private.as_slice(),
        whitespace.as_slice(),
        wrong_order.as_slice(),
    ] {
        invalid(P256PublicJwk::parse_exact(rejected));
    }

    let mut y = base64url_decode("tdXohmn4d0O78ACF989uLrxgHWAryPJteiOQIvBjRDo");
    *y.last_mut().unwrap() ^= 1;
    let off_curve = format!(
        "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"qXlTk75KQKYN-PBJPDM4qHw8tYKgDLaqixcHrthpc_U\",\"y\":\"{}\"}}",
        base64url_encode_unpadded(&y)
    );
    invalid(P256PublicJwk::parse_exact(off_curve.as_bytes()));
}

#[test]
fn content_digest_is_exact_rfc9530_sha256_parse_render_and_verify() {
    let body = br#"{"state":"available","watts":12.5}"#;
    let expected = "sha-256=:0kxpPrj5n3JB2UP9HDOUSY3rZ0PaDU+raWZlU4EZ730=:";
    let digest = ContentDigest::for_body(body);
    assert_eq!(digest.render(), expected);
    assert_eq!(ContentDigest::parse_exact(expected).unwrap(), digest);
    assert_eq!(digest.verify(body), Ok(()));
    invalid(digest.verify(br#"{"watts":12.5,"state":"available"}"#));

    for rejected in [
        "SHA-256=:0kxpPrj5n3JB2UP9HDOUSY3rZ0PaDU+raWZlU4EZ730=:",
        "sha-256=:0kxpPrj5n3JB2UP9HDOUSY3rZ0PaDU-raWZlU4EZ730=:",
        "sha-256=:0kxpPrj5n3JB2UP9HDOUSY3rZ0PaDU+raWZlU4EZ730:",
        "sha-256=:0kxpPrj5n3JB2UP9HDOUSY3rZ0PaDU+raWZlU4EZ730=:, sha-256=:0kxpPrj5n3JB2UP9HDOUSY3rZ0PaDU+raWZlU4EZ730=:",
        "sha-512=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==:",
        " sha-256=:0kxpPrj5n3JB2UP9HDOUSY3rZ0PaDU+raWZlU4EZ730=:",
    ] {
        invalid(ContentDigest::parse_exact(rejected));
    }
}

#[test]
fn every_common_content_digest_mutation_executes_against_parse_or_verify() {
    let case = vector_case(
        &parse_json(&fixture("vectors/common.json")),
        "common.content-digest",
    )
    .clone();
    let body = named_value(&case, "inputs", "body").as_bytes();
    let header = output_value(&case, "headers.content-digest");
    let digest = ContentDigest::parse_exact(header).unwrap();

    let mut consumed = Vec::new();
    for mutation in case.member("mutations").array() {
        let id = mutation.member("id").string();
        match id {
            "common.content-digest.m00" => invalid(ContentDigest::parse_exact(substitute_value(
                &case,
                "headers.content-digest",
            ))),
            "common.content-digest.m01" => {
                invalid(digest.verify(substitute_value(&case, "body").as_bytes()))
            }
            "common.content-digest.m02" => {
                let mut changed = hex_decode(named_value(&case, "intermediates", "body.sha256"));
                *changed.last_mut().unwrap() ^= 1;
                let changed_header =
                    format!("sha-256=:{}:", base64_standard_encode_padded(&changed));
                invalid(
                    ContentDigest::parse_exact(&changed_header)
                        .unwrap()
                        .verify(body),
                );
            }
            "common.content-digest.m03" => {
                invalid(ContentDigest::parse_exact(&format!("{header}, {header}")));
            }
            _ => panic!("unconsumed common Content-Digest mutation {id}"),
        }
        consumed.push(id);
    }
    assert_eq!(consumed.len(), 4);
}

#[test]
fn canonical_json_accepts_and_returns_only_the_exact_profile_encoding() {
    let exact = br#"{"action":"approve","count":0,"enabled":true,"metadata":null,"watts":12.5}"#;
    assert_eq!(CanonicalJson::parse_exact(exact).unwrap().as_bytes(), exact);

    for rejected in [
        br#" {"action":"approve","count":0,"enabled":true,"metadata":null,"watts":12.5}"#.as_slice(),
        br#"{"count":0,"action":"approve","enabled":true,"metadata":null,"watts":12.5}"#.as_slice(),
        br#"{"action":"approve","action":"approve","count":0,"enabled":true,"metadata":null,"watts":12.5}"#.as_slice(),
        br#"{"action":"approve","count":00,"enabled":true,"metadata":null,"watts":12.5}"#.as_slice(),
        br#"{"action":"approve","count":0,"enabled":true,"metadata":null,"watts":12.50}"#.as_slice(),
        br#"{"action":"approve","count":0,"enabled":true,"metadata":null,"watts":1.25e1}"#.as_slice(),
        b"\xef\xbb\xbf{}".as_slice(),
        br#"[[[[[[[[[0]]]]]]]]]"#.as_slice(),
    ] {
        invalid(CanonicalJson::parse_exact(rejected));
    }
}

#[test]
fn canonical_json_debug_exposes_metadata_without_secret_content() {
    const SECRET_MARKER: &str = "SEC2_CANONICAL_JSON_SECRET_MARKER";

    let encoded = format!(r#""{SECRET_MARKER}""#);
    let canonical = CanonicalJson::parse_exact(encoded.as_bytes()).unwrap();
    let debug = format!("{canonical:?}");
    let marker_bytes = format!("{:?}", SECRET_MARKER.as_bytes());
    let marker_byte_values = &marker_bytes[1..marker_bytes.len() - 1];

    assert!(
        debug.starts_with("CanonicalJson"),
        "Debug output omitted the CanonicalJson type"
    );
    assert!(
        !debug.contains(SECRET_MARKER) && !debug.contains(marker_byte_values),
        "CanonicalJson Debug must not expose canonical JSON content"
    );
    assert!(
        debug.contains(&canonical.as_bytes().len().to_string()),
        "CanonicalJson Debug omitted safe byte-length metadata"
    );
}

#[test]
fn canonical_json_accepts_each_canonical_top_level_scalar_form() {
    for exact in [
        b"true".as_slice(),
        b"false",
        b"null",
        b"0",
        b"18446744073709551615",
        b"12.5",
        br#""text""#,
        br#""quote:\" backslash:\\""#,
    ] {
        assert_eq!(
            CanonicalJson::parse_exact(exact).unwrap().as_bytes(),
            exact,
            "{}",
            String::from_utf8_lossy(exact)
        );
    }
}

#[test]
fn canonical_json_orders_and_deduplicates_escaped_ascii_member_names_by_decoded_bytes() {
    let exact = br#"{"a\"":1,"a#":2,"a\\":3,"a]":4}"#;
    let parsed = CanonicalJson::parse_exact(exact).unwrap();
    assert_eq!(parsed.as_bytes(), exact);
    assert_eq!(parsed.top_level_member("a\""), Some(b"1".as_slice()));
    assert_eq!(parsed.top_level_member("a\\"), Some(b"3".as_slice()));

    for rejected in [
        br#"{"a#":2,"a\"":1}"#.as_slice(),
        br#"{"a\"":1,"a\"":2}"#,
        br#"{"a\\":1,"a\\":2}"#,
    ] {
        invalid(CanonicalJson::parse_exact(rejected));
    }
}

#[test]
fn p1363_verifier_accepts_exact_low_s_and_rejects_high_s_or_malformed_scalars() {
    let jwk = P256PublicJwk::parse_exact(REPORT_PUBLIC_JWK).unwrap();
    let low_s = hex_decode(
        "5abe8ce0eca1178b7edee4e83f03f000a0c2f7f7d360aa7dfe62f840e8b3a0fe441c8d21e2f135e08cf6d5ea0cdd3c811f41b28805a0e3bf20cde4bfc0614640",
    );
    let high_s = hex_decode(
        "5abe8ce0eca1178b7edee4e83f03f000a0c2f7f7d360aa7dfe62f840e8b3a0febbe372dd1d0eca2073092a15f322c37e9da54825a176bac5d2ebe6033c01df11",
    );
    assert_eq!(
        verify_p1363_low_s(&jwk, REPORT_SIGNATURE_BASE, &low_s),
        Ok(())
    );
    unauthenticated(verify_p1363_low_s(&jwk, REPORT_SIGNATURE_BASE, &high_s));
    unauthenticated(verify_p1363_low_s(
        &jwk,
        REPORT_SIGNATURE_BASE,
        &low_s[..63],
    ));

    let mut zero_r = low_s.clone();
    zero_r[..32].fill(0);
    unauthenticated(verify_p1363_low_s(&jwk, REPORT_SIGNATURE_BASE, &zero_r));
    let mut zero_s = low_s.clone();
    zero_s[32..].fill(0);
    unauthenticated(verify_p1363_low_s(&jwk, REPORT_SIGNATURE_BASE, &zero_s));
    let mut changed_message = REPORT_SIGNATURE_BASE.to_vec();
    *changed_message.last_mut().unwrap() ^= 1;
    unauthenticated(verify_p1363_low_s(&jwk, &changed_message, &low_s));
}

#[test]
fn route_lookup_returns_exact_profile_and_rejects_target_aliases() {
    let report = lookup_route(b"POST", b"/api/v1/reports").unwrap();
    assert_eq!(report.id(), "reporter.report.create");
    assert_eq!(report.surface(), Surface::Reporter);
    assert_eq!(
        report.signature_profile(),
        Some(SignatureProfile::ReporterRfc9421V1)
    );
    assert_eq!(report.purpose(), "rem-report-v1");
    assert_eq!(report.request_body_max_bytes(), 1024);
    assert_eq!(report.success_body_max_bytes(), 1024);
    assert_eq!(report.success_status(), 200);

    let roster = lookup_route(
        b"GET",
        b"/control/v1/roster/events?after_generation=7&wait_seconds=25",
    )
    .unwrap();
    assert_eq!(roster.id(), "control.roster.events");
    assert_eq!(roster.surface(), Surface::Control);
    assert_eq!(
        roster.signature_profile(),
        Some(SignatureProfile::ControlRfc9421V1)
    );
    assert_eq!(
        roster.named_query(),
        &[("after_generation", "7"), ("wait_seconds", "25")]
    );

    assert_eq!(
        lookup_route(b"GET", b"/api/v1/reports").unwrap_err(),
        ErrorClass::MethodNotAllowed
    );
    assert_eq!(
        lookup_route(b"POST", b"/api/v1/missing").unwrap_err(),
        ErrorClass::NotFound
    );
    for target in [
        b"/api/v1/reports?".as_slice(),
        b"/api//v1/reports".as_slice(),
        b"/api/v1/./reports".as_slice(),
        b"/api/v1/%72eports".as_slice(),
        b"/control/v1/roster/events?wait_seconds=25&after_generation=7".as_slice(),
        b"/control/v1/roster/events?after_generation=07&wait_seconds=25".as_slice(),
        b"/control/v1/roster/events?after_generation=7&wait_seconds=26".as_slice(),
        b"/control/v1/roster/events?after_generation=7&after_generation=8&wait_seconds=25"
            .as_slice(),
    ] {
        assert_eq!(
            lookup_route(b"GET", target).unwrap_err(),
            ErrorClass::InvalidRequest
        );
    }
}

#[test]
fn every_json_value_published_as_utf8_is_accepted_byte_for_byte_as_canonical() {
    // Mutation substitutes are deliberately altered inputs, not published canonical values: each
    // JSON substitute is consumed explicitly below with the canonicality its mutation declares.
    const SUBSTITUTES: &[(&str, &str, bool)] = &[
        ("common.jwk-thumbprint", "jwk.canonical", false),
        ("common.content-digest", "body", false),
        ("mqtt.process-offline-will", "payload.state", true),
    ];

    fn visit(value: &Json, count: &mut usize, case_id: Option<&str>) {
        match value {
            Json::Object(object) => {
                let case_id = object
                    .get("id")
                    .filter(|_| object.contains_key("mutations"))
                    .map_or(case_id, |id| Some(id.string()));
                if object
                    .get("encoding")
                    .is_some_and(|encoding| encoding.string() == "utf8")
                {
                    let bytes = object["value"].string().as_bytes();
                    if matches!(bytes.first(), Some(b'{') | Some(b'[')) {
                        assert_eq!(CanonicalJson::parse_exact(bytes).unwrap().as_bytes(), bytes);
                        *count += 1;
                    }
                }
                for (name, member) in object {
                    if name == "substitutes" {
                        for substitute in member.array() {
                            let replacement = substitute.member("replacement");
                            let bytes = replacement.member("value").string().as_bytes();
                            if replacement.member("encoding").string() != "utf8"
                                || !matches!(bytes.first(), Some(b'{') | Some(b'['))
                            {
                                continue;
                            }
                            let field = substitute.member("field").string();
                            let &(_, _, canonical) = SUBSTITUTES
                                .iter()
                                .find(|(id, name, _)| Some(*id) == case_id && *name == field)
                                .unwrap_or_else(|| panic!("unconsumed JSON substitute {field}"));
                            assert_eq!(
                                CanonicalJson::parse_exact(bytes).is_ok(),
                                canonical,
                                "substitute {field} canonicality"
                            );
                            *count += 1;
                        }
                    } else {
                        visit(member, count, case_id);
                    }
                }
            }
            Json::Array(array) => {
                for item in array {
                    visit(item, count, case_id);
                }
            }
            Json::Null | Json::Bool(_) | Json::Number(_) | Json::String(_) => {}
        }
    }

    let mut count = 0;
    for file in [
        "common.json",
        "control-bootstrap-recovery.json",
        "http-signatures.json",
        "interactive-enrollment.json",
        "key-rotations.json",
        "managed-enrollment.json",
        "managed-token-control.json",
        "mqtt-v2-aead.json",
    ] {
        visit(
            &parse_json(&fixture(&format!("vectors/{file}"))),
            &mut count,
            None,
        );
    }
    assert_eq!(
        count, 128,
        "new canonical JSON vector values require explicit consumption"
    );
}

fn output_value<'a>(case: &'a Json, name: &str) -> &'a str {
    case.member("expected")
        .member("outputs")
        .array()
        .iter()
        .find(|value| value.member("name").string() == name)
        .unwrap_or_else(|| panic!("missing output {name}"))
        .member("value")
        .string()
}

fn substitute_value<'a>(case: &'a Json, field: &str) -> &'a str {
    case.member("substitutes")
        .array()
        .iter()
        .find(|value| value.member("field").string() == field)
        .unwrap_or_else(|| panic!("missing substitute {field}"))
        .member("replacement")
        .member("value")
        .string()
}

fn transcript_parts(case: &Json) -> (String, Vec<(String, Vec<u8>)>) {
    let intermediates = case.member("intermediates").array();
    let domain = hex_decode(named_value(
        case,
        "intermediates",
        "transcript.encoded.domain-purpose",
    ));
    let purpose_length = usize::from(u16::from_be_bytes(domain[..2].try_into().unwrap()));
    assert_eq!(domain.len(), purpose_length + 2);
    let purpose = std::str::from_utf8(&domain[2..]).unwrap().to_owned();
    let fields = intermediates
        .iter()
        .filter_map(|value| {
            let encoded_name = value.member("name").string();
            if !encoded_name.starts_with("transcript.encoded.")
                || matches!(
                    encoded_name,
                    "transcript.encoded.header" | "transcript.encoded.domain-purpose"
                )
            {
                return None;
            }
            let encoded = hex_decode(value.member("value").string());
            let name_length = usize::from(u16::from_be_bytes(encoded[..2].try_into().unwrap()));
            let value_length_at = 2 + name_length;
            let name = std::str::from_utf8(&encoded[2..value_length_at])
                .unwrap()
                .to_owned();
            let value_length = u32::from_be_bytes(
                encoded[value_length_at..value_length_at + 4]
                    .try_into()
                    .unwrap(),
            ) as usize;
            assert_eq!(encoded.len(), value_length_at + 4 + value_length);
            Some((name, encoded[value_length_at + 4..].to_vec()))
        })
        .collect();
    (purpose, fields)
}

fn transcript_with_mutation(case: &Json, mutation: &Json) -> Vec<u8> {
    let (purpose, mut fields) = transcript_parts(case);
    let field = mutation.member("field").string();
    let operation = mutation.member("operation").string();
    assert!(field.starts_with("transcript."));
    if field == "transcript.field-order" {
        fields.swap(0, 1);
    } else {
        let name = field.strip_prefix("transcript.").unwrap();
        let (_, value) = fields
            .iter_mut()
            .find(|(candidate, _)| candidate == name)
            .unwrap_or_else(|| panic!("missing transcript field {name}"));
        match operation {
            "alter-byte" => *value.last_mut().expect("non-empty transcript value") ^= 1,
            "alter-value" => {
                assert_eq!(
                    value.len(),
                    1,
                    "typed mutation needs an explicit implementation"
                );
                value[0] = value[0].checked_add(1).unwrap();
            }
            _ => panic!("unsupported transcript mutation {field} {operation}"),
        }
    }
    let borrowed: Vec<_> = fields
        .iter()
        .map(|(name, value)| TranscriptField::new(name, value))
        .collect();
    encode_transcript(&purpose, &borrowed, 4096).unwrap()
}

#[test]
fn every_jwk_backed_transcript_signature_vector_accepts_low_s_and_rejects_high_s() {
    let managed_set = parse_json(&fixture("vectors/managed-enrollment.json"));
    let managed = vector_case(&managed_set, "managed.proof");
    let rotation_set = parse_json(&fixture("vectors/key-rotations.json"));
    let rotation = vector_case(&rotation_set, "rotation.reporter");
    let cases = [
        (
            managed,
            "proposed_jwk",
            "proposed_signature",
            "proposed_signature.high-s",
        ),
        (
            rotation,
            "current_jwk",
            "current_signature",
            "current_signature.high-s",
        ),
        (
            rotation,
            "proposed_jwk",
            "proposed_signature",
            "proposed_signature.high-s",
        ),
    ];

    for (case, jwk_name, signature_name, high_s_name) in cases {
        let jwk =
            P256PublicJwk::parse_exact(named_value(case, "inputs", jwk_name).as_bytes()).unwrap();
        let transcript = hex_decode(named_value(case, "intermediates", "transcript"));
        let low_s = base64url_decode(output_value(case, signature_name));
        let high_s = base64url_decode(substitute_value(case, high_s_name));
        assert_eq!(low_s.len(), 64);
        assert_eq!(high_s.len(), 64);
        assert_eq!(verify_p1363_low_s(&jwk, &transcript, &low_s), Ok(()));

        let mut altered = low_s.clone();
        *altered.last_mut().unwrap() ^= 1;
        unauthenticated(verify_p1363_low_s(&jwk, &transcript, &altered));
        unauthenticated(verify_p1363_low_s(&jwk, &transcript, &high_s));

        let signature_mutations: Vec<_> = case
            .member("mutations")
            .array()
            .iter()
            .filter(|mutation| {
                matches!(
                    mutation.member("field").string(),
                    field if field == signature_name || field == high_s_name
                )
            })
            .map(|mutation| {
                (
                    mutation.member("field").string(),
                    mutation.member("operation").string(),
                )
            })
            .collect();
        assert_eq!(
            signature_mutations,
            [(signature_name, "alter-byte"), (high_s_name, "substitute")]
        );
    }
}

#[test]
fn every_signed_transcript_field_mutation_invalidates_each_bound_jwk_signature() {
    let cases = [
        (
            "managed-enrollment.json",
            "managed.proof",
            vec![("proposed_jwk", "proposed_signature")],
            15,
        ),
        (
            "key-rotations.json",
            "rotation.reporter",
            vec![
                ("current_jwk", "current_signature"),
                ("proposed_jwk", "proposed_signature"),
            ],
            13,
        ),
    ];
    for (file, case_id, bindings, expected_mutations) in cases {
        let set = parse_json(&fixture(&format!("vectors/{file}")));
        let case = vector_case(&set, case_id);
        let signatures: Vec<_> = bindings
            .into_iter()
            .map(|(jwk_name, signature_name)| {
                (
                    P256PublicJwk::parse_exact(named_value(case, "inputs", jwk_name).as_bytes())
                        .unwrap(),
                    base64url_decode(output_value(case, signature_name)),
                )
            })
            .collect();
        let mut consumed = 0;
        for mutation in case.member("mutations").array() {
            if !mutation.member("field").string().starts_with("transcript.") {
                continue;
            }
            let mutated = transcript_with_mutation(case, mutation);
            for (key, signature) in &signatures {
                assert_eq!(
                    verify_p1363_low_s(key, &mutated, signature),
                    Err(ErrorClass::AuthenticationRequired),
                    "{}",
                    mutation.member("id").string()
                );
            }
            consumed += 1;
        }
        assert_eq!(consumed, expected_mutations, "{case_id}");
    }
}

#[test]
fn control_spki_transcript_and_signature_mutations_are_executed() {
    let spki_prefix = hex_decode("3059301306072a8648ce3d020106082a8648ce3d03010703420004");
    let set = parse_json(&fixture("vectors/key-rotations.json"));
    let case = vector_case(&set, "rotation.control-spki");
    let transcript = hex_decode(named_value(case, "intermediates", "transcript"));
    let mut bindings = Vec::new();
    for prefix in ["old", "new"] {
        let der = base64url_decode(named_value(case, "inputs", &format!("{prefix}_spki_der")));
        assert_eq!(der.len(), 91);
        assert_eq!(&der[..spki_prefix.len()], spki_prefix);
        let x: [u8; 32] = der[spki_prefix.len()..spki_prefix.len() + 32]
            .try_into()
            .unwrap();
        let y: [u8; 32] = der[spki_prefix.len() + 32..].try_into().unwrap();
        let key = P256PublicJwk::from_coordinates(&x, &y).unwrap();
        let signature_name = format!("{prefix}_spki_signature");
        let signature = base64url_decode(output_value(case, &signature_name));
        assert_eq!(verify_p1363_low_s(&key, &transcript, &signature), Ok(()));
        bindings.push((prefix, key, signature));
    }

    let mut transcript_mutations = 0;
    for mutation in case.member("mutations").array() {
        if !mutation.member("field").string().starts_with("transcript.") {
            continue;
        }
        let mutated = transcript_with_mutation(case, mutation);
        for (_, key, signature) in &bindings {
            unauthenticated(verify_p1363_low_s(key, &mutated, signature));
        }
        transcript_mutations += 1;
    }
    assert_eq!(transcript_mutations, 13);

    for (prefix, key, signature) in bindings {
        let altered_id = format!(
            "rotation.control-spki.m{}",
            if prefix == "old" { "13" } else { "14" }
        );
        let high_id = format!(
            "rotation.control-spki.m{}",
            if prefix == "old" { "15" } else { "20" }
        );
        let mut altered = signature.clone();
        *altered.last_mut().unwrap() ^= 1;
        unauthenticated(verify_p1363_low_s(&key, &transcript, &altered));
        let high = base64url_decode(substitute_value(
            case,
            &format!("{prefix}_spki_signature.high-s"),
        ));
        unauthenticated(verify_p1363_low_s(&key, &transcript, &high));
        assert!(
            case.member("mutations")
                .array()
                .iter()
                .any(|mutation| mutation.member("id").string() == altered_id)
        );
        assert!(
            case.member("mutations")
                .array()
                .iter()
                .any(|mutation| mutation.member("id").string() == high_id)
        );
    }
}

#[test]
fn every_published_bounded_protocol_transcript_is_reencoded_exactly() {
    let vector_files = [
        "control-bootstrap-recovery.json",
        "interactive-enrollment.json",
        "key-rotations.json",
        "managed-enrollment.json",
        "mqtt-v2-aead.json",
    ];
    let mut consumed = 0;

    for file in vector_files {
        let set = parse_json(&fixture(&format!("vectors/{file}")));
        for case in set.member("cases").array() {
            let intermediates = case.member("intermediates").array();
            let Some(domain) = intermediates
                .iter()
                .find(|value| value.member("name").string() == "transcript.encoded.domain-purpose")
            else {
                continue;
            };
            if !intermediates
                .iter()
                .any(|value| value.member("name").string() == "transcript")
            {
                continue;
            }

            let domain = hex_decode(domain.member("value").string());
            let purpose_length = usize::from(u16::from_be_bytes(domain[..2].try_into().unwrap()));
            assert_eq!(domain.len(), purpose_length + 2);
            let purpose = std::str::from_utf8(&domain[2..]).unwrap();
            let mut decoded_fields = Vec::new();
            for value in intermediates {
                let name = value.member("name").string();
                if !name.starts_with("transcript.encoded.")
                    || matches!(
                        name,
                        "transcript.encoded.header" | "transcript.encoded.domain-purpose"
                    )
                {
                    continue;
                }
                let encoded = hex_decode(value.member("value").string());
                let name_length = usize::from(u16::from_be_bytes(encoded[..2].try_into().unwrap()));
                let value_length_at = 2 + name_length;
                let field_name = std::str::from_utf8(&encoded[2..value_length_at]).unwrap();
                let value_length = u32::from_be_bytes(
                    encoded[value_length_at..value_length_at + 4]
                        .try_into()
                        .unwrap(),
                ) as usize;
                assert_eq!(encoded.len(), value_length_at + 4 + value_length);
                decoded_fields.push((
                    field_name.to_owned(),
                    encoded[value_length_at + 4..].to_vec(),
                ));
            }
            let fields: Vec<_> = decoded_fields
                .iter()
                .map(|(name, value)| TranscriptField::new(name, value))
                .collect();
            let actual = encode_transcript(purpose, &fields, 4096).unwrap();
            assert_eq!(
                actual,
                hex_decode(named_value(case, "intermediates", "transcript")),
                "transcript mismatch for {}",
                case.member("id").string()
            );
            assert!(actual.len() <= 4096);
            let expected_names: Vec<_> = decoded_fields
                .iter()
                .map(|(name, _)| name.as_str())
                .collect();
            let decoded = decode_transcript(&actual, purpose, &expected_names, 4096).unwrap();
            assert_eq!(decoded.len(), decoded_fields.len());
            for (actual_field, (expected_name, expected_value)) in
                decoded.iter().zip(&decoded_fields)
            {
                assert_eq!(actual_field.name(), expected_name);
                assert_eq!(actual_field.value(), expected_value);
            }
            consumed += 1;
        }
    }

    assert_eq!(
        consumed, 8,
        "new bounded transcript vectors require explicit consumption"
    );
}
