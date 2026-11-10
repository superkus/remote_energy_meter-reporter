//! Narrow RFC 9421 request signatures: `reporter-rfc9421-v1` and `control-rfc9421-v1`
//! (wire profile sections 7–9).
//!
//! [`verify_request`] admits a raw request in the profile's deterministic order and returns the
//! first matching [`ErrorClass`]:
//!
//! 1. route lookup on the exact raw target ([`super::routes::lookup_route`]);
//! 2. header count/size caps and per-header caps → `headers_too_large`;
//! 3. body cap → `request_body_too_large`; `Content-Encoding`, or a missing, wrong, or parameterized
//!    `Content-Type` → `unsupported_media_type`;
//! 4. malformed authority, header, framing header, REM header, `Content-Digest`, digest mismatch,
//!    non-canonical JSON, or a body `mode` that selects no purpose → `invalid_request`;
//! 5. anything about the signature — missing/duplicate headers, labels, component list or order,
//!    parameter set or order, parameter/header disagreement, purpose, `alg`, `keyid`, generation,
//!    authority, freshness, signature bytes, high-S → `authentication_required`.
//!
//! The `Signature-Input` value is parsed with a grammar that accepts only the byte-exact
//! serialization the profile produces; the signature base is rebuilt from the received raw
//! method, authority, path, query, and trimmed header values (no decoding or normalization).
//! Reporter signatures carry no `created` parameter or other client clock. Control routes enforce
//! the section 8.3 `created`/`expires`/`nonce` window against the caller-supplied server receipt
//! time.
//!
//! Replay protection is stateful and lives outside this module. [`VerifiedIdentity`] retains the
//! exact admitted request, an unambiguous request hash, the stable principal from the trusted key
//! binding, and the control nonce/expiry or reporter session/sequence needed by later replay logic.

use std::fmt;

use sha2::{Digest, Sha256};

use super::ErrorClass;
use super::b64u::{B64u, decode_standard_exact, encode_standard};
use super::canonical_json::CanonicalJson;
use super::content_digest::{CONTENT_DIGEST_HEADER_MAX_BYTES, ContentDigest};
use super::jwk::P256PublicJwk;
use super::parse_canonical_u64;
use super::routes::{
    DUAL_SIGNATURE_ROUTE_ID, HEADER_BYTES_MAX, HEADER_COUNT_MAX, RouteMatch,
    SIGNATURE_HEADER_MAX_BYTES, SIGNATURE_INPUT_HEADER_MAX_BYTES, SignatureProfile, lookup_route,
};
use super::signature::verify_p1363_low_s;

/// The only signature algorithm.
pub const ALGORITHM: &str = "ecdsa-p256-sha256";
/// The primary signature label.
pub const LABEL: &str = "rem";
/// The second label, used only on `control.control-key-rotation.complete`.
pub const PROPOSED_LABEL: &str = "rem-proposed";
/// Longest valid received authority: 253-byte host, colon, and five-digit port.
/// Transport adapters must enforce this while parsing, before buffering an oversized authority.
pub const AUTHORITY_MAX_BYTES: usize = 259;
/// Largest accepted clock lead of control `created` over server receipt time, in seconds.
pub const CONTROL_CREATED_MAX_LEAD_SECONDS: u64 = 30;
/// Longest control signature lifetime (`expires - created`), in seconds.
pub const CONTROL_LIFETIME_MAX_SECONDS: u64 = 60;
const JSON_MEDIA_TYPE: &[u8] = b"application/json";
const PURPOSE_MAX_BYTES: usize = 64;

/// One received header field, exactly as framed by the transport.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct HeaderField {
    /// Field name (matched case-insensitively).
    pub name: Vec<u8>,
    /// Raw field value; leading and trailing SP/HTAB are not significant.
    pub value: Vec<u8>,
}

impl fmt::Debug for HeaderField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HeaderField")
            .field("name_len", &self.name.len())
            .field("value_len", &self.value.len())
            .finish()
    }
}

/// A received request as raw bytes, before any decoding.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RawRequest {
    /// Method, e.g. `POST`.
    pub method: Vec<u8>,
    /// Received authority (`host:port`).
    pub authority: Vec<u8>,
    /// Raw request target (path and optional query).
    pub target: Vec<u8>,
    /// Header fields in received order.
    pub headers: Vec<HeaderField>,
    /// Exact received body bytes (empty for bodyless routes).
    pub body: Vec<u8>,
}

impl fmt::Debug for RawRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawRequest")
            .field("method_len", &self.method.len())
            .field("authority_len", &self.authority.len())
            .field("target_len", &self.target.len())
            .field("header_count", &self.headers.len())
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// A public key the verifier may accept for one signature label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationKey {
    /// Stable authenticated principal ID, independent of active-key rotation. Both keys on the
    /// dual-signature route must carry the same principal ID.
    pub stable_principal_id: B64u<32>,
    /// `rem` for the active key, `rem-proposed` for the proposed control key.
    pub label: Vec<u8>,
    /// The key.
    pub jwk: P256PublicJwk,
    /// Durable control key generation; `None` for reporter keys.
    pub generation: Option<u64>,
}

/// Server-side configuration and state the verifier needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationContext {
    /// The dispatcher-selected manifest route. The request target must resolve to this exact route.
    pub expected_route_id: &'static str,
    /// The configured identity authority (`host:port`) the request must name exactly.
    pub expected_authority: Vec<u8>,
    /// Server receipt time in Unix seconds (the core's clock, never the client's).
    pub received_at: u64,
    /// Candidate keys by label; each label may appear at most once.
    pub keys: Vec<VerificationKey>,
}

/// The stable, comparable outcome of a successful verification, for replay logic.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct VerifiedIdentity {
    request: RawRequest,
    request_hash: [u8; 32],
    route_id: &'static str,
    raw_query: Option<Vec<u8>>,
    named_query: Vec<(String, Vec<u8>)>,
    purpose: Vec<u8>,
    stable_principal_id: [u8; 32],
    keyid: Vec<u8>,
    proposed_keyid: Option<Vec<u8>>,
    key_generation: Option<u64>,
    created: Option<u64>,
    nonce: Option<[u8; 16]>,
    expires: Option<u64>,
    session_id: Option<[u8; 16]>,
    sequence: Option<u64>,
    content_digest: Option<[u8; 32]>,
}

impl fmt::Debug for VerifiedIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedIdentity")
            .field("route_id", &self.route_id)
            .field("request_header_count", &self.request.headers.len())
            .field("request_body_len", &self.request.body.len())
            .field("named_query_count", &self.named_query.len())
            .field("has_raw_query", &self.raw_query.is_some())
            .field("has_proposed_keyid", &self.proposed_keyid.is_some())
            .field("has_control_nonce", &self.nonce.is_some())
            .field("has_reporter_session", &self.session_id.is_some())
            .field("has_content_digest", &self.content_digest.is_some())
            .finish()
    }
}

impl VerifiedIdentity {
    /// The complete exact request admitted by the verifier.
    #[must_use]
    pub const fn request(&self) -> &RawRequest {
        &self.request
    }
    /// SHA-256 of the unambiguous length-delimited exact request representation.
    #[must_use]
    pub const fn request_hash(&self) -> &[u8; 32] {
        &self.request_hash
    }
    /// Manifest route ID.
    #[must_use]
    pub const fn route_id(&self) -> &'static str {
        self.route_id
    }
    /// Exact method.
    #[must_use]
    pub fn method(&self) -> &[u8] {
        &self.request.method
    }
    /// Exact authority.
    #[must_use]
    pub fn authority(&self) -> &[u8] {
        &self.request.authority
    }
    /// Exact raw target.
    #[must_use]
    pub fn target(&self) -> &[u8] {
        &self.request.target
    }
    /// Exact raw query without `?`, when the route has one.
    #[must_use]
    pub fn raw_query(&self) -> Option<&[u8]> {
        self.raw_query.as_deref()
    }
    /// Exact signed value of named query input `name`.
    #[must_use]
    pub fn named_query(&self, name: &str) -> Option<&[u8]> {
        self.named_query
            .iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, value)| value.as_slice())
    }
    /// The verified purpose label.
    #[must_use]
    pub fn purpose(&self) -> &[u8] {
        &self.purpose
    }
    /// Stable authenticated principal identity selected by the trusted key binding.
    #[must_use]
    pub const fn stable_principal_id(&self) -> &[u8; 32] {
        &self.stable_principal_id
    }
    /// The `rem` keyid (canonical b64u thumbprint text).
    #[must_use]
    pub fn keyid(&self) -> &[u8] {
        &self.keyid
    }
    /// The `rem-proposed` keyid, on the dual-signature route.
    #[must_use]
    pub fn proposed_keyid(&self) -> Option<&[u8]> {
        self.proposed_keyid.as_deref()
    }
    /// Control key generation (control routes only).
    #[must_use]
    pub const fn key_generation(&self) -> Option<u64> {
        self.key_generation
    }
    /// Control signature `created` value. Reporter signatures carry no client clock.
    #[must_use]
    pub const fn created(&self) -> Option<u64> {
        self.created
    }
    /// Decoded control request nonce (control routes only).
    #[must_use]
    pub fn nonce(&self) -> Option<&[u8]> {
        self.nonce.as_ref().map(<[u8; 16]>::as_slice)
    }
    /// Control signature expiry (control routes only).
    #[must_use]
    pub const fn expires(&self) -> Option<u64> {
        self.expires
    }
    /// Decoded reporter session ID (report route only).
    #[must_use]
    pub fn session_id(&self) -> Option<&[u8]> {
        self.session_id.as_ref().map(<[u8; 16]>::as_slice)
    }
    /// Reporter sequence number (report route only).
    #[must_use]
    pub const fn sequence(&self) -> Option<u64> {
        self.sequence
    }
    /// SHA-256 body digest (body routes only).
    #[must_use]
    pub const fn content_digest(&self) -> Option<&[u8; 32]> {
        self.content_digest.as_ref()
    }
}

/// A request whose signature(s) verified.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedRequest {
    identity: VerifiedIdentity,
    bases: Vec<(&'static str, Vec<u8>)>,
}

impl fmt::Debug for VerifiedRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedRequest")
            .field("route_id", &self.identity.route_id)
            .field("signature_base_count", &self.bases.len())
            .finish()
    }
}

impl VerifiedRequest {
    /// The verified identity.
    #[must_use]
    pub const fn identity(&self) -> &VerifiedIdentity {
        &self.identity
    }
    /// The exact signature base that verified under `label`.
    #[must_use]
    pub fn signature_base(&self, label: &str) -> Option<&[u8]> {
        self.bases
            .iter()
            .find(|(candidate, _)| *candidate == label)
            .map(|(_, base)| base.as_slice())
    }
}

/// The signer's view of one label: its `Signature-Input` member value and the bytes to sign.
#[derive(Clone, PartialEq, Eq)]
pub struct SignatureMaterial {
    signature_params: String,
    signature_base: Vec<u8>,
}

impl fmt::Debug for SignatureMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignatureMaterial")
            .field("signature_params_len", &self.signature_params.len())
            .field("signature_base_len", &self.signature_base.len())
            .finish()
    }
}

impl SignatureMaterial {
    /// The member value after `label=` (inner list and parameters).
    #[must_use]
    pub fn signature_params(&self) -> &str {
        &self.signature_params
    }
    /// The exact signature base to sign with ECDSA P-256/SHA-256 (low-S, P1363).
    #[must_use]
    pub fn signature_base(&self) -> &[u8] {
        &self.signature_base
    }
}

/// Build stateless pre-signature material for one label of an otherwise complete request.
///
/// This helper applies the request-shape checks needed before signing: route lookup, caps, media
/// type, framing, digest, canonical body, REM headers, and purpose. It does not provide the
/// contextual or stateful guarantees of [`verify_request`]. The verifier or caller must still bind
/// the dispatcher-selected route, configured authority, trusted key and generation, and control
/// freshness; verify the signature; and enforce replay protection. Reporter signatures must pass
/// `None` because the profile omits client-clock time. Control signatures must pass
/// `Some(created)`; `expires` and `nonce` are taken from the `REM-Request-Expires` and
/// `REM-Request-Nonce` headers they must equal.
///
/// # Errors
/// The first admission failure's class, or [`ErrorClass::AuthenticationRequired`] for an unsigned
/// route or a label the route does not use.
pub fn signature_material(
    request: &RawRequest,
    label: &str,
    keyid: &B64u<32>,
    created: Option<u64>,
) -> Result<SignatureMaterial, ErrorClass> {
    let admitted = admit(request)?;
    if !admitted.labels().contains(&label)
        || matches!(
            (admitted.profile, created),
            (SignatureProfile::ReporterRfc9421V1, Some(_))
                | (SignatureProfile::ControlRfc9421V1, None)
        )
    {
        return Err(ErrorClass::AuthenticationRequired);
    }
    let params = Params {
        created,
        control: admitted.control.as_ref().map(|control| ControlParams {
            expires: control.expires,
            nonce: control.nonce.clone(),
        }),
        keyid: keyid.as_str().to_owned(),
        alg: ALGORITHM.to_owned(),
        tag: admitted.purpose.to_owned(),
    };
    let signature_params = admitted.serialize_params(&params);
    let signature_base = admitted.signature_base(request, &signature_params);
    Ok(SignatureMaterial {
        signature_params,
        signature_base,
    })
}

/// Render a `Signature-Input` header value from `(label, material)` members in order.
#[must_use]
pub fn render_signature_input(members: &[(&str, &SignatureMaterial)]) -> String {
    members
        .iter()
        .map(|(label, material)| format!("{label}={}", material.signature_params))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Render a `Signature` header value from `(label, P1363 signature)` members in order.
#[must_use]
pub fn render_signature(members: &[(&str, &[u8; 64])]) -> String {
    members
        .iter()
        .map(|(label, signature)| format!("{label}=:{}:", encode_standard(signature.as_slice())))
        .collect::<Vec<_>>()
        .join(", ")
}

fn exact_request_hash(request: &RawRequest) -> [u8; 32] {
    let mut digest = Sha256::new();
    for value in [
        request.method.as_slice(),
        request.authority.as_slice(),
        request.target.as_slice(),
        request.body.as_slice(),
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    digest.update((request.headers.len() as u32).to_be_bytes());
    for header in &request.headers {
        digest.update((header.name.len() as u32).to_be_bytes());
        digest.update(&header.name);
        digest.update((header.value.len() as u64).to_be_bytes());
        digest.update(&header.value);
    }
    digest.finalize().into()
}

struct ParsedSignatures {
    members: Vec<(String, Params)>,
    signatures: Vec<[u8; 64]>,
}

struct BoundKeys<'a> {
    keys: Vec<&'a VerificationKey>,
}

/// Verify a signed reporter or control request.
///
/// # Errors
/// The first failing admission class, in the order documented on this module.
pub fn verify_request(
    request: &RawRequest,
    context: &VerificationContext,
) -> Result<VerifiedRequest, ErrorClass> {
    verify_selected_route(request, context)?;
    let admitted = admit(request)?;
    let parsed = parse_signatures(request, &admitted)?;
    let bound = bind_keys(context, &admitted, &parsed.members)?;
    validate_signature_relationships(&parsed.members, &bound)?;
    validate_signature_context(request, context, &admitted, &parsed.members, &bound)?;
    let bases = verify_signature_bytes(request, &admitted, &parsed, &bound)?;
    let identity = verified_identity(request, &admitted, &parsed.members, &bound);
    Ok(VerifiedRequest { identity, bases })
}

fn verify_selected_route(
    request: &RawRequest,
    context: &VerificationContext,
) -> Result<(), ErrorClass> {
    let selected_route = lookup_route(&request.method, &request.target)?;
    if selected_route.id() != context.expected_route_id {
        return Err(ErrorClass::InvalidRequest);
    }
    Ok(())
}

fn parse_signatures(
    request: &RawRequest,
    admitted: &Admitted<'_>,
) -> Result<ParsedSignatures, ErrorClass> {
    let labels = admitted.labels();
    let auth = ErrorClass::AuthenticationRequired;
    let signature_input = single_raw_header(&request.headers, b"signature-input")
        .map(trim)
        .ok_or(auth)?;
    let signature = single_raw_header(&request.headers, b"signature")
        .map(trim)
        .ok_or(auth)?;
    let signature_input = std::str::from_utf8(signature_input).map_err(|_| auth)?;
    let signature = std::str::from_utf8(signature).map_err(|_| auth)?;
    Ok(ParsedSignatures {
        members: admitted.parse_signature_input(signature_input, labels)?,
        signatures: parse_signature(signature, labels)?,
    })
}

fn bind_keys<'a>(
    context: &'a VerificationContext,
    admitted: &Admitted<'_>,
    members: &[(String, Params)],
) -> Result<BoundKeys<'a>, ErrorClass> {
    let labels = admitted.labels();
    let auth = ErrorClass::AuthenticationRequired;
    let mut keys = Vec::with_capacity(labels.len());
    for (label, (_, params)) in labels.iter().zip(members) {
        let mut candidates = context
            .keys
            .iter()
            .filter(|key| key.label == label.as_bytes());
        let key = candidates.next().ok_or(auth)?;
        if candidates.next().is_some()
            || params.keyid != key.jwk.thumbprint_b64u().as_str()
            || params.alg != ALGORITHM
            || params.tag != admitted.purpose
        {
            return Err(auth);
        }
        keys.push(key);
    }
    Ok(BoundKeys { keys })
}

fn validate_signature_relationships(
    members: &[(String, Params)],
    bound: &BoundKeys<'_>,
) -> Result<(), ErrorClass> {
    let auth = ErrorClass::AuthenticationRequired;
    let (_, primary) = &members[0];
    if bound
        .keys
        .iter()
        .skip(1)
        .any(|key| key.stable_principal_id != bound.keys[0].stable_principal_id)
    {
        return Err(auth);
    }
    if let Some((_, proposed)) = members.get(1)
        && (proposed.created != primary.created
            || proposed.control != primary.control
            || proposed.keyid == primary.keyid)
    {
        return Err(auth);
    }
    Ok(())
}

fn validate_signature_context(
    request: &RawRequest,
    context: &VerificationContext,
    admitted: &Admitted<'_>,
    members: &[(String, Params)],
    bound: &BoundKeys<'_>,
) -> Result<(), ErrorClass> {
    let auth = ErrorClass::AuthenticationRequired;
    if request.authority != context.expected_authority {
        return Err(auth);
    }
    let (_, primary) = &members[0];
    match (&admitted.control, &primary.control) {
        (Some(headers), Some(params)) => {
            let proposed_generation_ok = bound.keys.get(1).is_none_or(|proposed| {
                headers
                    .generation
                    .checked_add(1)
                    .is_some_and(|next| proposed.generation == Some(next))
            });
            if bound.keys[0].generation != Some(headers.generation)
                || !proposed_generation_ok
                || params.expires != headers.expires
                || params.nonce != headers.nonce
                || !primary.created.is_some_and(|created| {
                    control_is_fresh(created, params.expires, context.received_at)
                })
            {
                return Err(auth);
            }
        }
        (None, None) => {
            if bound.keys[0].generation.is_some() {
                return Err(auth);
            }
        }
        _ => return Err(auth),
    }
    Ok(())
}

fn verify_signature_bytes(
    request: &RawRequest,
    admitted: &Admitted<'_>,
    parsed: &ParsedSignatures,
    bound: &BoundKeys<'_>,
) -> Result<Vec<(&'static str, Vec<u8>)>, ErrorClass> {
    let labels = admitted.labels();
    let mut bases = Vec::with_capacity(labels.len());
    for (((label, (raw_params, _)), key), signature) in labels
        .iter()
        .zip(&parsed.members)
        .zip(&bound.keys)
        .zip(&parsed.signatures)
    {
        let base = admitted.signature_base(request, raw_params);
        verify_p1363_low_s(&key.jwk, &base, signature)?;
        bases.push((*label, base));
    }
    Ok(bases)
}

fn verified_identity(
    request: &RawRequest,
    admitted: &Admitted<'_>,
    members: &[(String, Params)],
    bound: &BoundKeys<'_>,
) -> VerifiedIdentity {
    let (_, primary) = &members[0];
    VerifiedIdentity {
        request: request.clone(),
        request_hash: exact_request_hash(request),
        route_id: admitted.route.id(),
        raw_query: admitted
            .route
            .raw_query()
            .map(|query| query.as_bytes().to_vec()),
        named_query: admitted
            .route
            .named_query()
            .iter()
            .map(|(name, value)| ((*name).to_owned(), value.as_bytes().to_vec()))
            .collect(),
        purpose: admitted.purpose.as_bytes().to_vec(),
        stable_principal_id: *bound.keys[0].stable_principal_id.as_array(),
        keyid: primary.keyid.as_bytes().to_vec(),
        proposed_keyid: members
            .get(1)
            .map(|(_, proposed)| proposed.keyid.as_bytes().to_vec()),
        key_generation: admitted.control.as_ref().map(|control| control.generation),
        created: primary.created,
        nonce: admitted
            .control
            .as_ref()
            .map(|control| *control.nonce.as_array()),
        expires: admitted.control.as_ref().map(|control| control.expires),
        session_id: admitted
            .report
            .as_ref()
            .map(|report| *report.session_id.as_array()),
        sequence: admitted.report.as_ref().map(|report| report.sequence),
        content_digest: admitted.content_digest.map(|digest| *digest.sha256()),
    }
}

/// Section 8.3 at server receipt time: `created <= now + 30`,
/// `created + 1 <= expires <= created + 60`, and `now <= expires`.
fn control_is_fresh(created: u64, expires: u64, now: u64) -> bool {
    let lead_ok = created <= now
        || created
            .checked_sub(now)
            .is_some_and(|lead| lead <= CONTROL_CREATED_MAX_LEAD_SECONDS);
    let lifetime_ok = expires
        .checked_sub(created)
        .is_some_and(|lifetime| (1..=CONTROL_LIFETIME_MAX_SECONDS).contains(&lifetime));
    lead_ok && lifetime_ok && now <= expires
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ControlHeaders {
    generation: u64,
    nonce: B64u<16>,
    expires: u64,
}

#[derive(Clone, Debug)]
struct ReportHeaders {
    session_id: B64u<16>,
    sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ControlParams {
    expires: u64,
    nonce: B64u<16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Params {
    created: Option<u64>,
    control: Option<ControlParams>,
    keyid: String,
    alg: String,
    tag: String,
}

/// A request admitted through every check before the signature step.
struct Admitted<'a> {
    route: RouteMatch<'a>,
    profile: SignatureProfile,
    purpose: &'static str,
    control: Option<ControlHeaders>,
    report: Option<ReportHeaders>,
    content_digest: Option<ContentDigest>,
}

#[derive(Clone, Copy)]
enum Component<'a> {
    Method,
    Authority,
    Path,
    Query,
    QueryParam(&'a str),
    Header(&'static str),
}

fn header_matches(field: &HeaderField, name: &[u8]) -> bool {
    field.name.eq_ignore_ascii_case(name)
}

fn trim(value: &[u8]) -> &[u8] {
    let is_ows = |byte: &u8| matches!(byte, b' ' | b'\t');
    let start = value
        .iter()
        .position(|byte| !is_ows(byte))
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|byte| !is_ows(byte))
        .map_or(start, |end| end + 1);
    &value[start..end]
}

fn header_count(headers: &[HeaderField], name: &[u8]) -> usize {
    headers
        .iter()
        .filter(|field| header_matches(field, name))
        .count()
}

/// The unmodified value of a header that appears exactly once.
fn single_raw_header<'h>(headers: &'h [HeaderField], name: &[u8]) -> Option<&'h [u8]> {
    let mut matching = headers.iter().filter(|field| header_matches(field, name));
    let value = matching.next()?;
    matching.next().is_none().then_some(value.value.as_slice())
}

/// The trimmed value of a header that appears exactly once.
fn single_header<'h>(headers: &'h [HeaderField], name: &[u8]) -> Option<&'h [u8]> {
    single_raw_header(headers, name).map(trim)
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn parse_ipv4_component(component: &[u8]) -> Option<u64> {
    let (digits, radix) = if let Some(hex) = component.strip_prefix(b"0x") {
        (hex, 16)
    } else if component.len() > 1 && component.starts_with(b"0") {
        (component, 8)
    } else {
        (component, 10)
    };
    if digits.is_empty() {
        return None;
    }
    digits.iter().try_fold(0_u64, |value, byte| {
        let digit = match *byte {
            b'0'..=b'9' => u64::from(byte - b'0'),
            b'a'..=b'f' if radix == 16 => u64::from(byte - b'a' + 10),
            _ => return None,
        };
        (digit < radix).then_some(())?;
        value.checked_mul(radix)?.checked_add(digit)
    })
}

fn is_numeric_address_form(host: &[u8]) -> bool {
    let components: Vec<_> = host.split(|byte| *byte == b'.').collect();
    if !(1..=4).contains(&components.len()) {
        return false;
    }
    let Some((last, leading)) = components.split_last() else {
        return false;
    };
    if leading
        .iter()
        .any(|component| parse_ipv4_component(component).is_none_or(|value| value > 255))
    {
        return false;
    }
    let last_bits = 8 * (5 - components.len());
    parse_ipv4_component(last).is_some_and(|value| value < (1_u64 << last_bits))
}

fn is_valid_authority(authority: &[u8]) -> bool {
    if authority.len() > AUTHORITY_MAX_BYTES {
        return false;
    }
    let Some(colon) = authority.iter().rposition(|byte| *byte == b':') else {
        return false;
    };
    let (host, port) = (&authority[..colon], &authority[colon + 1..]);
    if !(1..=253).contains(&host.len()) {
        return false;
    }
    let labels_ok = host.split(|byte| *byte == b'.').all(|label| {
        (1..=63).contains(&label.len())
            && label
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
            && !label.starts_with(b"-")
            && !label.ends_with(b"-")
            && (label.get(2..4) != Some(b"--") || label.starts_with(b"xn--"))
    });
    if !labels_ok || is_numeric_address_form(host) {
        return false;
    }
    let canonical_idna = !host
        .split(|byte| *byte == b'.')
        .any(|label| label.starts_with(b"xn--"))
        || std::str::from_utf8(host).is_ok_and(|host| {
            idna::domain_to_ascii_strict(host)
                .is_ok_and(|ascii| ascii.as_bytes() == host.as_bytes())
        });
    let port_ok = parse_canonical_u64(port).is_some_and(|port| (1..=65535).contains(&port));
    canonical_idna && port_ok
}

fn is_purpose_label(value: &[u8]) -> bool {
    (1..=PURPOSE_MAX_BYTES).contains(&value.len())
        && value.split(|byte| *byte == b'-').all(|part| {
            !part.is_empty()
                && part
                    .iter()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

fn parse_b64u16_header(headers: &[HeaderField], name: &[u8]) -> Result<B64u<16>, ErrorClass> {
    single_header(headers, name)
        .and_then(|value| std::str::from_utf8(value).ok())
        .ok_or(ErrorClass::InvalidRequest)
        .and_then(B64u::<16>::parse)
}

fn parse_u64_header(headers: &[HeaderField], name: &[u8]) -> Result<u64, ErrorClass> {
    single_header(headers, name)
        .and_then(parse_canonical_u64)
        .ok_or(ErrorClass::InvalidRequest)
}

struct AdmissionRoute<'a> {
    route: RouteMatch<'a>,
    profile: SignatureProfile,
}

struct AdmittedBody {
    content_digest: Option<ContentDigest>,
    canonical: Option<CanonicalJson>,
}

struct RemHeaders<'a> {
    purpose: &'a [u8],
    control: Option<ControlHeaders>,
    report: Option<ReportHeaders>,
}

/// Run every admission check that precedes signature verification.
fn admit(request: &RawRequest) -> Result<Admitted<'_>, ErrorClass> {
    let selected = admit_route(request)?;
    admit_header_caps(&request.headers)?;
    admit_body_and_media_type(request, &selected.route)?;
    admit_header_grammar_and_framing(request)?;
    let body = admit_digest_and_canonical_body(request, &selected.route)?;
    let rem = admit_rem_headers(&request.headers, &selected)?;
    let purpose = select_purpose(&selected.route, body.canonical.as_ref())?;
    admit_purpose(rem.purpose, purpose)?;

    Ok(Admitted {
        route: selected.route,
        profile: selected.profile,
        purpose,
        control: rem.control,
        report: rem.report,
        content_digest: body.content_digest,
    })
}

fn admit_route(request: &RawRequest) -> Result<AdmissionRoute<'_>, ErrorClass> {
    let route = lookup_route(&request.method, &request.target)?;
    let profile = route
        .signature_profile()
        .ok_or(ErrorClass::AuthenticationRequired)?;
    Ok(AdmissionRoute { route, profile })
}

fn admit_header_caps(headers: &[HeaderField]) -> Result<(), ErrorClass> {
    // Reject the field count before inspecting attacker-controlled fields, so the work below is
    // bounded by the manifest limit even if a transport adapter violates its cap.
    if headers.len() > HEADER_COUNT_MAX {
        return Err(ErrorClass::HeadersTooLarge);
    }
    let total: usize = headers
        .iter()
        .map(|field| field.name.len().saturating_add(field.value.len()))
        .fold(0, usize::saturating_add);
    let oversized = headers.iter().any(|field| {
        let cap = if header_matches(field, b"signature") {
            SIGNATURE_HEADER_MAX_BYTES
        } else if header_matches(field, b"signature-input") {
            SIGNATURE_INPUT_HEADER_MAX_BYTES
        } else if header_matches(field, b"content-digest") {
            CONTENT_DIGEST_HEADER_MAX_BYTES
        } else {
            HEADER_BYTES_MAX
        };
        field.value.len() > cap
    });
    if total > HEADER_BYTES_MAX || oversized {
        return Err(ErrorClass::HeadersTooLarge);
    }
    Ok(())
}

fn admit_body_and_media_type(
    request: &RawRequest,
    route: &RouteMatch<'_>,
) -> Result<(), ErrorClass> {
    if request.body.len() > route.request_body_max_bytes() {
        return Err(ErrorClass::RequestBodyTooLarge);
    }
    if header_count(&request.headers, b"content-encoding") != 0 {
        return Err(ErrorClass::UnsupportedMediaType);
    }
    if route.has_body() {
        if single_header(&request.headers, b"content-type") != Some(JSON_MEDIA_TYPE) {
            return Err(ErrorClass::UnsupportedMediaType);
        }
    } else if header_count(&request.headers, b"content-type") != 0 {
        return Err(ErrorClass::UnsupportedMediaType);
    }
    Ok(())
}

fn admit_header_grammar_and_framing(request: &RawRequest) -> Result<(), ErrorClass> {
    let headers = request.headers.as_slice();
    let invalid = ErrorClass::InvalidRequest;
    if headers.iter().any(|field| {
        field.name.is_empty()
            || !field.name.iter().copied().all(is_token_byte)
            || (!header_matches(field, b"signature")
                && !header_matches(field, b"signature-input")
                && !field
                    .value
                    .iter()
                    .all(|byte| matches!(byte, b'\t' | b' '..=b'~')))
    }) {
        return Err(invalid);
    }
    if !is_valid_authority(&request.authority) {
        return Err(invalid);
    }
    if header_count(headers, b"host") != 0
        && single_header(headers, b"host") != Some(request.authority.as_slice())
    {
        return Err(invalid);
    }
    if header_count(headers, b"transfer-encoding") != 0
        || header_count(headers, b"repr-digest") != 0
    {
        return Err(invalid);
    }
    if header_count(headers, b"content-length") != 0 {
        let length = single_header(headers, b"content-length")
            .and_then(parse_canonical_u64)
            .ok_or(invalid)?;
        if usize::try_from(length).ok() != Some(request.body.len()) {
            return Err(invalid);
        }
    }
    Ok(())
}

fn admit_digest_and_canonical_body(
    request: &RawRequest,
    route: &RouteMatch<'_>,
) -> Result<AdmittedBody, ErrorClass> {
    let invalid = ErrorClass::InvalidRequest;
    if route.has_body() {
        let digest = single_header(&request.headers, b"content-digest")
            .and_then(|value| std::str::from_utf8(value).ok())
            .ok_or(invalid)
            .and_then(ContentDigest::parse_exact)?;
        digest.verify(&request.body)?;
        Ok(AdmittedBody {
            content_digest: Some(digest),
            canonical: Some(CanonicalJson::parse_exact(&request.body)?),
        })
    } else {
        if header_count(&request.headers, b"content-digest") != 0 {
            return Err(invalid);
        }
        Ok(AdmittedBody {
            content_digest: None,
            canonical: None,
        })
    }
}

fn admit_rem_headers<'a>(
    headers: &'a [HeaderField],
    selected: &AdmissionRoute<'_>,
) -> Result<RemHeaders<'a>, ErrorClass> {
    let invalid = ErrorClass::InvalidRequest;
    let allowed: &[&[u8]] = match (selected.profile, selected.route.id()) {
        (SignatureProfile::ReporterRfc9421V1, "reporter.report.create") => {
            &[b"rem-purpose", b"rem-session-id", b"rem-sequence"]
        }
        (SignatureProfile::ReporterRfc9421V1, _) => &[b"rem-purpose"],
        (SignatureProfile::ControlRfc9421V1, _) => &[
            b"rem-purpose",
            b"rem-control-key-generation",
            b"rem-request-nonce",
            b"rem-request-expires",
        ],
    };
    if headers.iter().any(|field| {
        field.name.len() >= 4
            && field.name[..4].eq_ignore_ascii_case(b"rem-")
            && !allowed.iter().any(|name| header_matches(field, name))
    }) {
        return Err(invalid);
    }
    let purpose = single_header(headers, b"rem-purpose")
        .filter(|value| is_purpose_label(value))
        .ok_or(invalid)?;
    let report = (selected.route.id() == "reporter.report.create")
        .then(|| {
            Ok::<_, ErrorClass>(ReportHeaders {
                session_id: parse_b64u16_header(headers, b"rem-session-id")?,
                sequence: parse_u64_header(headers, b"rem-sequence")?,
            })
        })
        .transpose()?;
    let control = (selected.profile == SignatureProfile::ControlRfc9421V1)
        .then(|| {
            Ok::<_, ErrorClass>(ControlHeaders {
                generation: parse_u64_header(headers, b"rem-control-key-generation")?,
                nonce: parse_b64u16_header(headers, b"rem-request-nonce")?,
                expires: parse_u64_header(headers, b"rem-request-expires")?,
            })
        })
        .transpose()?;
    Ok(RemHeaders {
        purpose,
        control,
        report,
    })
}

fn select_purpose(
    route: &RouteMatch<'_>,
    body: Option<&CanonicalJson>,
) -> Result<&'static str, ErrorClass> {
    let invalid = ErrorClass::InvalidRequest;
    let mut purposes = route.purposes();
    match (purposes.next(), purposes.next()) {
        (Some(only), None) => Ok(only),
        _ if route.id() == "reporter.enrollment.create" => {
            let mode = body
                .and_then(|body| body.top_level_member("mode"))
                .ok_or(invalid)?;
            match mode {
                br#""interactive""# => Ok("rem-enroll-v1"),
                br#""managed""# => Ok("rem-managed-enroll-v1"),
                _ => Err(invalid),
            }
        }
        _ => Err(ErrorClass::AuthenticationRequired),
    }
}

fn admit_purpose(purpose_header: &[u8], purpose: &str) -> Result<(), ErrorClass> {
    if purpose_header != purpose.as_bytes() {
        return Err(ErrorClass::AuthenticationRequired);
    }
    Ok(())
}

impl<'a> Admitted<'a> {
    fn labels(&self) -> &'static [&'static str] {
        if self.route.id() == DUAL_SIGNATURE_ROUTE_ID {
            &[LABEL, PROPOSED_LABEL]
        } else {
            &[LABEL]
        }
    }

    /// The exact covered components, in profile order.
    fn components(&self) -> Vec<Component<'a>> {
        let mut components = vec![
            Component::Method,
            Component::Authority,
            Component::Path,
            Component::Query,
            Component::Header("rem-purpose"),
        ];
        match self.profile {
            SignatureProfile::ReporterRfc9421V1 => {
                if self.report.is_some() {
                    components.push(Component::Header("rem-session-id"));
                    components.push(Component::Header("rem-sequence"));
                }
            }
            SignatureProfile::ControlRfc9421V1 => {
                components.push(Component::Header("rem-control-key-generation"));
                components.push(Component::Header("rem-request-nonce"));
                components.push(Component::Header("rem-request-expires"));
            }
        }
        for (name, _) in self.route.named_query() {
            components.push(Component::QueryParam(name));
        }
        if self.route.has_body() {
            components.push(Component::Header("content-type"));
            components.push(Component::Header("content-digest"));
        }
        components
    }

    fn inner_list(&self) -> String {
        let identifiers: Vec<_> = self
            .components()
            .into_iter()
            .map(component_identifier)
            .collect();
        format!("({})", identifiers.join(" "))
    }

    fn serialize_params(&self, params: &Params) -> String {
        let mut output = self.inner_list();
        if let Some(created) = params.created {
            output.push_str(&format!(";created={created}"));
        }
        if let Some(control) = &params.control {
            output.push_str(&format!(
                ";expires={};nonce=\"{}\"",
                control.expires,
                control.nonce.as_str()
            ));
        }
        output.push_str(&format!(
            ";keyid=\"{}\";alg=\"{}\";tag=\"{}\"",
            params.keyid, params.alg, params.tag
        ));
        output
    }

    /// RFC 9421 section 2.5 base: one LF-joined line per component, then `@signature-params`.
    fn signature_base(&self, request: &RawRequest, signature_params: &str) -> Vec<u8> {
        let mut base = Vec::with_capacity(1024);
        for component in self.components() {
            base.extend_from_slice(component_identifier(component).as_bytes());
            base.extend_from_slice(b": ");
            match component {
                Component::Method => base.extend_from_slice(&request.method),
                Component::Authority => base.extend_from_slice(&request.authority),
                Component::Path => base.extend_from_slice(self.route.path().as_bytes()),
                Component::Query => {
                    base.push(b'?');
                    if let Some(query) = self.route.raw_query() {
                        base.extend_from_slice(query.as_bytes());
                    }
                }
                Component::QueryParam(name) => {
                    if let Some((_, value)) = self
                        .route
                        .named_query()
                        .iter()
                        .find(|(candidate, _)| *candidate == name)
                    {
                        base.extend_from_slice(value.as_bytes());
                    }
                }
                Component::Header(name) => {
                    // Admission guaranteed every covered header appears exactly once.
                    if let Some(value) = single_header(&request.headers, name.as_bytes()) {
                        base.extend_from_slice(value);
                    }
                }
            }
            base.push(b'\n');
        }
        base.extend_from_slice(b"\"@signature-params\": ");
        base.extend_from_slice(signature_params.as_bytes());
        base
    }

    /// Parse `Signature-Input` with a grammar accepting only the profile's exact serialization.
    /// Returns each member's raw value with its typed parameters.
    fn parse_signature_input(
        &self,
        header: &str,
        labels: &[&str],
    ) -> Result<Vec<(String, Params)>, ErrorClass> {
        let auth = ErrorClass::AuthenticationRequired;
        let inner_list = self.inner_list();
        let mut rest = header;
        let mut members = Vec::with_capacity(labels.len());
        for (index, label) in labels.iter().enumerate() {
            if index > 0 {
                rest = rest.strip_prefix(", ").ok_or(auth)?;
            }
            rest = rest
                .strip_prefix(*label)
                .and_then(|rest| rest.strip_prefix('='))
                .ok_or(auth)?;
            let member_start = rest;
            rest = rest.strip_prefix(inner_list.as_str()).ok_or(auth)?;
            let created = match self.profile {
                SignatureProfile::ControlRfc9421V1 => Some(take_integer(&mut rest, "created")?),
                SignatureProfile::ReporterRfc9421V1 => None,
            };
            let control = match self.profile {
                SignatureProfile::ControlRfc9421V1 => {
                    let expires = take_integer(&mut rest, "expires")?;
                    let nonce =
                        B64u::<16>::parse(take_string(&mut rest, "nonce")?).map_err(|_| auth)?;
                    Some(ControlParams { expires, nonce })
                }
                SignatureProfile::ReporterRfc9421V1 => None,
            };
            let keyid = take_string(&mut rest, "keyid")?.to_owned();
            let alg = take_string(&mut rest, "alg")?.to_owned();
            let tag = take_string(&mut rest, "tag")?.to_owned();
            let raw = &member_start[..member_start.len() - rest.len()];
            let params = Params {
                created,
                control,
                keyid,
                alg,
                tag,
            };
            // The grammar is exact, so re-serialization must reproduce the received bytes.
            if self.serialize_params(&params) != raw {
                return Err(auth);
            }
            members.push((raw.to_owned(), params));
        }
        if rest.is_empty() {
            Ok(members)
        } else {
            Err(auth)
        }
    }
}

fn component_identifier(component: Component<'_>) -> String {
    match component {
        Component::Method => "\"@method\"".to_owned(),
        Component::Authority => "\"@authority\"".to_owned(),
        Component::Path => "\"@path\"".to_owned(),
        Component::Query => "\"@query\"".to_owned(),
        Component::QueryParam(name) => format!("\"@query-param\";name=\"{name}\""),
        Component::Header(name) => format!("\"{name}\""),
    }
}

/// Take `;name=<canonical uint64>`.
fn take_integer(rest: &mut &str, name: &str) -> Result<u64, ErrorClass> {
    let auth = ErrorClass::AuthenticationRequired;
    let tail = rest
        .strip_prefix(';')
        .and_then(|tail| tail.strip_prefix(name))
        .and_then(|tail| tail.strip_prefix('='))
        .ok_or(auth)?;
    let digits = tail.bytes().take_while(u8::is_ascii_digit).count();
    let value = parse_canonical_u64(&tail.as_bytes()[..digits]).ok_or(auth)?;
    *rest = &tail[digits..];
    Ok(value)
}

/// Take `;name="<visible ASCII without quote or backslash>"`.
fn take_string<'h>(rest: &mut &'h str, name: &str) -> Result<&'h str, ErrorClass> {
    let auth = ErrorClass::AuthenticationRequired;
    let tail = rest
        .strip_prefix(';')
        .and_then(|tail| tail.strip_prefix(name))
        .and_then(|tail| tail.strip_prefix("=\""))
        .ok_or(auth)?;
    let end = tail.find('"').ok_or(auth)?;
    let value = &tail[..end];
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'\\')
    {
        return Err(auth);
    }
    *rest = &tail[end + 1..];
    Ok(value)
}

/// Parse `Signature`: exactly `label=:<base64 of 64 bytes>:` per label, joined by `, `.
fn parse_signature(header: &str, labels: &[&str]) -> Result<Vec<[u8; 64]>, ErrorClass> {
    let auth = ErrorClass::AuthenticationRequired;
    let mut rest = header;
    let mut signatures = Vec::with_capacity(labels.len());
    for (index, label) in labels.iter().enumerate() {
        if index > 0 {
            rest = rest.strip_prefix(", ").ok_or(auth)?;
        }
        let value = rest
            .strip_prefix(*label)
            .and_then(|tail| tail.strip_prefix("=:"))
            .ok_or(auth)?;
        let end = value.find(':').ok_or(auth)?;
        signatures.push(decode_standard_exact::<64>(&value[..end]).ok_or(auth)?);
        rest = &value[end + 1..];
    }
    if rest.is_empty() {
        Ok(signatures)
    } else {
        Err(auth)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_freshness_window_is_exact_at_every_edge() {
        let created = 1_000;
        assert!(control_is_fresh(created, created + 1, created));
        assert!(control_is_fresh(created, created + 60, created + 60));
        assert!(!control_is_fresh(created, created, created));
        assert!(!control_is_fresh(created, created + 61, created));
        assert!(!control_is_fresh(created, created + 60, created + 61));
        assert!(control_is_fresh(created, created + 60, created - 30));
        assert!(!control_is_fresh(created, created + 60, created - 31));
        assert!(control_is_fresh(u64::MAX - 60, u64::MAX, u64::MAX));
        assert!(control_is_fresh(u64::MAX - 30, u64::MAX, u64::MAX - 60));
        assert!(!control_is_fresh(u64::MAX, u64::MAX, u64::MAX));
    }

    #[test]
    fn authority_grammar_is_lowercase_canonical_idna_host_and_port() {
        let longest_host = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        let longest_authority = format!("{longest_host}:65535");
        assert_eq!(longest_authority.len(), AUTHORITY_MAX_BYTES);
        assert!(is_valid_authority(longest_authority.as_bytes()));

        let oversized_authority = format!("{longest_host}d:65535");
        assert_eq!(oversized_authority.len(), AUTHORITY_MAX_BYTES + 1);
        assert!(!is_valid_authority(oversized_authority.as_bytes()));

        assert!(is_valid_authority(b"ha.example.com:58443"));
        assert!(is_valid_authority(b"xn--bcher-kva.example:443"));
        for rejected in [
            b"ha.example.com".as_slice(),
            b"HA.example.com:1",
            b"ha.example.com:0",
            b"ha.example.com:65536",
            b"ha.example.com:01",
            b"ha..example.com:1",
            b"-ha.example.com:1",
            b"user@ha.example.com:1",
            b"127.0.0.1:1",
            b"0x7f000001:1",
            b"ab--reserved.example:1",
            b"xn--a.example:1",
            b":1",
        ] {
            assert!(!is_valid_authority(rejected));
        }
    }

    #[test]
    fn signature_header_grammar_is_exact() {
        let encoded = encode_standard(&[7_u8; 64]);
        assert!(parse_signature(&format!("rem=:{encoded}:"), &[LABEL]).is_ok());
        for rejected in [
            format!("rem=:{encoded}: "),
            format!("rem=:{encoded}:, rem-proposed=:{encoded}:"),
            format!("rem =:{encoded}:"),
            format!("rem=:{}:", encoded.trim_end_matches('=')),
            format!("other=:{encoded}:"),
            "rem=:AAAA:".to_owned(),
        ] {
            assert_eq!(
                parse_signature(&rejected, &[LABEL]),
                Err(ErrorClass::AuthenticationRequired)
            );
        }
        assert_eq!(
            parse_signature(&format!("rem=:{encoded}:"), &[LABEL, PROPOSED_LABEL]),
            Err(ErrorClass::AuthenticationRequired)
        );
    }
}
