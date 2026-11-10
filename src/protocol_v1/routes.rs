//! Route lookup driven by the vendored route manifest (`routes.json`, wire profile section 10).
//!
//! [`ROUTES`] mirrors every manifest field that admission depends on, spelled exactly as in the
//! manifest (path templates, query forms, purposes); a conformance test compares it field by field
//! with the vendored `routes.json`, so any drift fails the build's tests.
//!
//! [`lookup_route`] applies the profile's admission order for the target:
//!
//! 1. a target over 256 bytes is [`ErrorClass::TargetTooLong`];
//! 2. a target outside the narrow grammar (anything but unreserved characters and `/` in the path,
//!    percent encoding, a fragment, empty or dot segments, a trailing slash), an invalid typed path
//!    parameter, a query on a route without a query form, or a query that is not exactly one of the
//!    route's forms is [`ErrorClass::InvalidRequest`];
//! 3. an unknown path is [`ErrorClass::NotFound`]; a known path with another method is
//!    [`ErrorClass::MethodNotAllowed`].

use std::ops::Deref;

use super::ErrorClass;
use super::b64u::{B64u, OpaqueB64u};

/// Request target cap.
pub const REQUEST_TARGET_MAX_BYTES: usize = 256;
/// Maximum number of request header fields.
pub const HEADER_COUNT_MAX: usize = 24;
/// Maximum total request header bytes (names plus values).
pub const HEADER_BYTES_MAX: usize = 8192;
/// Maximum `Signature` header value length.
pub const SIGNATURE_HEADER_MAX_BYTES: usize = 1024;
/// Maximum `Signature-Input` header value length.
pub const SIGNATURE_INPUT_HEADER_MAX_BYTES: usize = 1024;
/// Maximum problem response size including headers.
pub const PROBLEM_RESPONSE_MAX_BYTES: usize = 2048;
/// Largest accepted `wait_seconds` long-poll value.
pub const WAIT_SECONDS_MAX: u64 = 25;

/// The API surface a route belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Surface {
    /// `/api/v1/...`, called by reporters.
    Reporter,
    /// `/control/v1/...`, called by the Home Assistant integration.
    Control,
}

/// The trust state a route requires (wire profile section 10).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TrustState {
    /// Interactive or managed first contact.
    PreEnrollment,
    /// Server verified per the enrolled trust mode; no request signature.
    ServerAuthenticated,
    /// Verified server TLS plus `reporter-rfc9421-v1` under the active key.
    EnrolledReporter,
    /// Bootstrap or recovery with a fresh pairing credential.
    ProvisionalControl,
    /// Pinned control SPKI plus `control-rfc9421-v1`.
    PostPair,
}

/// The RFC 9421 signature profile a route requires.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignatureProfile {
    /// `reporter-rfc9421-v1`.
    ReporterRfc9421V1,
    /// `control-rfc9421-v1`.
    ControlRfc9421V1,
}

impl SignatureProfile {
    /// The manifest name of the profile.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ReporterRfc9421V1 => "reporter-rfc9421-v1",
            Self::ControlRfc9421V1 => "control-rfc9421-v1",
        }
    }
}

/// One manifest route.
#[derive(Debug, PartialEq, Eq)]
pub struct Route {
    id: &'static str,
    surface: Surface,
    trust_state: TrustState,
    method: &'static str,
    path_template: &'static str,
    query_forms: &'static [&'static str],
    request_body_max_bytes: usize,
    success_body_max_bytes: usize,
    success_item_maximum: Option<usize>,
    success_status: u16,
    purpose: &'static str,
    signature_profile: Option<SignatureProfile>,
}

impl Route {
    /// Manifest route ID.
    #[must_use]
    pub const fn id(&self) -> &'static str {
        self.id
    }
    /// API surface.
    #[must_use]
    pub const fn surface(&self) -> Surface {
        self.surface
    }
    /// Required trust state.
    #[must_use]
    pub const fn trust_state(&self) -> TrustState {
        self.trust_state
    }
    /// Uppercase method.
    #[must_use]
    pub const fn method(&self) -> &'static str {
        self.method
    }
    /// Path template exactly as in the manifest.
    #[must_use]
    pub const fn path_template(&self) -> &'static str {
        self.path_template
    }
    /// Query forms exactly as in the manifest (empty: no query allowed).
    #[must_use]
    pub const fn query_forms(&self) -> &'static [&'static str] {
        self.query_forms
    }
    /// Request body cap in bytes (`0` forbids a body).
    #[must_use]
    pub const fn request_body_max_bytes(&self) -> usize {
        self.request_body_max_bytes
    }
    /// Success body cap in bytes.
    #[must_use]
    pub const fn success_body_max_bytes(&self) -> usize {
        self.success_body_max_bytes
    }
    /// Success item cap, where the manifest defines one.
    #[must_use]
    pub const fn success_item_maximum(&self) -> Option<usize> {
        self.success_item_maximum
    }
    /// Success HTTP status.
    #[must_use]
    pub const fn success_status(&self) -> u16 {
        self.success_status
    }
    /// Purpose label(s) exactly as in the manifest (space-separated when a body field selects one).
    #[must_use]
    pub const fn purpose(&self) -> &'static str {
        self.purpose
    }
    /// The individual purpose labels.
    pub fn purposes(&self) -> impl Iterator<Item = &'static str> + use<> {
        self.purpose.split(' ')
    }
    /// Required signature profile, if the route is signed.
    #[must_use]
    pub const fn signature_profile(&self) -> Option<SignatureProfile> {
        self.signature_profile
    }
    /// Whether the route carries a request body.
    #[must_use]
    pub const fn has_body(&self) -> bool {
        self.request_body_max_bytes > 0
    }
}

/// A route matched against an exact request target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteMatch<'a> {
    route: &'static Route,
    path: &'a str,
    raw_query: Option<&'a str>,
    path_parameters: Vec<(&'static str, &'a str)>,
    named_query: Vec<(&'a str, &'a str)>,
}

impl<'a> RouteMatch<'a> {
    /// The manifest route.
    #[must_use]
    pub const fn route(&self) -> &'static Route {
        self.route
    }
    /// The exact received path.
    #[must_use]
    pub const fn path(&self) -> &'a str {
        self.path
    }
    /// The exact received query without `?`, if the target has one.
    #[must_use]
    pub const fn raw_query(&self) -> Option<&'a str> {
        self.raw_query
    }
    /// The typed path parameters in template order, as exact received text.
    #[must_use]
    pub fn path_parameters(&self) -> &[(&'static str, &'a str)] {
        &self.path_parameters
    }
    /// The named query inputs in wire order, as exact received text.
    #[must_use]
    pub fn named_query(&self) -> &[(&'a str, &'a str)] {
        &self.named_query
    }
}

impl Deref for RouteMatch<'_> {
    type Target = Route;
    fn deref(&self) -> &Route {
        self.route
    }
}

macro_rules! route {
    (
        id: $id:literal,
        surface: $surface:ident,
        trust: $trust:ident,
        method: $method:literal,
        path: $path:literal,
        query: [$($query:literal),*],
        request_max: $request:literal,
        success_max: $success:literal,
        items: $items:expr,
        status: $status:literal,
        purpose: $purpose:literal,
        profile: $profile:expr $(,)?
    ) => {
        Route {
            id: $id,
            surface: Surface::$surface,
            trust_state: TrustState::$trust,
            method: $method,
            path_template: $path,
            query_forms: &[$($query),*],
            request_body_max_bytes: $request,
            success_body_max_bytes: $success,
            success_item_maximum: $items,
            success_status: $status,
            purpose: $purpose,
            signature_profile: $profile,
        }
    };
}

const REPORTER: Option<SignatureProfile> = Some(SignatureProfile::ReporterRfc9421V1);
const CONTROL: Option<SignatureProfile> = Some(SignatureProfile::ControlRfc9421V1);

/// Every protocol v1 route, in manifest order.
pub static ROUTES: &[Route] = &[
    route!(
        id: "reporter.managed-enrollment-challenge.create",
        surface: Reporter,
        trust: PreEnrollment,
        method: "POST",
        path: "/api/v1/managed-enrollment-challenges",
        query: [],
        request_max: 1024,
        success_max: 1024,
        items: None,
        status: 201,
        purpose: "rem-managed-enroll-challenge-v1",
        profile: None,
    ),
    route!(
        id: "reporter.enrollment.create",
        surface: Reporter,
        trust: PreEnrollment,
        method: "POST",
        path: "/api/v1/enrollments",
        query: [],
        request_max: 4096,
        success_max: 2048,
        items: None,
        status: 201,
        purpose: "rem-enroll-v1 rem-managed-enroll-v1",
        profile: REPORTER,
    ),
    route!(
        id: "reporter.enrollment.reveal",
        surface: Reporter,
        trust: PreEnrollment,
        method: "POST",
        path: "/api/v1/enrollments/{enrollment_id}/reveal",
        query: [],
        request_max: 256,
        success_max: 2048,
        items: None,
        status: 200,
        purpose: "rem-enroll-reveal-v1",
        profile: REPORTER,
    ),
    route!(
        id: "reporter.enrollment.confirm",
        surface: Reporter,
        trust: PreEnrollment,
        method: "POST",
        path: "/api/v1/enrollments/{enrollment_id}/confirm",
        query: [],
        request_max: 512,
        success_max: 1024,
        items: None,
        status: 200,
        purpose: "rem-enroll-confirm-v1",
        profile: REPORTER,
    ),
    route!(
        id: "reporter.enrollment.status",
        surface: Reporter,
        trust: PreEnrollment,
        method: "GET",
        path: "/api/v1/enrollments/{enrollment_id}",
        query: ["after_status_generation={uint64}&wait_seconds={0..25}"],
        request_max: 0,
        success_max: 2048,
        items: None,
        status: 200,
        purpose: "rem-enroll-status-v1",
        profile: REPORTER,
    ),
    route!(
        id: "reporter.challenge-context.read",
        surface: Reporter,
        trust: ServerAuthenticated,
        method: "GET",
        path: "/api/v1/challenge-context",
        query: [],
        request_max: 0,
        success_max: 1024,
        items: None,
        status: 200,
        purpose: "rem-challenge-context-v1",
        profile: None,
    ),
    route!(
        id: "reporter.challenge.create",
        surface: Reporter,
        trust: EnrolledReporter,
        method: "POST",
        path: "/api/v1/challenges",
        query: [],
        request_max: 512,
        success_max: 1024,
        items: None,
        status: 201,
        purpose: "rem-challenge-v1",
        profile: REPORTER,
    ),
    route!(
        id: "reporter.session.create",
        surface: Reporter,
        trust: EnrolledReporter,
        method: "POST",
        path: "/api/v1/sessions",
        query: [],
        request_max: 1024,
        success_max: 1024,
        items: None,
        status: 201,
        purpose: "rem-session-v1",
        profile: REPORTER,
    ),
    route!(
        id: "reporter.report.create",
        surface: Reporter,
        trust: EnrolledReporter,
        method: "POST",
        path: "/api/v1/reports",
        query: [],
        request_max: 1024,
        success_max: 1024,
        items: None,
        status: 200,
        purpose: "rem-report-v1",
        profile: REPORTER,
    ),
    route!(
        id: "reporter.key-rotation-challenge.create",
        surface: Reporter,
        trust: EnrolledReporter,
        method: "POST",
        path: "/api/v1/reporters/{reporter_id}/key-rotations/challenges",
        query: [],
        request_max: 2048,
        success_max: 2048,
        items: None,
        status: 201,
        purpose: "rem-rotate-challenge-v1",
        profile: REPORTER,
    ),
    route!(
        id: "reporter.key-rotation.complete",
        surface: Reporter,
        trust: EnrolledReporter,
        method: "POST",
        path: "/api/v1/reporters/{reporter_id}/key-rotations/{rotation_id}",
        query: [],
        request_max: 1024,
        success_max: 2048,
        items: None,
        status: 202,
        purpose: "rem-rotate-v1",
        profile: REPORTER,
    ),
    route!(
        id: "control.bootstrap.commit",
        surface: Control,
        trust: ProvisionalControl,
        method: "POST",
        path: "/control/v1/bootstrap/commit",
        query: [],
        request_max: 2048,
        success_max: 2048,
        items: None,
        status: 201,
        purpose: "rem-control-pairing-v1",
        profile: None,
    ),
    route!(
        id: "control.bootstrap.reveal",
        surface: Control,
        trust: ProvisionalControl,
        method: "POST",
        path: "/control/v1/bootstrap/reveal",
        query: [],
        request_max: 1024,
        success_max: 2048,
        items: None,
        status: 200,
        purpose: "rem-control-pairing-v1",
        profile: None,
    ),
    route!(
        id: "control.bootstrap.confirm",
        surface: Control,
        trust: ProvisionalControl,
        method: "POST",
        path: "/control/v1/bootstrap/confirm",
        query: [],
        request_max: 1024,
        success_max: 2048,
        items: None,
        status: 200,
        purpose: "rem-control-pairing-v1",
        profile: None,
    ),
    route!(
        id: "control.recovery.commit",
        surface: Control,
        trust: ProvisionalControl,
        method: "POST",
        path: "/control/v1/recovery/commit",
        query: [],
        request_max: 1024,
        success_max: 2048,
        items: None,
        status: 201,
        purpose: "rem-control-recovery-v1",
        profile: None,
    ),
    route!(
        id: "control.recovery.reveal",
        surface: Control,
        trust: ProvisionalControl,
        method: "POST",
        path: "/control/v1/recovery/reveal",
        query: [],
        request_max: 256,
        success_max: 1024,
        items: None,
        status: 200,
        purpose: "rem-control-recovery-v1",
        profile: None,
    ),
    route!(
        id: "control.recovery.revoke",
        surface: Control,
        trust: ProvisionalControl,
        method: "POST",
        path: "/control/v1/recovery/revoke",
        query: [],
        request_max: 1024,
        success_max: 2048,
        items: None,
        status: 200,
        purpose: "rem-control-recovery-v1",
        profile: None,
    ),
    route!(
        id: "control.managed-token.issue",
        surface: Control,
        trust: PostPair,
        method: "POST",
        path: "/control/v1/managed-enrollment-tokens",
        query: [],
        request_max: 1024,
        success_max: 2048,
        items: None,
        status: 201,
        purpose: "rem-control-managed-token-v1",
        profile: CONTROL,
    ),
    route!(
        id: "control.managed-token.status",
        surface: Control,
        trust: PostPair,
        method: "POST",
        path: "/control/v1/managed-enrollment-token-operations/status",
        query: [],
        request_max: 512,
        success_max: 1024,
        items: None,
        status: 200,
        purpose: "rem-control-managed-token-status-v1",
        profile: CONTROL,
    ),
    route!(
        id: "control.managed-token.revoke",
        surface: Control,
        trust: PostPair,
        method: "POST",
        path: "/control/v1/managed-enrollment-tokens/revoke",
        query: [],
        request_max: 512,
        success_max: 1024,
        items: None,
        status: 200,
        purpose: "rem-control-managed-token-revoke-v1",
        profile: CONTROL,
    ),
    route!(
        id: "control.roster.events",
        surface: Control,
        trust: PostPair,
        method: "GET",
        path: "/control/v1/roster/events",
        query: ["after_generation={uint64}&wait_seconds={0..25}"],
        request_max: 0,
        success_max: 65536,
        items: Some(100),
        status: 200,
        purpose: "rem-control-roster-events-v1",
        profile: CONTROL,
    ),
    route!(
        id: "control.roster.snapshot",
        surface: Control,
        trust: PostPair,
        method: "GET",
        path: "/control/v1/roster/snapshot",
        query: [
            "after_generation={uint64}",
            "continuation_token={opaque128}"
        ],
        request_max: 0,
        success_max: 65536,
        items: Some(100),
        status: 200,
        purpose: "rem-control-roster-snapshot-v1",
        profile: CONTROL,
    ),
    route!(
        id: "control.reporter.action",
        surface: Control,
        trust: PostPair,
        method: "POST",
        path: "/control/v1/reporters/actions",
        query: [],
        request_max: 2048,
        success_max: 2048,
        items: None,
        status: 200,
        purpose: "rem-control-reporter-action-v1",
        profile: CONTROL,
    ),
    route!(
        id: "control.reporter-key-rotation.confirm",
        surface: Control,
        trust: PostPair,
        method: "POST",
        path: "/control/v1/reporters/key-rotations/confirm",
        query: [],
        request_max: 1024,
        success_max: 2048,
        items: None,
        status: 200,
        purpose: "rem-control-reporter-key-rotation-v1",
        profile: CONTROL,
    ),
    route!(
        id: "control.control-key-rotation-challenge.create",
        surface: Control,
        trust: PostPair,
        method: "POST",
        path: "/control/v1/control-keys/rotation-challenges",
        query: [],
        request_max: 2048,
        success_max: 2048,
        items: None,
        status: 201,
        purpose: "rem-control-key-rotation-challenge-v1",
        profile: CONTROL,
    ),
    route!(
        id: "control.control-key-rotation.complete",
        surface: Control,
        trust: PostPair,
        method: "POST",
        path: "/control/v1/control-keys/rotations",
        query: [],
        request_max: 4096,
        success_max: 2048,
        items: None,
        status: 200,
        purpose: "rem-control-key-rotation-v1",
        profile: CONTROL,
    ),
    route!(
        id: "control.control-spki-rotation",
        surface: Control,
        trust: PostPair,
        method: "POST",
        path: "/control/v1/control-spki/rotations",
        query: [],
        request_max: 4096,
        success_max: 2048,
        items: None,
        status: 200,
        purpose: "rem-control-spki-rotation-v1",
        profile: CONTROL,
    ),
    route!(
        id: "control.mqtt-key.provision",
        surface: Control,
        trust: PostPair,
        method: "POST",
        path: "/control/v1/mqtt-keys/provision",
        query: [],
        request_max: 4096,
        success_max: 4096,
        items: None,
        status: 200,
        purpose: "rem-control-mqtt-key-provision-v1",
        profile: CONTROL,
    ),
    route!(
        id: "control.mqtt-key.acknowledge",
        surface: Control,
        trust: PostPair,
        method: "POST",
        path: "/control/v1/mqtt-keys/acknowledge",
        query: [],
        request_max: 1024,
        success_max: 2048,
        items: None,
        status: 200,
        purpose: "rem-control-mqtt-key-ack-v1",
        profile: CONTROL,
    ),
    route!(
        id: "control.lease.refresh",
        surface: Control,
        trust: PostPair,
        method: "POST",
        path: "/control/v1/leases/refresh",
        query: [],
        request_max: 512,
        success_max: 1024,
        items: None,
        status: 200,
        purpose: "rem-control-lease-refresh-v1",
        profile: CONTROL,
    ),
];

/// The only route that carries the second `rem-proposed` signature label.
pub const DUAL_SIGNATURE_ROUTE_ID: &str = "control.control-key-rotation.complete";

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

/// Validate a typed path parameter by its manifest name.
fn path_parameter_is_valid(name: &str, value: &str) -> bool {
    match name {
        "enrollment_id" | "rotation_id" => B64u::<16>::parse(value).is_ok(),
        "reporter_id" => B64u::<32>::parse(value).is_ok(),
        _ => false,
    }
}

/// Validate a typed query value by its manifest placeholder.
fn query_value_is_valid(placeholder: &str, value: &str) -> bool {
    match placeholder {
        "{uint64}" => super::parse_canonical_u64(value.as_bytes()).is_some(),
        "{0..25}" => super::parse_canonical_u64(value.as_bytes())
            .is_some_and(|seconds| seconds <= WAIT_SECONDS_MAX),
        "{opaque128}" => OpaqueB64u::<128>::parse(value).is_ok(),
        _ => false,
    }
}

/// Match the received query against one manifest form; returns the named pairs in wire order.
fn match_query_form<'a>(form: &str, query: &'a str) -> Option<Vec<(&'a str, &'a str)>> {
    let expected: Vec<_> = form.split('&').collect();
    let received: Vec<_> = query.split('&').collect();
    if expected.len() != received.len() {
        return None;
    }
    let mut pairs = Vec::with_capacity(received.len());
    for (expected, received) in expected.into_iter().zip(received) {
        let (name, placeholder) = expected.split_once('=')?;
        let (received_name, value) = received.split_once('=')?;
        if received_name != name || !query_value_is_valid(placeholder, value) {
            return None;
        }
        pairs.push((received_name, value));
    }
    Some(pairs)
}

enum PathMatch<'a> {
    Exact(Vec<(&'static str, &'a str)>),
    InvalidParameter,
    Different,
}

fn match_path<'a>(template: &'static str, segments: &[&'a str]) -> PathMatch<'a> {
    let template_segments: Vec<_> = template.split('/').skip(1).collect();
    if template_segments.len() != segments.len() {
        return PathMatch::Different;
    }
    let mut parameters = Vec::new();
    let mut parameter_valid = true;
    for (expected, received) in template_segments.into_iter().zip(segments) {
        if let Some(name) = expected
            .strip_prefix('{')
            .and_then(|rest| rest.strip_suffix('}'))
        {
            parameter_valid &= path_parameter_is_valid(name, received);
            parameters.push((name, *received));
        } else if expected != *received {
            return PathMatch::Different;
        }
    }
    if parameter_valid {
        PathMatch::Exact(parameters)
    } else {
        PathMatch::InvalidParameter
    }
}

/// Look up the route for an exact method and raw request target.
///
/// # Errors
/// See the module documentation for the admission order and classes.
pub fn lookup_route<'a>(method: &[u8], target: &'a [u8]) -> Result<RouteMatch<'a>, ErrorClass> {
    if target.len() > REQUEST_TARGET_MAX_BYTES {
        return Err(ErrorClass::TargetTooLong);
    }
    let target = std::str::from_utf8(target).map_err(|_| ErrorClass::InvalidRequest)?;
    let (path, raw_query) = match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    };
    if !path.starts_with('/') || !path.bytes().all(|byte| byte == b'/' || is_unreserved(byte)) {
        return Err(ErrorClass::InvalidRequest);
    }
    if raw_query.is_some_and(|query| {
        !query
            .bytes()
            .all(|byte| is_unreserved(byte) || byte == b'=' || byte == b'&')
    }) {
        return Err(ErrorClass::InvalidRequest);
    }
    let segments: Vec<_> = path[1..].split('/').collect();
    if segments
        .iter()
        .any(|segment| matches!(*segment, "" | "." | ".."))
    {
        return Err(ErrorClass::InvalidRequest);
    }

    let mut invalid_parameter = false;
    let mut found = None;
    for route in ROUTES {
        match match_path(route.path_template, &segments) {
            PathMatch::Exact(parameters) => {
                found = Some((route, parameters));
                break;
            }
            PathMatch::InvalidParameter => invalid_parameter = true,
            PathMatch::Different => {}
        }
    }
    let Some((route, path_parameters)) = found else {
        return Err(if invalid_parameter {
            ErrorClass::InvalidRequest
        } else {
            ErrorClass::NotFound
        });
    };

    let named_query = match (raw_query, route.query_forms) {
        (None, []) => Vec::new(),
        (Some(query), forms) => forms
            .iter()
            .find_map(|form| match_query_form(form, query))
            .ok_or(ErrorClass::InvalidRequest)?,
        (None, _) => return Err(ErrorClass::InvalidRequest),
    };

    if method != route.method.as_bytes() {
        return Err(ErrorClass::MethodNotAllowed);
    }
    Ok(RouteMatch {
        route,
        path,
        raw_query,
        path_parameters,
        named_query,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_segments_win_over_typed_parameters_and_no_two_routes_share_a_path() {
        let challenge = lookup_route(
            b"POST",
            b"/api/v1/reporters/XvXTjzJmaKXJaWfpsV9mUH4K2PpAF6SjWjhbcCN9dIU/key-rotations/challenges",
        )
        .unwrap();
        assert_eq!(challenge.id(), "reporter.key-rotation-challenge.create");
        assert_eq!(
            challenge.path_parameters(),
            &[("reporter_id", "XvXTjzJmaKXJaWfpsV9mUH4K2PpAF6SjWjhbcCN9dIU")]
        );
        for (index, route) in ROUTES.iter().enumerate() {
            assert!(
                ROUTES[..index]
                    .iter()
                    .all(|earlier| earlier.path_template != route.path_template),
                "path shared by {}",
                route.id
            );
        }
    }

    #[test]
    fn target_grammar_and_typed_parameters_are_exact() {
        let long = format!("/api/v1/{}", "a".repeat(REQUEST_TARGET_MAX_BYTES));
        assert_eq!(
            lookup_route(b"POST", long.as_bytes()).unwrap_err(),
            ErrorClass::TargetTooLong
        );
        for target in [
            b"api/v1/reports".as_slice(),
            b"/api/v1/reports/",
            b"/api/v1/reports#x",
            b"/api/v1/../v1/reports",
            b"/api/v1/enrollments/AQEBAQEBAQEBAQEBAQEBAR",
            b"/api/v1/enrollments/AQEBAQEBAQEBAQEBAQEBAQ",
            b"/api/v1/enrollments/AQEBAQEBAQEBAQEBAQEBAQ?after_status_generation=1",
            b"/api/v1/enrollments/AQEBAQEBAQEBAQEBAQEBAQ?after_status_generation=1&wait_seconds=1&x=1",
            b"/control/v1/roster/snapshot?continuation_token=",
            b"/control/v1/roster/snapshot?after_generation=1&continuation_token=AA",
            b"/control/v1/roster/snapshot?",
            b"/api/v1/reports?a=%41",
            b"/api/v1/r\xc3\xa9ports",
        ] {
            assert_eq!(
                lookup_route(b"GET", target).unwrap_err(),
                ErrorClass::InvalidRequest,
                "{}",
                String::from_utf8_lossy(target)
            );
        }
        let snapshot =
            lookup_route(b"GET", b"/control/v1/roster/snapshot?continuation_token=AA").unwrap();
        assert_eq!(snapshot.named_query(), &[("continuation_token", "AA")]);
        assert_eq!(
            lookup_route(b"get", b"/api/v1/challenge-context").unwrap_err(),
            ErrorClass::MethodNotAllowed
        );
    }
}
