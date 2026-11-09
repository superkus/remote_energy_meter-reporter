#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

//! Native whole-system power reporting primitives.
//!
//! Code-only qualification completed on the tested Apple-silicon laptop, validating
//! software-visible semantics and behavior. The production reporter remains unavailable until the
//! documented release gates pass, and the result does not establish externally calibrated or
//! billing-grade accuracy.

pub mod cli;
pub mod power;
pub mod spike;

#[cfg(target_os = "macos")]
pub mod macos_telemetry;
