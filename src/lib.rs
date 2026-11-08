#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

//! Native whole-system power reporting primitives.
//!
//! The first implementation is deliberately unavailable: Apple-silicon support is admitted only
//! after the hardware spike proves the candidate telemetry against an external wall meter.

pub mod power;
