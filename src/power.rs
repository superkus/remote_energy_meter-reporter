//! Whole-system power source contract.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// Protocol-wide hard ceiling. Platform providers may enforce a lower operational ceiling.
pub const HARD_MAX_WATTS: f64 = 100_000.0;

/// A qualified instantaneous whole-system power measurement.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct WholeSystemWatts(f64);

impl WholeSystemWatts {
    /// Validate a candidate whole-system reading.
    ///
    /// Zero is valid for a machine that has powered down between acquisition and reporting. Values
    /// above [`HARD_MAX_WATTS`] are never credible for a reporter and are rejected before transport.
    pub fn new(watts: f64) -> Result<Self, InvalidWatts> {
        if !watts.is_finite() {
            return Err(InvalidWatts::NotFinite);
        }
        if watts < 0.0 {
            return Err(InvalidWatts::Negative);
        }
        if watts > HARD_MAX_WATTS {
            return Err(InvalidWatts::AboveHardLimit);
        }
        Ok(Self(watts))
    }

    /// Return the validated value in watts.
    #[must_use]
    pub const fn get(self) -> f64 {
        self.0
    }
}

/// Why a numeric candidate cannot become a whole-system reading.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidWatts {
    /// NaN or positive/negative infinity.
    NotFinite,
    /// A value below zero.
    Negative,
    /// A value above [`HARD_MAX_WATTS`].
    AboveHardLimit,
}

impl Display for InvalidWatts {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotFinite => "power value is not finite",
            Self::Negative => "power value is negative",
            Self::AboveHardLimit => "power value exceeds the hard limit",
        })
    }
}

impl Error for InvalidWatts {}

/// A platform measurement provider.
///
/// Implementations return only qualified whole-system power. CPU, GPU, package, estimated, stale,
/// or undocumented-but-unqualified values must return [`PowerSourceError::WholeSystemUnavailable`]
/// rather than being relabelled.
pub trait PowerSource {
    /// Acquire one whole-system power sample.
    fn sample(&mut self) -> Result<WholeSystemWatts, PowerSourceError>;
}

/// A fail-closed source used until a platform passes hardware qualification.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailablePowerSource;

impl PowerSource for UnavailablePowerSource {
    fn sample(&mut self) -> Result<WholeSystemWatts, PowerSourceError> {
        Err(PowerSourceError::WholeSystemUnavailable)
    }
}

/// A stable, non-sensitive source failure returned to callers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PowerSourceError {
    /// No qualified whole-system source exists on this machine.
    WholeSystemUnavailable,
}

impl PowerSourceError {
    /// Stable machine-readable code used by the spike and later daemon diagnostics.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::WholeSystemUnavailable => "WHOLE_SYSTEM_UNAVAILABLE",
        }
    }
}

impl Display for PowerSourceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for PowerSourceError {}
