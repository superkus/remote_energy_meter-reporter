//! Privacy-safe raw telemetry types for the foreground macOS qualification spike.
//!
//! These values are experimental and are not a [`crate::power::PowerSource`]. Passing the
//! numeric-bound checks means only that values used by the candidate conversions and V×I
//! calculation are plausible; it does not qualify the undocumented Apple source as whole-system
//! power. Qualification requires the external-meter procedure in the project plan.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use crate::power::HARD_MAX_WATTS;

const MILLIWATTS_PER_WATT: f64 = 1_000.0;
const MICROWATTS_PER_WATT: f64 = 1_000_000.0;
const HARD_MAX_MILLIWATTS: i64 = {
    let milliwatts = HARD_MAX_WATTS * MILLIWATTS_PER_WATT;
    assert!(milliwatts >= 0.0);
    assert!(milliwatts < i64::MAX as f64);
    let exact_milliwatts = milliwatts as i64;
    assert!(exact_milliwatts as f64 == milliwatts);
    exact_milliwatts
};

/// Raw integer fields read from the `AppleSmartBattery.PowerTelemetryData` dictionary.
///
/// The key names and units are undocumented by Apple. Names ending in `_mw`, `_mv`, or `_ma`
/// express the hypothesis the spike is testing; they are not an API guarantee.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawPowerTelemetry {
    /// Candidate whole-system load, hypothesized milliwatts.
    pub system_load_mw: i64,
    /// Candidate system input power, hypothesized milliwatts.
    pub system_power_in_mw: i64,
    /// Candidate system input voltage, hypothesized millivolts.
    pub system_voltage_mv: i64,
    /// Candidate system input current, hypothesized milliamps.
    pub system_current_ma: i64,
    /// Battery power, raw hypothesized milliwatts.
    pub battery_power_mw: i64,
    /// Adapter loss, raw signed hypothesized milliwatts.
    pub adapter_efficiency_loss_mw: i64,
    /// Undocumented accumulated/interval energy field; retained raw for qualification only.
    pub system_energy_consumed_raw: i64,
    /// Undocumented wall-energy estimate field; retained raw for qualification only.
    pub wall_energy_estimate_raw: i64,
}

impl RawPowerTelemetry {
    /// Validate numeric bounds needed for candidate conversions and the V×I calculation.
    pub fn validate(self) -> Result<ValidatedTelemetry, TelemetryError> {
        if self.system_load_mw < 0 {
            return Err(TelemetryError::NegativeSystemLoad);
        }
        if self.system_power_in_mw < 0 {
            return Err(TelemetryError::NegativeSystemPowerIn);
        }
        if self.system_load_mw > HARD_MAX_MILLIWATTS
            || self.system_power_in_mw > HARD_MAX_MILLIWATTS
        {
            return Err(TelemetryError::AboveHardLimit);
        }
        if self.system_voltage_mv <= 0 {
            return Err(TelemetryError::InvalidVoltage);
        }
        if self.system_current_ma < 0 {
            return Err(TelemetryError::InvalidCurrent);
        }
        let derived =
            (self.system_voltage_mv as f64) * (self.system_current_ma as f64) / MICROWATTS_PER_WATT;
        if !derived.is_finite() || derived > HARD_MAX_WATTS {
            return Err(TelemetryError::AboveHardLimit);
        }
        Ok(ValidatedTelemetry(self))
    }

    /// Stable CSV header. It deliberately contains no host/model/user/device identity.
    #[must_use]
    pub const fn csv_header() -> &'static str {
        "elapsed_ms,sample_index,system_load_mw,system_power_in_mw,system_voltage_mv,system_current_ma,battery_power_mw,adapter_efficiency_loss_mw,system_energy_consumed_raw,wall_energy_estimate_raw,derived_input_w"
    }
}

/// A raw snapshot whose numeric bounds and unit prerequisites are plausible.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedTelemetry(RawPowerTelemetry);

impl ValidatedTelemetry {
    /// Candidate system load in watts.
    #[must_use]
    pub fn system_load_watts(self) -> f64 {
        self.0.system_load_mw as f64 / MILLIWATTS_PER_WATT
    }

    /// Candidate input power in watts.
    #[must_use]
    pub fn system_power_in_watts(self) -> f64 {
        self.0.system_power_in_mw as f64 / MILLIWATTS_PER_WATT
    }

    /// Input watts independently derived from millivolts × milliamps.
    #[must_use]
    pub fn derived_input_watts(self) -> f64 {
        (self.0.system_voltage_mv as f64) * (self.0.system_current_ma as f64) / MICROWATTS_PER_WATT
    }

    /// Relative difference between `SystemPowerIn` and voltage × current.
    #[must_use]
    pub fn power_in_crosscheck_relative_error(self) -> f64 {
        let reported = self.system_power_in_watts();
        let derived = self.derived_input_watts();
        let scale = reported.abs().max(derived.abs());
        if scale == 0.0 {
            0.0
        } else {
            (reported - derived).abs() / scale
        }
    }

    /// Render one privacy-safe raw row for a gitignored spike capture.
    #[must_use]
    pub fn to_csv_row(self, elapsed_ms: u64, sample_index: u64) -> String {
        let RawPowerTelemetry {
            system_load_mw,
            system_power_in_mw,
            system_voltage_mv,
            system_current_ma,
            battery_power_mw,
            adapter_efficiency_loss_mw,
            system_energy_consumed_raw,
            wall_energy_estimate_raw,
        } = self.0;
        let derived_input_w = self.derived_input_watts();
        format!(
            "{elapsed_ms},{sample_index},{system_load_mw},{system_power_in_mw},{system_voltage_mv},{system_current_ma},{battery_power_mw},{adapter_efficiency_loss_mw},{system_energy_consumed_raw},{wall_energy_estimate_raw},{derived_input_w:.6}"
        )
    }
}

/// Why a raw telemetry snapshot is not even numerically suitable for qualification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TelemetryError {
    /// Candidate system load was below zero.
    NegativeSystemLoad,
    /// Candidate input power was below zero.
    NegativeSystemPowerIn,
    /// Input voltage was zero or negative.
    InvalidVoltage,
    /// Input current was negative.
    InvalidCurrent,
    /// A candidate or derived power exceeded the protocol hard ceiling.
    AboveHardLimit,
}

impl Display for TelemetryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NegativeSystemLoad => "candidate system load is negative",
            Self::NegativeSystemPowerIn => "candidate system input power is negative",
            Self::InvalidVoltage => "candidate system voltage is not positive",
            Self::InvalidCurrent => "candidate system current is negative",
            Self::AboveHardLimit => "candidate power exceeds the hard limit",
        })
    }
}

impl Error for TelemetryError {}
