//! Privacy-safe raw telemetry types for the foreground macOS qualification spike.
//!
//! These values are experimental and are not a [`crate::power::PowerSource`]. Passing the
//! numeric-bound checks means only that values used by the candidate conversions and internal
//! cross-checks are plausible. Code-only qualification can establish source behavior, units,
//! freshness, and load response, but it cannot establish calibrated or billing-grade accuracy.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::time::Duration;

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
const MAX_BRACKET_DURATION: Duration = Duration::from_secs(1);

fn within_one_percent_milliwatts(left: i128, right: i128) -> bool {
    let difference = left.abs_diff(right);
    let scale = left.unsigned_abs().max(right.unsigned_abs());
    difference.saturating_mul(100) <= 100_u128.max(scale)
}

fn relative_error(left: f64, right: f64) -> f64 {
    let scale = left.abs().max(right.abs());
    if scale == 0.0 {
        0.0
    } else {
        (left - right).abs() / scale
    }
}

fn within_one_percent_microwatts(left_milliwatts: i64, right_microwatts: i128) -> bool {
    let left_microwatts = i128::from(left_milliwatts) * 1_000;
    let difference = left_microwatts.abs_diff(right_microwatts);
    let scale = left_microwatts
        .unsigned_abs()
        .max(right_microwatts.unsigned_abs());
    difference.saturating_mul(100) <= 100_000_u128.max(scale)
}

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
    /// Number of hardware updates contributing to accumulated system load.
    pub system_load_count: i64,
    /// Undocumented accumulated system-load value.
    pub accumulated_system_load_raw: i64,
    /// Number of hardware updates contributing to accumulated system input power.
    pub system_power_in_count: i64,
    /// Undocumented accumulated system-input-power value.
    pub accumulated_system_power_in_raw: i64,
    /// Number of hardware updates contributing to accumulated battery power.
    pub battery_power_count: i64,
    /// Undocumented accumulated battery-power value.
    pub accumulated_battery_power_raw: i64,
    /// Number of hardware updates contributing to accumulated battery discharge.
    pub battery_discharge_count: i64,
    /// Undocumented signed accumulated battery-discharge value.
    pub accumulated_battery_discharge_raw: i64,
    /// Undocumented accumulated system-energy-consumed value.
    pub accumulated_system_energy_consumed_raw: i64,
    /// Undocumented accumulated wall-energy-estimate value.
    pub accumulated_wall_energy_estimate_raw: i64,
}

impl RawPowerTelemetry {
    /// Validate numeric bounds for AC candidate conversion and the input V×I cross-check.
    pub fn validate(self) -> Result<ValidatedTelemetry, TelemetryError> {
        self.validate_for_mode(PlatformPowerMode::Ac)
    }

    /// Validate candidate fields according to the public platform power mode.
    pub fn validate_for_mode(
        self,
        mode: PlatformPowerMode,
    ) -> Result<ValidatedTelemetry, TelemetryError> {
        self.validate_common_power_bounds()?;
        match mode {
            PlatformPowerMode::Ac => self.validate_ac()?,
            PlatformPowerMode::Battery => self.validate_battery()?,
        }
        Ok(ValidatedTelemetry { raw: self, mode })
    }

    fn validate_common_power_bounds(self) -> Result<(), TelemetryError> {
        if self.system_load_mw < 0 {
            return Err(TelemetryError::NegativeSystemLoad);
        }
        if self.system_power_in_mw < 0 {
            return Err(TelemetryError::NegativeSystemPowerIn);
        }
        if self.system_load_mw > HARD_MAX_MILLIWATTS
            || self.system_power_in_mw > HARD_MAX_MILLIWATTS
            || self.battery_power_mw.unsigned_abs() > HARD_MAX_MILLIWATTS as u64
        {
            return Err(TelemetryError::AboveHardLimit);
        }
        Ok(())
    }

    fn validate_common_input_bounds_and_counters(self) -> Result<(), TelemetryError> {
        if self.system_voltage_mv < 0 {
            return Err(TelemetryError::InvalidVoltage);
        }
        if self.system_current_ma < 0 {
            return Err(TelemetryError::InvalidCurrent);
        }
        if self.system_voltage_mv > HARD_MAX_MILLIWATTS
            || self.system_current_ma > HARD_MAX_MILLIWATTS
        {
            return Err(TelemetryError::AboveHardLimit);
        }
        if [
            self.system_load_count,
            self.accumulated_system_load_raw,
            self.system_power_in_count,
            self.accumulated_system_power_in_raw,
            self.battery_power_count,
            self.accumulated_battery_power_raw,
            self.battery_discharge_count,
            self.accumulated_system_energy_consumed_raw,
            self.accumulated_wall_energy_estimate_raw,
        ]
        .into_iter()
        .any(|value| value < 0)
        {
            return Err(TelemetryError::NegativeCountOrAccumulator);
        }
        Ok(())
    }

    fn validate_ac(self) -> Result<(), TelemetryError> {
        if self.system_voltage_mv <= 0 {
            return Err(TelemetryError::InvalidVoltage);
        }
        self.validate_common_input_bounds_and_counters()?;
        if self.system_power_in_mw == 0 {
            return Err(TelemetryError::NonPositiveCandidate);
        }
        let load_plus_battery = i128::from(self.system_load_mw) + i128::from(self.battery_power_mw);
        if !within_one_percent_milliwatts(i128::from(self.system_power_in_mw), load_plus_battery) {
            return Err(TelemetryError::InconsistentPowerBalance);
        }
        let derived_microwatts =
            i128::from(self.system_voltage_mv) * i128::from(self.system_current_ma);
        if derived_microwatts > i128::from(HARD_MAX_MILLIWATTS) * 1_000 {
            return Err(TelemetryError::AboveHardLimit);
        }
        if !within_one_percent_microwatts(self.system_power_in_mw, derived_microwatts) {
            return Err(TelemetryError::InconsistentInputPower);
        }
        Ok(())
    }

    fn validate_battery(self) -> Result<(), TelemetryError> {
        self.validate_common_input_bounds_and_counters()?;
        if self.system_load_mw == 0 {
            return Err(TelemetryError::NonPositiveCandidate);
        }
        if self.battery_power_mw >= 0 {
            return Err(TelemetryError::InvalidBatteryPower);
        }
        if !within_one_percent_milliwatts(
            i128::from(self.system_load_mw),
            -i128::from(self.battery_power_mw),
        ) {
            return Err(TelemetryError::InconsistentBatteryPower);
        }
        let load_plus_battery = i128::from(self.system_load_mw) + i128::from(self.battery_power_mw);
        if !within_one_percent_milliwatts(i128::from(self.system_power_in_mw), load_plus_battery) {
            return Err(TelemetryError::InconsistentPowerBalance);
        }
        Ok(())
    }

    /// Stable CSV header. It deliberately contains no host/model/user/device identity.
    #[must_use]
    pub const fn csv_header() -> &'static str {
        concat!(
            "elapsed_ms,",
            "sample_index,",
            "system_load_mw,",
            "system_power_in_mw,",
            "system_voltage_mv,",
            "system_current_ma,",
            "battery_power_mw,",
            "adapter_efficiency_loss_mw,",
            "system_energy_consumed_raw,",
            "wall_energy_estimate_raw,",
            "system_load_count,",
            "accumulated_system_load_raw,",
            "system_power_in_count,",
            "accumulated_system_power_in_raw,",
            "battery_power_count,",
            "accumulated_battery_power_raw,",
            "battery_discharge_count,",
            "accumulated_battery_discharge_raw,",
            "accumulated_system_energy_consumed_raw,",
            "accumulated_wall_energy_estimate_raw,",
            "derived_input_w",
        )
    }
}

/// A raw snapshot whose candidate is validated for one public power mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedTelemetry {
    raw: RawPowerTelemetry,
    mode: PlatformPowerMode,
}

impl ValidatedTelemetry {
    /// Public power mode used to validate and select this sample.
    #[must_use]
    pub const fn mode(self) -> PlatformPowerMode {
        self.mode
    }

    /// Candidate system load in watts.
    #[must_use]
    pub fn system_load_watts(self) -> f64 {
        self.raw.system_load_mw as f64 / MILLIWATTS_PER_WATT
    }

    /// Mode-selected Apple-reported system power in watts.
    ///
    /// AC uses system input so battery charging remains included. Battery mode uses system load
    /// because no external input is present. The mode is fixed during validation.
    #[must_use]
    pub fn candidate_watts(self) -> f64 {
        match self.mode {
            PlatformPowerMode::Ac => self.system_power_in_watts(),
            PlatformPowerMode::Battery => self.system_load_watts(),
        }
    }

    /// Relative residual of `SystemPowerIn = SystemLoad + BatteryPower`.
    #[must_use]
    pub fn system_power_balance_relative_error(self) -> f64 {
        relative_error(
            self.raw.system_power_in_mw as f64,
            (self.raw.system_load_mw as f64) + (self.raw.battery_power_mw as f64),
        )
    }

    /// Relative residual of the mode-specific secondary direct cross-check.
    ///
    /// AC compares `SystemPowerIn` with input voltage times current. Battery compares
    /// `SystemLoad` with the magnitude of negative `BatteryPower`.
    #[must_use]
    pub fn mode_crosscheck_relative_error(self) -> f64 {
        match self.mode {
            PlatformPowerMode::Ac => self.power_in_crosscheck_relative_error(),
            PlatformPowerMode::Battery => relative_error(
                self.raw.system_load_mw as f64,
                (self.raw.battery_power_mw as f64).abs(),
            ),
        }
    }

    /// Render the selected candidate and separate mandatory residuals for CSV.
    #[must_use]
    pub fn qualification_csv_fields(self) -> String {
        format!(
            "{:.6},{:.6},{:.6}",
            self.candidate_watts(),
            self.system_power_balance_relative_error(),
            self.mode_crosscheck_relative_error(),
        )
    }

    /// Stable CSV header for selected candidate and mandatory residuals.
    #[must_use]
    pub const fn qualification_csv_header() -> &'static str {
        "candidate_w,system_power_balance_relative_error,mode_crosscheck_relative_error"
    }

    /// Candidate input power in watts.
    #[must_use]
    pub fn system_power_in_watts(self) -> f64 {
        self.raw.system_power_in_mw as f64 / MILLIWATTS_PER_WATT
    }

    /// Input watts independently derived from millivolts × milliamps.
    #[must_use]
    pub fn derived_input_watts(self) -> f64 {
        (self.raw.system_voltage_mv as f64) * (self.raw.system_current_ma as f64)
            / MICROWATTS_PER_WATT
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

    /// Compare source-owned update counters, rejecting cross-mode comparisons.
    pub fn update_since(self, previous: Self) -> Result<HardwareUpdate, TelemetryError> {
        if self.mode != previous.mode {
            return Err(TelemetryError::ModeTransition);
        }
        let current = self.update_counts();
        let previous = previous.update_counts();
        if current
            .into_iter()
            .zip(previous)
            .any(|(current, previous)| current < previous)
        {
            Ok(HardwareUpdate::CounterReset)
        } else if current == previous {
            Ok(HardwareUpdate::Unchanged)
        } else {
            Ok(HardwareUpdate::Advanced)
        }
    }

    fn update_counts(self) -> [i64; 4] {
        [
            self.raw.system_load_count,
            self.raw.system_power_in_count,
            self.raw.battery_power_count,
            self.raw.battery_discharge_count,
        ]
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
            system_load_count,
            accumulated_system_load_raw,
            system_power_in_count,
            accumulated_system_power_in_raw,
            battery_power_count,
            accumulated_battery_power_raw,
            battery_discharge_count,
            accumulated_battery_discharge_raw,
            accumulated_system_energy_consumed_raw,
            accumulated_wall_energy_estimate_raw,
        } = self.raw;
        let derived_input_w = self.derived_input_watts();
        format!(
            "{elapsed_ms},\
             {sample_index},\
             {system_load_mw},\
             {system_power_in_mw},\
             {system_voltage_mv},\
             {system_current_ma},\
             {battery_power_mw},\
             {adapter_efficiency_loss_mw},\
             {system_energy_consumed_raw},\
             {wall_energy_estimate_raw},\
             {system_load_count},\
             {accumulated_system_load_raw},\
             {system_power_in_count},\
             {accumulated_system_power_in_raw},\
             {battery_power_count},\
             {accumulated_battery_power_raw},\
             {battery_discharge_count},\
             {accumulated_battery_discharge_raw},\
             {accumulated_system_energy_consumed_raw},\
             {accumulated_wall_energy_estimate_raw},\
             {derived_input_w:.6}"
        )
    }
}

/// Whether Apple produced a new hardware telemetry interval since the previous read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HardwareUpdate {
    /// This is the first sample, so there is no previous counter state.
    Initial,
    /// At least one source-owned accumulator count increased.
    Advanced,
    /// Every selected accumulator count is unchanged.
    Unchanged,
    /// At least one count decreased, indicating hardware/driver reset or wrap.
    CounterReset,
}

impl HardwareUpdate {
    /// Stable lowercase value for qualification CSV.
    #[must_use]
    pub const fn csv_value(self) -> &'static str {
        match self {
            Self::Initial => "initial",
            Self::Advanced => "advanced",
            Self::Unchanged => "unchanged",
            Self::CounterReset => "counter_reset",
        }
    }
}

/// Minimal read interface used to acquire one bracketed Apple telemetry candidate.
pub trait TelemetryAcquisition {
    /// Reader-specific failure type.
    type Error;

    /// Read one classifiable public power-state snapshot.
    fn read_public_battery_reference(&mut self) -> Result<RawBatteryReference, Self::Error>;

    /// Read one private candidate telemetry snapshot.
    fn read_raw(&mut self) -> Result<RawPowerTelemetry, Self::Error>;
}

/// Monotonic boundaries around a bracketed candidate acquisition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcquisitionBoundaries {
    /// Time immediately before the leading public-state read.
    pub reference_before_started: Duration,
    /// Time immediately after the leading public-state read.
    pub reference_before_finished: Duration,
    /// Time immediately after the private telemetry read.
    pub telemetry_finished: Duration,
    /// Time immediately after the trailing public-state read.
    pub reference_after_finished: Duration,
}

/// One candidate accepted under matching public power-state snapshots.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BracketedTelemetry {
    sample: ValidatedTelemetry,
    reference_before: ValidatedBatteryReference,
    reference_after: ValidatedBatteryReference,
    boundaries: AcquisitionBoundaries,
}

impl BracketedTelemetry {
    /// Return the mode-bound candidate telemetry.
    #[must_use]
    pub const fn sample(self) -> ValidatedTelemetry {
        self.sample
    }

    /// Return the leading validated public-state snapshot.
    #[must_use]
    pub const fn reference_before(self) -> ValidatedBatteryReference {
        self.reference_before
    }

    /// Return the trailing validated public-state snapshot.
    #[must_use]
    pub const fn reference_after(self) -> ValidatedBatteryReference {
        self.reference_after
    }

    /// Return the monotonic acquisition boundaries.
    #[must_use]
    pub const fn boundaries(self) -> AcquisitionBoundaries {
        self.boundaries
    }
}

/// Why a public/private/public acquisition cannot admit a candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcquisitionError<E> {
    /// A source read failed.
    Read(E),
    /// One public-state snapshot failed numeric validation.
    InvalidReference(BatteryReferenceError),
    /// The two public-state reads reported different modes.
    ModeChanged,
    /// The complete public/private/public bracket exceeded one monotonic second.
    BracketTooLong,
    /// The injected monotonic clock moved backwards.
    NonMonotonicClock,
    /// The private candidate failed mode-specific validation.
    InvalidTelemetry(TelemetryError),
}

impl<E: Display> Display for AcquisitionError<E> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(error) => write!(formatter, "telemetry acquisition failed: {error}"),
            Self::InvalidReference(error) => {
                write!(formatter, "public power-state validation failed: {error}")
            }
            Self::ModeChanged => {
                formatter.write_str("platform power mode changed during acquisition")
            }
            Self::BracketTooLong => {
                formatter.write_str("telemetry acquisition bracket exceeded one second")
            }
            Self::NonMonotonicClock => {
                formatter.write_str("telemetry acquisition clock moved backwards")
            }
            Self::InvalidTelemetry(error) => {
                write!(formatter, "candidate telemetry is invalid: {error}")
            }
        }
    }
}

impl<E: Error + 'static> Error for AcquisitionError<E> {}

/// Read and validate one public/private/public telemetry bracket.
pub fn acquire_bracketed_telemetry<R, C>(
    reader: &mut R,
    mut monotonic_now: C,
) -> Result<BracketedTelemetry, AcquisitionError<R::Error>>
where
    R: TelemetryAcquisition,
    C: FnMut() -> Duration,
{
    let reference_before_started = monotonic_now();
    let reference_before = reader
        .read_public_battery_reference()
        .map_err(AcquisitionError::Read)?;
    let reference_before_finished = monotonic_now();
    let raw = reader.read_raw().map_err(AcquisitionError::Read)?;
    let telemetry_finished = monotonic_now();
    let reference_after = reader
        .read_public_battery_reference()
        .map_err(AcquisitionError::Read)?;
    let reference_after_finished = monotonic_now();

    if reference_before_finished < reference_before_started
        || telemetry_finished < reference_before_finished
        || reference_after_finished < telemetry_finished
    {
        return Err(AcquisitionError::NonMonotonicClock);
    }
    if reference_after_finished - reference_before_started > MAX_BRACKET_DURATION {
        return Err(AcquisitionError::BracketTooLong);
    }

    let reference_before = reference_before
        .validate()
        .map_err(AcquisitionError::InvalidReference)?;
    let reference_after = reference_after
        .validate()
        .map_err(AcquisitionError::InvalidReference)?;
    if reference_before.mode() != reference_after.mode() {
        return Err(AcquisitionError::ModeChanged);
    }
    let sample = raw
        .validate_for_mode(reference_before.mode())
        .map_err(AcquisitionError::InvalidTelemetry)?;

    Ok(BracketedTelemetry {
        sample,
        reference_before,
        reference_after,
        boundaries: AcquisitionBoundaries {
            reference_before_started,
            reference_before_finished,
            telemetry_finished,
            reference_after_finished,
        },
    })
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
    /// A source-owned count or unsigned accumulator was negative.
    NegativeCountOrAccumulator,
    /// The mode-selected candidate was zero.
    NonPositiveCandidate,
    /// Battery mode reported zero or positive battery power.
    InvalidBatteryPower,
    /// Direct candidate fields violate the required power-balance relation.
    InconsistentPowerBalance,
    /// AC input power does not match voltage times current within tolerance.
    InconsistentInputPower,
    /// Battery load and discharge magnitude do not match within tolerance.
    InconsistentBatteryPower,
    /// Consecutive accepted candidates were validated for different modes.
    ModeTransition,
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
            Self::NegativeCountOrAccumulator => {
                "candidate telemetry count or unsigned accumulator is negative"
            }
            Self::NonPositiveCandidate => "mode-selected candidate is not positive",
            Self::InvalidBatteryPower => "battery power is not negative while on battery",
            Self::InconsistentPowerBalance => "candidate telemetry power balance is inconsistent",
            Self::InconsistentInputPower => "candidate input power cross-check is inconsistent",
            Self::InconsistentBatteryPower => "battery power does not match system load",
            Self::ModeTransition => "platform power mode changed between accepted candidates",
            Self::AboveHardLimit => "candidate power exceeds the hard limit",
        })
    }
}

impl Error for TelemetryError {}

/// Power source mode reported by Apple's public IOPowerSources API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformPowerMode {
    /// The computer is drawing from external AC power.
    Ac,
    /// The computer is drawing from its internal battery.
    Battery,
}

impl PlatformPowerMode {
    /// Stable lowercase value for qualification CSV.
    #[must_use]
    pub const fn csv_value(self) -> &'static str {
        match self {
            Self::Ac => "ac",
            Self::Battery => "battery",
        }
    }
}

/// Allowlisted public IOPowerSources fields used as a battery-terminal reference.
///
/// Apple documents voltage in millivolts and current in milliamps, but does not document the
/// current sign convention. The signed value is therefore preserved in CSV. Its magnitude is
/// called discharge power only when the public API says the machine is on battery and is not
/// charging.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawBatteryReference {
    /// System power mode from `IOPSGetProvidingPowerSourceType`.
    pub mode: PlatformPowerMode,
    /// Public charging state of the present internal battery.
    pub is_charging: bool,
    /// Public internal-battery voltage in millivolts, when exposed in this mode.
    pub voltage_mv: Option<i64>,
    /// Public signed internal-battery current in milliamps, when exposed in this mode.
    pub current_ma: Option<i64>,
}

impl RawBatteryReference {
    /// Validate units and bounds before the public reference enters qualification CSV.
    pub fn validate(self) -> Result<ValidatedBatteryReference, BatteryReferenceError> {
        if self.voltage_mv.is_some_and(|voltage_mv| voltage_mv <= 0) {
            return Err(BatteryReferenceError::InvalidVoltage);
        }
        if self
            .voltage_mv
            .is_some_and(|voltage_mv| voltage_mv > HARD_MAX_MILLIWATTS)
            || self
                .current_ma
                .is_some_and(|current_ma| current_ma.unsigned_abs() > HARD_MAX_MILLIWATTS as u64)
        {
            return Err(BatteryReferenceError::AboveHardLimit);
        }
        if let (Some(voltage_mv), Some(current_ma)) = (self.voltage_mv, self.current_ma) {
            let signed_watts = (voltage_mv as f64) * (current_ma as f64) / MICROWATTS_PER_WATT;
            if !signed_watts.is_finite() || signed_watts.abs() > HARD_MAX_WATTS {
                return Err(BatteryReferenceError::AboveHardLimit);
            }
        }
        Ok(ValidatedBatteryReference(self))
    }

    /// Stable CSV fields. They contain no battery or machine identity.
    #[must_use]
    pub const fn csv_header() -> &'static str {
        "platform_power_mode,battery_is_charging,battery_voltage_mv,battery_current_ma,battery_signed_w,battery_discharge_w"
    }

    /// Stable CSV fields with `prefix` applied to each column name.
    #[must_use]
    pub fn csv_header_with_prefix(prefix: &str) -> String {
        Self::csv_header()
            .split(',')
            .map(|field| format!("{prefix}_{field}"))
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// Numerically validated public battery-terminal reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedBatteryReference(RawBatteryReference);

impl ValidatedBatteryReference {
    /// Public platform power mode associated with this reference.
    #[must_use]
    pub fn mode(self) -> PlatformPowerMode {
        self.0.mode
    }

    /// Signed battery-terminal watts, preserving Apple's undocumented current sign convention.
    #[must_use]
    pub fn signed_watts(self) -> Option<f64> {
        Some((self.0.voltage_mv? as f64) * (self.0.current_ma? as f64) / MICROWATTS_PER_WATT)
    }

    /// Whether all public fields establish a synchronized battery-discharge reference.
    #[must_use]
    pub fn has_discharge_reference(self) -> bool {
        self.0.mode == PlatformPowerMode::Battery
            && !self.0.is_charging
            && self.0.voltage_mv.is_some()
            && self.0.current_ma.is_some()
    }

    /// Battery-discharge magnitude when public mode, charging, voltage, and current are available.
    #[must_use]
    pub fn discharge_watts(self) -> Option<f64> {
        if self.has_discharge_reference() {
            self.signed_watts().map(f64::abs)
        } else {
            None
        }
    }

    /// Render the allowlisted public fields for a qualification CSV row.
    #[must_use]
    pub fn csv_fields(self) -> String {
        let voltage = self
            .0
            .voltage_mv
            .map(|value| value.to_string())
            .unwrap_or_default();
        let current = self
            .0
            .current_ma
            .map(|value| value.to_string())
            .unwrap_or_default();
        let signed = self
            .signed_watts()
            .map(|watts| format!("{watts:.6}"))
            .unwrap_or_default();
        let discharge = self
            .discharge_watts()
            .map(|watts| format!("{watts:.6}"))
            .unwrap_or_default();
        format!(
            "{},{},{voltage},{current},{signed},{discharge}",
            self.0.mode.csv_value(),
            self.0.is_charging,
        )
    }
}

/// Why a public battery-terminal reference is unusable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BatteryReferenceError {
    /// Public battery voltage was zero or negative.
    InvalidVoltage,
    /// Derived battery-terminal power exceeded the protocol hard ceiling.
    AboveHardLimit,
}

impl Display for BatteryReferenceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidVoltage => "public battery voltage is not positive",
            Self::AboveHardLimit => "public battery-terminal power exceeds the hard limit",
        })
    }
}

impl Error for BatteryReferenceError {}
