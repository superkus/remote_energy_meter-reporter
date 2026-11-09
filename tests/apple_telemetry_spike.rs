use std::collections::VecDeque;
use std::time::Duration;

use remote_energy_meter_reporter::power::HARD_MAX_WATTS;
use remote_energy_meter_reporter::spike::{
    AcquisitionError, BatteryReferenceError, HardwareUpdate, PlatformPowerMode,
    RawBatteryReference, RawPowerTelemetry, TelemetryAcquisition, TelemetryError,
    acquire_bracketed_telemetry,
};

const MILLIWATTS_PER_WATT: f64 = 1_000.0;
const HARD_MAX_MILLIWATTS: i64 = {
    let milliwatts = HARD_MAX_WATTS * MILLIWATTS_PER_WATT;
    assert!(milliwatts >= 0.0);
    assert!(milliwatts < i64::MAX as f64);
    let exact_milliwatts = milliwatts as i64;
    assert!(exact_milliwatts as f64 == milliwatts);
    exact_milliwatts
};
const ABOVE_HARD_MAX_MILLIWATTS: i64 = match HARD_MAX_MILLIWATTS.checked_add(1) {
    Some(value) => value,
    None => panic!("milliwatt boundary must have a representable successor"),
};

fn plausible() -> RawPowerTelemetry {
    RawPowerTelemetry {
        system_load_mw: 4_250,
        system_power_in_mw: 4_240,
        system_voltage_mv: 20_000,
        system_current_ma: 212,
        battery_power_mw: 0,
        adapter_efficiency_loss_mw: -180,
        system_energy_consumed_raw: 1_200,
        wall_energy_estimate_raw: 1_020,
        system_load_count: 10,
        accumulated_system_load_raw: 42_500,
        system_power_in_count: 10,
        accumulated_system_power_in_raw: 42_400,
        battery_power_count: 5,
        accumulated_battery_power_raw: 0,
        battery_discharge_count: 5,
        accumulated_battery_discharge_raw: 0,
        accumulated_system_energy_consumed_raw: 12_000,
        accumulated_wall_energy_estimate_raw: 10_200,
    }
}

fn plausible_battery() -> RawPowerTelemetry {
    let mut raw = plausible();
    raw.system_power_in_mw = 0;
    raw.system_voltage_mv = 0;
    raw.system_current_ma = 0;
    raw.battery_power_mw = -raw.system_load_mw;
    raw
}

fn public_reference(mode: PlatformPowerMode) -> RawBatteryReference {
    RawBatteryReference {
        mode,
        is_charging: mode == PlatformPowerMode::Ac,
        voltage_mv: Some(12_000),
        current_ma: Some(if mode == PlatformPowerMode::Ac {
            2_500
        } else {
            -2_500
        }),
    }
}

struct FakeAcquisition {
    references: VecDeque<RawBatteryReference>,
    raw: Option<RawPowerTelemetry>,
    calls: Vec<&'static str>,
}

impl FakeAcquisition {
    fn new(
        before: RawBatteryReference,
        raw: RawPowerTelemetry,
        after: RawBatteryReference,
    ) -> Self {
        Self {
            references: VecDeque::from([before, after]),
            raw: Some(raw),
            calls: Vec::new(),
        }
    }
}

impl TelemetryAcquisition for FakeAcquisition {
    type Error = &'static str;

    fn read_public_battery_reference(&mut self) -> Result<RawBatteryReference, Self::Error> {
        self.calls.push("public");
        self.references.pop_front().ok_or("missing public read")
    }

    fn read_raw(&mut self) -> Result<RawPowerTelemetry, Self::Error> {
        self.calls.push("private");
        self.raw.take().ok_or("missing private read")
    }
}

fn acquire_with_times(
    reader: &mut FakeAcquisition,
    times_ms: [u64; 4],
) -> Result<remote_energy_meter_reporter::spike::BracketedTelemetry, AcquisitionError<&'static str>>
{
    let mut times = times_ms.map(Duration::from_millis).into_iter();
    acquire_bracketed_telemetry(reader, || {
        times.next().expect("four acquisition boundaries")
    })
}

#[test]
fn bracketed_acquisition_rejects_mode_transitions_and_binds_stable_mode() {
    let mut stable = FakeAcquisition::new(
        public_reference(PlatformPowerMode::Battery),
        plausible_battery(),
        public_reference(PlatformPowerMode::Battery),
    );
    let acquired = acquire_with_times(&mut stable, [10, 20, 30, 40]).unwrap();
    assert_eq!(stable.calls, ["public", "private", "public"]);
    assert_eq!(acquired.sample().mode(), PlatformPowerMode::Battery);
    assert_eq!(acquired.sample().candidate_watts(), 4.25);
    assert_eq!(
        acquired.boundaries().reference_before_started,
        Duration::from_millis(10)
    );
    assert_eq!(
        acquired.boundaries().reference_after_finished,
        Duration::from_millis(40)
    );

    let mut changing = FakeAcquisition::new(
        public_reference(PlatformPowerMode::Ac),
        plausible(),
        public_reference(PlatformPowerMode::Battery),
    );
    assert_eq!(
        acquire_with_times(&mut changing, [0, 10, 20, 30]),
        Err(AcquisitionError::ModeChanged)
    );

    let ac = plausible()
        .validate_for_mode(PlatformPowerMode::Ac)
        .unwrap();
    assert_eq!(
        acquired.sample().update_since(ac),
        Err(TelemetryError::ModeTransition)
    );
}

#[test]
fn bracketed_acquisition_enforces_the_one_second_limit() {
    let mut at_limit = FakeAcquisition::new(
        public_reference(PlatformPowerMode::Ac),
        plausible(),
        public_reference(PlatformPowerMode::Ac),
    );
    assert!(acquire_with_times(&mut at_limit, [0, 100, 900, 1_000]).is_ok());

    let mut over_limit = FakeAcquisition::new(
        public_reference(PlatformPowerMode::Ac),
        plausible(),
        public_reference(PlatformPowerMode::Ac),
    );
    assert_eq!(
        acquire_with_times(&mut over_limit, [0, 100, 900, 1_001]),
        Err(AcquisitionError::BracketTooLong)
    );
}

#[test]
fn bracketed_acquisition_rejects_each_non_monotonic_boundary_pair() {
    for times in [[10, 9, 20, 30], [10, 20, 19, 30], [10, 20, 30, 29]] {
        let mut reader = FakeAcquisition::new(
            public_reference(PlatformPowerMode::Ac),
            plausible(),
            public_reference(PlatformPowerMode::Ac),
        );
        assert_eq!(
            acquire_with_times(&mut reader, times),
            Err(AcquisitionError::NonMonotonicClock)
        );
    }
}

#[test]
fn converts_milliwatts_and_cross_checks_voltage_times_current() {
    let sample = plausible().validate().unwrap();
    assert_eq!(sample.system_load_watts(), 4.25);
    assert_eq!(sample.system_power_in_watts(), 4.24);
    assert_eq!(sample.derived_input_watts(), 4.24);
    assert!(sample.power_in_crosscheck_relative_error() < 0.001);
}

#[test]
fn accepts_exact_direct_and_derived_power_ceilings() {
    let mut raw = plausible();
    raw.system_load_mw = HARD_MAX_MILLIWATTS;
    raw.system_power_in_mw = HARD_MAX_MILLIWATTS;
    raw.system_voltage_mv = HARD_MAX_MILLIWATTS;
    raw.system_current_ma = 1_000;

    let sample = raw.validate().expect("exact hard ceilings are valid");
    assert_eq!(sample.system_load_watts(), HARD_MAX_WATTS);
    assert_eq!(sample.system_power_in_watts(), HARD_MAX_WATTS);
    assert_eq!(sample.derived_input_watts(), HARD_MAX_WATTS);
}

#[test]
fn rejects_negative_or_above_limit_direct_power() {
    let mut raw = plausible();
    raw.system_load_mw = -1;
    assert_eq!(raw.validate(), Err(TelemetryError::NegativeSystemLoad));

    let mut raw = plausible();
    raw.system_power_in_mw = -1;
    assert_eq!(raw.validate(), Err(TelemetryError::NegativeSystemPowerIn));

    let mut raw = plausible();
    raw.system_load_mw = ABOVE_HARD_MAX_MILLIWATTS;
    assert_eq!(raw.validate(), Err(TelemetryError::AboveHardLimit));

    let mut raw = plausible();
    raw.system_power_in_mw = ABOVE_HARD_MAX_MILLIWATTS;
    assert_eq!(raw.validate(), Err(TelemetryError::AboveHardLimit));
}

#[test]
fn rejects_derived_power_above_the_hard_limit() {
    let mut raw = plausible();
    raw.system_voltage_mv = ABOVE_HARD_MAX_MILLIWATTS;
    raw.system_current_ma = 1_000;

    assert_eq!(raw.validate(), Err(TelemetryError::AboveHardLimit));
}

#[test]
fn mode_selects_system_input_on_ac_and_system_load_on_battery() {
    let ac = plausible();
    assert_eq!(
        ac.validate_for_mode(PlatformPowerMode::Ac)
            .unwrap()
            .candidate_watts(),
        4.24
    );

    let battery = plausible_battery();
    assert_eq!(
        battery
            .validate_for_mode(PlatformPowerMode::Battery)
            .unwrap()
            .candidate_watts(),
        4.25
    );
}

#[test]
fn power_balance_covers_battery_discharge_and_ac_charging() {
    let mut battery = plausible();
    battery.system_load_mw = 7_092;
    battery.system_power_in_mw = 0;
    battery.system_voltage_mv = 0;
    battery.system_current_ma = 0;
    battery.battery_power_mw = -7_092;
    assert_eq!(
        battery
            .validate_for_mode(PlatformPowerMode::Battery)
            .unwrap()
            .system_power_balance_relative_error(),
        0.0
    );

    let mut charging = plausible();
    charging.system_load_mw = 9_310;
    charging.system_power_in_mw = 34_809;
    charging.battery_power_mw = 25_499;
    charging.system_voltage_mv = 34_809;
    charging.system_current_ma = 1_000;
    assert_eq!(
        charging
            .validate_for_mode(PlatformPowerMode::Ac)
            .unwrap()
            .system_power_balance_relative_error(),
        0.0
    );
}

#[test]
fn battery_mode_allows_unavailable_ac_input_crosscheck_fields() {
    let raw = plausible_battery();

    let sample = raw.validate_for_mode(PlatformPowerMode::Battery).unwrap();
    assert_eq!(sample.system_load_watts(), 4.25);
    assert_eq!(sample.system_power_in_watts(), 0.0);
    assert_eq!(sample.derived_input_watts(), 0.0);
}

#[test]
fn rejects_non_positive_voltage_and_negative_current() {
    let mut raw = plausible();
    raw.system_voltage_mv = 0;
    assert_eq!(raw.validate(), Err(TelemetryError::InvalidVoltage));

    let mut raw = plausible();
    raw.system_current_ma = -1;
    assert_eq!(raw.validate(), Err(TelemetryError::InvalidCurrent));
}

#[test]
fn csv_contains_measurements_but_no_machine_identity() {
    let sample = plausible().validate().unwrap();
    let header = RawPowerTelemetry::csv_header();
    let row = sample.to_csv_row(1_500, 42);

    assert_eq!(
        header,
        "elapsed_ms,sample_index,system_load_mw,system_power_in_mw,system_voltage_mv,system_current_ma,battery_power_mw,adapter_efficiency_loss_mw,system_energy_consumed_raw,wall_energy_estimate_raw,system_load_count,accumulated_system_load_raw,system_power_in_count,accumulated_system_power_in_raw,battery_power_count,accumulated_battery_power_raw,battery_discharge_count,accumulated_battery_discharge_raw,accumulated_system_energy_consumed_raw,accumulated_wall_energy_estimate_raw,derived_input_w"
    );
    assert!(row.starts_with(
        "1500,42,4250,4240,20000,212,0,-180,1200,1020,10,42500,10,42400,5,0,5,0,12000,10200,"
    ));
    for forbidden in [
        "serial",
        "uuid",
        "username",
        "hostname",
        "model",
        "mac_address",
    ] {
        assert!(!header.contains(forbidden));
        assert!(!row.contains(forbidden));
    }
}

#[test]
fn hardware_update_state_uses_apple_accumulator_counts_not_read_frequency() {
    let first = plausible().validate().unwrap();
    let same = plausible().validate().unwrap();
    assert_eq!(same.update_since(first), Ok(HardwareUpdate::Unchanged));

    let mut advanced = plausible();
    advanced.system_load_count += 1;
    advanced.system_power_in_count += 1;
    let advanced = advanced.validate().unwrap();
    assert_eq!(advanced.update_since(first), Ok(HardwareUpdate::Advanced));

    let mut reset = plausible();
    reset.system_load_count -= 1;
    let reset = reset.validate().unwrap();
    assert_eq!(reset.update_since(first), Ok(HardwareUpdate::CounterReset));
}

#[test]
fn rejects_every_negative_unsigned_accumulator() {
    let mut cases = [plausible(); 9];
    cases[0].system_load_count = -1;
    cases[1].accumulated_system_load_raw = -1;
    cases[2].system_power_in_count = -1;
    cases[3].accumulated_system_power_in_raw = -1;
    cases[4].battery_power_count = -1;
    cases[5].accumulated_battery_power_raw = -1;
    cases[6].battery_discharge_count = -1;
    cases[7].accumulated_system_energy_consumed_raw = -1;
    cases[8].accumulated_wall_energy_estimate_raw = -1;

    for raw in cases {
        assert_eq!(
            raw.validate(),
            Err(TelemetryError::NegativeCountOrAccumulator)
        );
    }
}

#[test]
fn signed_accumulated_battery_discharge_is_preserved() {
    let mut raw = plausible();
    raw.accumulated_battery_discharge_raw = -1;
    assert!(raw.validate().is_ok());
}

#[test]
fn each_hardware_count_drives_update_state_and_reset_takes_precedence() {
    let first = plausible().validate().unwrap();
    let mut advances = [plausible(); 4];
    advances[0].system_load_count += 1;
    advances[1].system_power_in_count += 1;
    advances[2].battery_power_count += 1;
    advances[3].battery_discharge_count += 1;
    for raw in advances {
        assert_eq!(
            raw.validate().unwrap().update_since(first),
            Ok(HardwareUpdate::Advanced)
        );
    }

    let mut resets = [plausible(); 4];
    resets[0].system_load_count -= 1;
    resets[1].system_power_in_count -= 1;
    resets[2].battery_power_count -= 1;
    resets[3].battery_discharge_count -= 1;
    for raw in resets {
        assert_eq!(
            raw.validate().unwrap().update_since(first),
            Ok(HardwareUpdate::CounterReset)
        );
    }

    let mut mixed = plausible();
    mixed.system_load_count += 1;
    mixed.system_power_in_count -= 1;
    assert_eq!(
        mixed.validate().unwrap().update_since(first),
        Ok(HardwareUpdate::CounterReset)
    );
}

#[test]
fn public_battery_reference_preserves_signed_current_and_derives_discharge_magnitude() {
    let reference = RawBatteryReference {
        mode: PlatformPowerMode::Battery,
        is_charging: false,
        voltage_mv: Some(12_000),
        current_ma: Some(-2_500),
    }
    .validate()
    .unwrap();

    assert_eq!(reference.signed_watts(), Some(-30.0));
    assert_eq!(reference.discharge_watts(), Some(30.0));
    assert_eq!(
        reference.csv_fields(),
        "battery,false,12000,-2500,-30.000000,30.000000"
    );
}

#[test]
fn public_battery_reference_is_not_called_discharge_while_on_ac_or_charging() {
    for raw in [
        RawBatteryReference {
            mode: PlatformPowerMode::Ac,
            is_charging: false,
            voltage_mv: Some(12_000),
            current_ma: Some(-2_500),
        },
        RawBatteryReference {
            mode: PlatformPowerMode::Battery,
            is_charging: true,
            voltage_mv: Some(12_000),
            current_ma: Some(2_500),
        },
    ] {
        let reference = raw.validate().unwrap();
        assert_eq!(reference.discharge_watts(), None);
    }
}

#[test]
fn public_battery_reference_rejects_invalid_voltage_and_power() {
    let invalid_voltage = RawBatteryReference {
        mode: PlatformPowerMode::Battery,
        is_charging: false,
        voltage_mv: Some(0),
        current_ma: Some(-1),
    };
    assert_eq!(
        invalid_voltage.validate(),
        Err(BatteryReferenceError::InvalidVoltage)
    );

    let above_limit = RawBatteryReference {
        mode: PlatformPowerMode::Battery,
        is_charging: false,
        voltage_mv: Some(i64::MAX),
        current_ma: Some(i64::MIN),
    };
    assert_eq!(
        above_limit.validate(),
        Err(BatteryReferenceError::AboveHardLimit)
    );
}

#[test]
fn public_battery_reference_allows_omitted_voltage() {
    for mode in [PlatformPowerMode::Ac, PlatformPowerMode::Battery] {
        let reference = RawBatteryReference {
            mode,
            is_charging: mode == PlatformPowerMode::Ac,
            voltage_mv: None,
            current_ma: Some(-2_500),
        }
        .validate()
        .unwrap();

        assert_eq!(reference.signed_watts(), None);
        assert_eq!(reference.discharge_watts(), None);
        assert_eq!(
            reference.csv_fields(),
            match mode {
                PlatformPowerMode::Ac => "ac,true,,-2500,,",
                PlatformPowerMode::Battery => "battery,false,,-2500,,",
            }
        );
    }
}

#[test]
fn public_battery_reference_allows_omitted_current() {
    for mode in [PlatformPowerMode::Ac, PlatformPowerMode::Battery] {
        let reference = RawBatteryReference {
            mode,
            is_charging: mode == PlatformPowerMode::Ac,
            voltage_mv: Some(12_000),
            current_ma: None,
        }
        .validate()
        .unwrap();

        assert_eq!(reference.signed_watts(), None);
        assert_eq!(reference.discharge_watts(), None);
        assert_eq!(
            reference.csv_fields(),
            match mode {
                PlatformPowerMode::Ac => "ac,true,12000,,,",
                PlatformPowerMode::Battery => "battery,false,12000,,,",
            }
        );
    }
}

#[test]
fn public_battery_reference_allows_both_terminal_fields_omitted() {
    for mode in [PlatformPowerMode::Ac, PlatformPowerMode::Battery] {
        let reference = RawBatteryReference {
            mode,
            is_charging: mode == PlatformPowerMode::Ac,
            voltage_mv: None,
            current_ma: None,
        }
        .validate()
        .unwrap();

        assert_eq!(reference.signed_watts(), None);
        assert_eq!(reference.discharge_watts(), None);
        assert!(!reference.has_discharge_reference());
        assert_eq!(
            reference.csv_fields(),
            format!("{},{},,,,", mode.csv_value(), mode == PlatformPowerMode::Ac)
        );
    }
}

#[test]
fn public_battery_reference_csv_has_only_allowlisted_measurements() {
    assert_eq!(
        RawBatteryReference::csv_header(),
        "platform_power_mode,battery_is_charging,battery_voltage_mv,battery_current_ma,battery_signed_w,battery_discharge_w"
    );
    assert_eq!(
        RawBatteryReference::csv_header_with_prefix("reference"),
        "reference_platform_power_mode,reference_battery_is_charging,reference_battery_voltage_mv,reference_battery_current_ma,reference_battery_signed_w,reference_battery_discharge_w"
    );
    for forbidden in [
        "serial",
        "uuid",
        "username",
        "hostname",
        "model",
        "mac_address",
    ] {
        assert!(!RawBatteryReference::csv_header().contains(forbidden));
    }
}

#[test]
fn hardware_update_csv_value_is_stable() {
    assert_eq!(HardwareUpdate::Initial.csv_value(), "initial");
    assert_eq!(HardwareUpdate::Advanced.csv_value(), "advanced");
    assert_eq!(HardwareUpdate::Unchanged.csv_value(), "unchanged");
    assert_eq!(HardwareUpdate::CounterReset.csv_value(), "counter_reset");
}

#[test]
fn rejects_extreme_voltage_or_current_when_the_counterpart_is_zero() {
    let rejected = [(i64::MAX, 0), (i64::MIN, 0), (0, i64::MAX), (0, i64::MIN)].map(
        |(voltage_mv, current_ma)| {
            let mut raw = plausible_battery();
            raw.system_voltage_mv = voltage_mv;
            raw.system_current_ma = current_ma;
            raw.validate_for_mode(PlatformPowerMode::Battery).is_err()
        },
    );

    assert_eq!(rejected, [true; 4]);
}

#[test]
fn public_battery_reference_rejects_extreme_partial_terminal_fields() {
    let rejected = [
        (Some(i64::MAX), None),
        (Some(i64::MIN), None),
        (None, Some(i64::MAX)),
        (None, Some(i64::MIN)),
    ]
    .map(|(voltage_mv, current_ma)| {
        RawBatteryReference {
            mode: PlatformPowerMode::Battery,
            is_charging: false,
            voltage_mv,
            current_ma,
        }
        .validate()
        .is_err()
    });

    assert_eq!(rejected, [true; 4]);
}

#[test]
fn battery_mode_rejects_nonnegative_battery_power() {
    for battery_power_mw in [1, 0] {
        let mut raw = plausible_battery();
        raw.battery_power_mw = battery_power_mw;

        assert!(
            raw.validate_for_mode(PlatformPowerMode::Battery).is_err(),
            "battery mode requires negative BatteryPower, got {battery_power_mw}"
        );
    }
}

#[test]
fn battery_mode_accepts_a_magnitude_match_at_the_exact_one_percent_boundary() {
    let mut raw = plausible_battery();
    raw.system_load_mw = 10_000;
    raw.system_power_in_mw = 100;
    raw.battery_power_mw = -9_900;

    assert!(raw.validate_for_mode(PlatformPowerMode::Battery).is_ok());
}

#[test]
fn battery_mode_enforces_the_full_power_balance_at_the_exact_tolerance_boundary() {
    let mut at_boundary = plausible_battery();
    at_boundary.system_load_mw = 1_000_000;
    at_boundary.system_power_in_mw = 1_000;
    at_boundary.battery_power_mw = -999_010;
    assert!(
        at_boundary
            .validate_for_mode(PlatformPowerMode::Battery)
            .is_ok()
    );

    let mut past_boundary = at_boundary;
    past_boundary.battery_power_mw = -999_011;
    assert_eq!(
        past_boundary.validate_for_mode(PlatformPowerMode::Battery),
        Err(TelemetryError::InconsistentPowerBalance)
    );
}

#[test]
fn battery_mode_rejects_a_magnitude_mismatch_past_one_percent() {
    let mut raw = plausible_battery();
    raw.system_load_mw = 10_000;
    raw.battery_power_mw = -9_899;

    assert!(raw.validate_for_mode(PlatformPowerMode::Battery).is_err());
}

#[test]
fn battery_csv_fields_separate_full_balance_from_magnitude_crosscheck() {
    let mut raw = plausible_battery();
    raw.system_load_mw = 10_000;
    raw.system_power_in_mw = 100;
    raw.battery_power_mw = -9_900;

    let sample = raw
        .validate_for_mode(PlatformPowerMode::Battery)
        .expect("the exact one-percent residual is valid");
    assert_eq!(sample.system_power_balance_relative_error(), 0.0);
    assert_eq!(sample.mode_crosscheck_relative_error(), 0.01);
    assert_eq!(
        sample.qualification_csv_fields(),
        "10.000000,0.000000,0.010000"
    );
}

#[test]
fn battery_balance_uses_the_one_milliwatt_floor_at_low_power() {
    let mut at_floor = plausible_battery();
    at_floor.system_load_mw = 99;
    at_floor.battery_power_mw = -98;
    assert!(
        at_floor
            .validate_for_mode(PlatformPowerMode::Battery)
            .is_ok()
    );

    let mut past_floor = at_floor;
    past_floor.battery_power_mw = -97;
    assert!(
        past_floor
            .validate_for_mode(PlatformPowerMode::Battery)
            .is_err()
    );
}

#[test]
fn ac_input_crosscheck_accepts_exactly_one_percent_and_rejects_one_microwatt_more() {
    let mut at_boundary = plausible();
    at_boundary.system_power_in_mw = 10_000;
    at_boundary.system_load_mw = 10_000;
    at_boundary.battery_power_mw = 0;
    at_boundary.system_voltage_mv = 9_900;
    at_boundary.system_current_ma = 1_000;
    assert!(at_boundary.validate_for_mode(PlatformPowerMode::Ac).is_ok());

    let mut past_boundary = at_boundary;
    past_boundary.system_voltage_mv = 1;
    past_boundary.system_current_ma = 9_899_999;
    assert_eq!(
        past_boundary.validate_for_mode(PlatformPowerMode::Ac),
        Err(TelemetryError::InconsistentInputPower)
    );
}

#[test]
fn ac_input_crosscheck_uses_one_milliwatt_floor_at_exact_microwatt_boundary() {
    let mut at_floor = plausible();
    at_floor.system_power_in_mw = 99;
    at_floor.system_load_mw = 99;
    at_floor.battery_power_mw = 0;
    at_floor.system_voltage_mv = 98;
    at_floor.system_current_ma = 1_000;
    assert!(at_floor.validate_for_mode(PlatformPowerMode::Ac).is_ok());

    let mut past_floor = at_floor;
    past_floor.system_voltage_mv = 1;
    past_floor.system_current_ma = 97_999;
    assert_eq!(
        past_floor.validate_for_mode(PlatformPowerMode::Ac),
        Err(TelemetryError::InconsistentInputPower)
    );
}

#[test]
fn ac_balance_accepts_exactly_one_percent_and_rejects_one_milliwatt_more() {
    let mut at_boundary = plausible();
    at_boundary.system_power_in_mw = 10_000;
    at_boundary.system_load_mw = 9_900;
    at_boundary.battery_power_mw = 0;
    at_boundary.system_voltage_mv = 10_000;
    at_boundary.system_current_ma = 1_000;
    assert!(at_boundary.validate_for_mode(PlatformPowerMode::Ac).is_ok());

    let mut past_boundary = at_boundary;
    past_boundary.system_load_mw = 9_899;
    assert!(
        past_boundary
            .validate_for_mode(PlatformPowerMode::Ac)
            .is_err()
    );
}

#[test]
fn ac_balance_uses_the_one_milliwatt_floor_at_low_power() {
    let mut at_floor = plausible();
    at_floor.system_power_in_mw = 99;
    at_floor.system_load_mw = 98;
    at_floor.battery_power_mw = 0;
    at_floor.system_voltage_mv = 99;
    at_floor.system_current_ma = 1_000;
    assert!(at_floor.validate_for_mode(PlatformPowerMode::Ac).is_ok());

    let mut past_floor = at_floor;
    past_floor.system_load_mw = 97;
    assert!(past_floor.validate_for_mode(PlatformPowerMode::Ac).is_err());
}

#[test]
fn rejects_zero_mode_selected_candidate_in_each_power_mode() {
    let mut ac = plausible();
    ac.system_load_mw = 0;
    ac.system_power_in_mw = 0;
    ac.system_current_ma = 0;
    ac.battery_power_mw = 0;
    assert!(ac.validate_for_mode(PlatformPowerMode::Ac).is_err());

    let mut battery = plausible_battery();
    battery.system_load_mw = 0;
    battery.battery_power_mw = -1;
    assert!(
        battery
            .validate_for_mode(PlatformPowerMode::Battery)
            .is_err()
    );
}

#[test]
fn validated_telemetry_keeps_candidate_selection_bound_to_its_validated_mode() {
    let sample = plausible_battery()
        .validate_for_mode(PlatformPowerMode::Battery)
        .unwrap();

    assert_eq!(sample.mode(), PlatformPowerMode::Battery);
    assert_eq!(sample.candidate_watts(), sample.system_load_watts());
}

#[test]
fn battery_candidate_accepts_the_exact_hard_ceiling() {
    let mut raw = plausible_battery();
    raw.system_load_mw = HARD_MAX_MILLIWATTS;
    raw.battery_power_mw = -HARD_MAX_MILLIWATTS;

    let sample = raw
        .validate_for_mode(PlatformPowerMode::Battery)
        .expect("the exact hard ceiling is valid in battery mode");
    assert_eq!(sample.candidate_watts(), HARD_MAX_WATTS);
}
