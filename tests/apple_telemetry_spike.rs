use remote_energy_meter_reporter::power::HARD_MAX_WATTS;
use remote_energy_meter_reporter::spike::{RawPowerTelemetry, TelemetryError};

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
        "elapsed_ms,sample_index,system_load_mw,system_power_in_mw,system_voltage_mv,system_current_ma,battery_power_mw,adapter_efficiency_loss_mw,system_energy_consumed_raw,wall_energy_estimate_raw,derived_input_w"
    );
    assert!(row.starts_with("1500,42,4250,4240,20000,212,0,-180,1200,1020,"));
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
