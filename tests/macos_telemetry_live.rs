#![cfg(target_os = "macos")]

use remote_energy_meter_reporter::macos_telemetry::AppleBatteryTelemetryReader;

#[test]
#[ignore = "requires a physical Apple laptop with candidate PowerTelemetryData fields"]
fn candidate_telemetry_is_readable_but_not_qualified_as_a_power_source() {
    let mut reader =
        AppleBatteryTelemetryReader::open().expect("test requires an Apple laptop battery service");
    let raw = reader
        .read_raw()
        .expect("test requires the candidate PowerTelemetryData fields");
    let sample = raw
        .validate()
        .expect("live candidate fields must pass numeric safety bounds");

    assert!(sample.system_load_watts() >= 0.0);
    assert!(sample.system_power_in_watts() >= 0.0);
    assert!(sample.derived_input_watts() >= 0.0);
    // Independent voltage × current should be close enough to catch a mistaken unit hypothesis.
    assert!(sample.power_in_crosscheck_relative_error() <= 0.10);
}
