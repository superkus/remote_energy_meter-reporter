#![cfg(target_os = "macos")]

use std::time::Instant;

use remote_energy_meter_reporter::macos_telemetry::AppleBatteryTelemetryReader;
use remote_energy_meter_reporter::spike::{PlatformPowerMode, acquire_bracketed_telemetry};

#[test]
#[ignore = "requires a physical Apple laptop with candidate and public power-state fields"]
fn bracketed_candidate_telemetry_and_public_power_state_are_readable() {
    let mut reader =
        AppleBatteryTelemetryReader::open().expect("test requires an Apple laptop battery service");
    let started = Instant::now();
    let acquisition = acquire_bracketed_telemetry(&mut reader, || started.elapsed())
        .expect("live public/private/public acquisition must validate");
    let sample = acquisition.sample();
    let before = acquisition.reference_before();
    let after = acquisition.reference_after();

    assert_eq!(before.mode(), after.mode());
    assert!(sample.candidate_watts() > 0.0);
    assert!(sample.system_power_balance_relative_error() <= 0.01);
    assert!(sample.mode_crosscheck_relative_error() <= 0.01);
    if sample.mode() == PlatformPowerMode::Ac {
        assert!(sample.system_power_in_watts() > 0.0);
        assert!(sample.derived_input_watts() > 0.0);
        assert!(sample.power_in_crosscheck_relative_error() <= 0.01);
    }
    assert!(before.signed_watts().is_none_or(f64::is_finite));
    assert!(after.signed_watts().is_none_or(f64::is_finite));
}
