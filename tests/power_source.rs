use remote_energy_meter_reporter::power::{
    HARD_MAX_WATTS, InvalidWatts, PowerSource, PowerSourceError, UnavailablePowerSource,
    WholeSystemWatts,
};

#[test]
fn accepts_the_closed_valid_range() {
    assert_eq!(WholeSystemWatts::new(0.0).unwrap().get(), 0.0);
    assert_eq!(
        WholeSystemWatts::new(HARD_MAX_WATTS).unwrap().get(),
        HARD_MAX_WATTS
    );
}

#[test]
fn rejects_non_finite_negative_and_over_limit_values() {
    for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert_eq!(WholeSystemWatts::new(value), Err(InvalidWatts::NotFinite));
    }
    assert_eq!(WholeSystemWatts::new(-0.001), Err(InvalidWatts::Negative));
    assert_eq!(
        WholeSystemWatts::new(HARD_MAX_WATTS + 0.001),
        Err(InvalidWatts::AboveHardLimit)
    );
}

#[test]
fn the_baseline_source_fails_closed() {
    let mut source = UnavailablePowerSource;
    assert_eq!(
        source.sample(),
        Err(PowerSourceError::WholeSystemUnavailable)
    );
    assert_eq!(
        PowerSourceError::WholeSystemUnavailable.code(),
        "WHOLE_SYSTEM_UNAVAILABLE"
    );
}
