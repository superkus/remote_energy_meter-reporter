#![cfg(unix)]

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::process::Command;

use remote_energy_meter_reporter::cli::usage;

#[test]
fn invalid_utf8_argument_exits_with_controlled_usage_failure() {
    let output = Command::new(env!("CARGO_BIN_EXE_remote-energy-meter-reporter"))
        .arg(OsString::from_vec(vec![0xff]))
        .output()
        .expect("reporter executable should run");

    assert_eq!(output.status.code(), Some(64));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, format!("{}\n", usage()).as_bytes());
}
