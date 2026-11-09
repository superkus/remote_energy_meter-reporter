use std::env;
#[cfg(target_os = "macos")]
use std::io::{self, Write};
use std::process::ExitCode;
#[cfg(target_os = "macos")]
use std::thread;
#[cfg(target_os = "macos")]
use std::time::{Duration, Instant};

use remote_energy_meter_reporter::cli::{Command, SpikeOptions, parse_args, usage};
#[cfg(target_os = "macos")]
use remote_energy_meter_reporter::macos_telemetry::AppleBatteryTelemetryReader;
use remote_energy_meter_reporter::power::{PowerSource, UnavailablePowerSource};
#[cfg(target_os = "macos")]
use remote_energy_meter_reporter::spike::{
    BracketedTelemetry, HardwareUpdate, RawBatteryReference, RawPowerTelemetry, ValidatedTelemetry,
    acquire_bracketed_telemetry,
};

/// Existing reporter status for unavailable or not-yet-code-qualified power data.
const EXIT_POWER_UNAVAILABLE: u8 = 2;
#[cfg(target_os = "macos")]
/// Spike-specific status for an unavailable or invalid telemetry sample.
const EXIT_TELEMETRY_UNAVAILABLE: u8 = 3;
/// BSD `sysexits.h` status for invalid command arguments.
const EXIT_USAGE: u8 = 64;
#[cfg(target_os = "macos")]
/// BSD `sysexits.h` status for an output I/O failure.
const EXIT_IO_ERROR: u8 = 74;

fn main() -> ExitCode {
    let arguments = env::args_os().skip(1).map(|argument| {
        argument
            .into_string()
            .unwrap_or_else(|_| String::from("\0"))
    });
    match parse_args(arguments) {
        Ok(Command::Status) => fail_closed_status(),
        Ok(Command::Help) => {
            println!("{}", usage());
            ExitCode::SUCCESS
        }
        Ok(Command::Spike(options)) => run_spike(options),
        Err(_) => {
            eprintln!("{}", usage());
            ExitCode::from(EXIT_USAGE)
        }
    }
}

fn fail_closed_status() -> ExitCode {
    let mut source = UnavailablePowerSource;
    match source.sample() {
        Ok(reading) => {
            println!("{:.3}", reading.get());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{}", error.code());
            ExitCode::from(EXIT_POWER_UNAVAILABLE)
        }
    }
}

#[cfg(target_os = "macos")]
fn write_spike_csv_header(output: &mut impl Write) -> io::Result<()> {
    let raw_fields = RawPowerTelemetry::csv_header();
    let qualification_fields = ValidatedTelemetry::qualification_csv_header();
    let reference_before_fields = RawBatteryReference::csv_header_with_prefix("reference_before");
    let reference_after_fields = RawBatteryReference::csv_header_with_prefix("reference_after");
    writeln!(
        output,
        "{raw_fields},\
         {qualification_fields},\
         hardware_update,\
         reference_before_started_elapsed_ms,\
         reference_before_finished_elapsed_ms,\
         telemetry_finished_elapsed_ms,\
         reference_after_finished_elapsed_ms,\
         {reference_before_fields},\
         {reference_after_fields}"
    )
}

#[cfg(target_os = "macos")]
fn write_spike_csv_row(
    output: &mut impl Write,
    acquisition: BracketedTelemetry,
    hardware_update: HardwareUpdate,
    sample_index: u64,
) -> io::Result<()> {
    let sample = acquisition.sample();
    let boundaries = acquisition.boundaries();
    let elapsed_ms = |elapsed: Duration| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
    let raw_fields = sample.to_csv_row(elapsed_ms(boundaries.telemetry_finished), sample_index);
    let qualification_fields = sample.qualification_csv_fields();
    let hardware_update = hardware_update.csv_value();
    let reference_before_started_elapsed_ms = elapsed_ms(boundaries.reference_before_started);
    let reference_before_finished_elapsed_ms = elapsed_ms(boundaries.reference_before_finished);
    let telemetry_finished_elapsed_ms = elapsed_ms(boundaries.telemetry_finished);
    let reference_after_finished_elapsed_ms = elapsed_ms(boundaries.reference_after_finished);
    let reference_before_fields = acquisition.reference_before().csv_fields();
    let reference_after_fields = acquisition.reference_after().csv_fields();
    writeln!(
        output,
        "{raw_fields},\
         {qualification_fields},\
         {hardware_update},\
         {reference_before_started_elapsed_ms},\
         {reference_before_finished_elapsed_ms},\
         {telemetry_finished_elapsed_ms},\
         {reference_after_finished_elapsed_ms},\
         {reference_before_fields},\
         {reference_after_fields}"
    )
}

#[cfg(target_os = "macos")]
fn run_spike(options: SpikeOptions) -> ExitCode {
    let mut reader = match AppleBatteryTelemetryReader::open() {
        Ok(reader) => reader,
        Err(error) => {
            eprintln!("TELEMETRY_UNAVAILABLE: {error}");
            return ExitCode::from(EXIT_TELEMETRY_UNAVAILABLE);
        }
    };
    let stdout = io::stdout();
    let mut output = stdout.lock();
    if write_spike_csv_header(&mut output).is_err() {
        return ExitCode::from(EXIT_IO_ERROR);
    }
    let started = Instant::now();
    let mut previous = None;
    for sample_index in 0..options.samples {
        let acquisition = match acquire_bracketed_telemetry(&mut reader, || started.elapsed()) {
            Ok(acquisition) => acquisition,
            Err(error) => {
                eprintln!("TELEMETRY_UNAVAILABLE: {error}");
                return ExitCode::from(EXIT_TELEMETRY_UNAVAILABLE);
            }
        };
        let sample = acquisition.sample();
        let hardware_update = match previous {
            Some(previous) => match sample.update_since(previous) {
                Ok(update) => update,
                Err(error) => {
                    eprintln!("TELEMETRY_UNAVAILABLE: {error}");
                    return ExitCode::from(EXIT_TELEMETRY_UNAVAILABLE);
                }
            },
            None => HardwareUpdate::Initial,
        };
        previous = Some(sample);
        if write_spike_csv_row(&mut output, acquisition, hardware_update, sample_index).is_err() {
            return ExitCode::from(EXIT_IO_ERROR);
        }
        if sample_index + 1 < options.samples {
            thread::sleep(Duration::from_millis(options.interval_ms));
        }
    }
    ExitCode::SUCCESS
}

#[cfg(not(target_os = "macos"))]
fn run_spike(_options: SpikeOptions) -> ExitCode {
    fail_closed_status()
}
