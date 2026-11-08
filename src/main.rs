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
use remote_energy_meter_reporter::spike::RawPowerTelemetry;

/// Existing reporter status for unavailable or unqualified power data.
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
    if writeln!(output, "{}", RawPowerTelemetry::csv_header()).is_err() {
        return ExitCode::from(EXIT_IO_ERROR);
    }
    let started = Instant::now();
    for sample_index in 0..options.samples {
        let raw = match reader.read_raw() {
            Ok(raw) => raw,
            Err(error) => {
                eprintln!("TELEMETRY_UNAVAILABLE: {error}");
                return ExitCode::from(EXIT_TELEMETRY_UNAVAILABLE);
            }
        };
        let sample = match raw.validate() {
            Ok(sample) => sample,
            Err(_) => {
                eprintln!(
                    "TELEMETRY_UNAVAILABLE: candidate telemetry failed numeric safety checks"
                );
                return ExitCode::from(EXIT_TELEMETRY_UNAVAILABLE);
            }
        };
        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        if writeln!(output, "{}", sample.to_csv_row(elapsed_ms, sample_index)).is_err() {
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
