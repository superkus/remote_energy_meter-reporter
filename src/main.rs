use std::process::ExitCode;

use remote_energy_meter_reporter::power::{PowerSource, UnavailablePowerSource};

fn main() -> ExitCode {
    let mut source = UnavailablePowerSource;
    match source.sample() {
        Ok(reading) => {
            println!("{:.3}", reading.get());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{}", error.code());
            ExitCode::from(2)
        }
    }
}
