//! Minimal, dependency-free command-line parsing for the qualification spike.

/// Maximum rows one invocation may emit (about one hour at the minimum interval, or ten hours at the default).
pub const MAX_SAMPLES: u64 = 36_000;
/// Maximum scheduled span from the first sample to the last sample (ten hours).
pub const MAX_SAMPLING_SPAN_MS: u64 = 10 * 60 * 60 * 1_000;
/// Shortest allowed interval; prevents an accidental telemetry busy loop.
pub const MIN_INTERVAL_MS: u64 = 100;
/// Longest allowed interval; keeps a mistaken invocation visibly bounded.
pub const MAX_INTERVAL_MS: u64 = 60_000;

const MAX_GRAMMAR_TOKENS: usize = 5;
const MAX_NUMERIC_TOKEN_BYTES: usize = 5;

/// One supported foreground command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command {
    /// Fail-closed product status; no platform is qualified yet.
    Status,
    /// Collect raw, privacy-safe candidate telemetry for qualification.
    Spike(SpikeOptions),
    /// Print usage.
    Help,
}

/// Bounded sampling parameters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpikeOptions {
    /// Number of rows to collect.
    pub samples: u64,
    /// Delay between rows.
    pub interval_ms: u64,
}

impl Default for SpikeOptions {
    fn default() -> Self {
        Self {
            samples: 10,
            interval_ms: 1_000,
        }
    }
}

/// The command line did not match the closed grammar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    /// Unknown, repeated, missing, non-numeric, or out-of-range argument.
    InvalidArguments,
}

/// Parse only the documented command grammar; unknown input never changes behavior silently.
pub fn parse_args<I, S>(arguments: I) -> Result<Command, ParseError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut arguments = arguments.into_iter();
    let Some(command) = arguments.next() else {
        return Ok(Command::Status);
    };
    if command.as_ref() == "--help" || command.as_ref() == "help" {
        return if arguments.next().is_none() {
            Ok(Command::Help)
        } else {
            Err(ParseError::InvalidArguments)
        };
    }
    if command.as_ref() != "spike" {
        return Err(ParseError::InvalidArguments);
    }

    parse_spike_options(arguments).map(Command::Spike)
}

fn parse_spike_options<I, S>(mut arguments: I) -> Result<SpikeOptions, ParseError>
where
    I: Iterator<Item = S>,
    S: AsRef<str>,
{
    let mut options = SpikeOptions::default();
    let mut samples_seen = false;
    let mut interval_seen = false;
    let mut token_count = 1;
    loop {
        // `env::ArgsOs` and the concrete iterators used by the CLI expose an exact lower
        // size hint. Refuse known excess before materializing a sixth token. A custom
        // iterator may report zero and can only be detected by one bounded `next()`.
        if token_count == MAX_GRAMMAR_TOKENS && arguments.size_hint().0 > 0 {
            return Err(ParseError::InvalidArguments);
        }
        let Some(flag) = arguments.next() else {
            break;
        };
        token_count += 1;
        if token_count > MAX_GRAMMAR_TOKENS {
            return Err(ParseError::InvalidArguments);
        }

        let value = arguments.next().ok_or(ParseError::InvalidArguments)?;
        token_count += 1;
        if token_count > MAX_GRAMMAR_TOKENS {
            return Err(ParseError::InvalidArguments);
        }

        match flag.as_ref() {
            "--samples" if !samples_seen => {
                options.samples = bounded(value.as_ref(), 1, MAX_SAMPLES)?;
                samples_seen = true;
            }
            "--interval-ms" if !interval_seen => {
                options.interval_ms = bounded(value.as_ref(), MIN_INTERVAL_MS, MAX_INTERVAL_MS)?;
                interval_seen = true;
            }
            _ => return Err(ParseError::InvalidArguments),
        }
    }
    if !sampling_span_is_valid(options) {
        return Err(ParseError::InvalidArguments);
    }
    Ok(options)
}

fn sampling_span_is_valid(options: SpikeOptions) -> bool {
    options
        .samples
        .checked_sub(1)
        .and_then(|interval_count| interval_count.checked_mul(options.interval_ms))
        .is_some_and(|span_ms| span_ms <= MAX_SAMPLING_SPAN_MS)
}

fn bounded(value: &str, minimum: u64, maximum: u64) -> Result<u64, ParseError> {
    if value.len() > MAX_NUMERIC_TOKEN_BYTES {
        return Err(ParseError::InvalidArguments);
    }
    let value = value
        .parse::<u64>()
        .map_err(|_| ParseError::InvalidArguments)?;
    if (minimum..=maximum).contains(&value) {
        Ok(value)
    } else {
        Err(ParseError::InvalidArguments)
    }
}

/// Stable usage text with no host-specific data.
#[must_use]
pub const fn usage() -> &'static str {
    "usage: remote-energy-meter-reporter [help | --help | spike [--samples 1..36000] [--interval-ms 100..60000]]\nconstraint: (samples - 1) * interval-ms <= 36000000 (10 hours)"
}
