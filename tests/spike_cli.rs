use std::cell::Cell;

use remote_energy_meter_reporter::cli::{Command, ParseError, SpikeOptions, parse_args};

struct PoisonedTail<'a> {
    arguments: std::vec::IntoIter<String>,
    pulls: &'a Cell<usize>,
}

impl Iterator for PoisonedTail<'_> {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        self.pulls.set(self.pulls.get() + 1);
        self.arguments.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.arguments.size_hint()
    }
}

fn poisoned_after<'a>(arguments: &[&str], pulls: &'a Cell<usize>) -> PoisonedTail<'a> {
    PoisonedTail {
        arguments: arguments
            .iter()
            .map(|argument| (*argument).to_owned())
            .collect::<Vec<_>>()
            .into_iter(),
        pulls,
    }
}

#[test]
fn no_arguments_keeps_the_fail_closed_status_command() {
    assert_eq!(parse_args(Vec::<String>::new()), Ok(Command::Status));
}

#[test]
fn parses_bounded_spike_options() {
    assert_eq!(
        parse_args(["spike", "--samples", "10", "--interval-ms", "500"]),
        Ok(Command::Spike(SpikeOptions {
            samples: 10,
            interval_ms: 500,
        }))
    );
}

#[test]
fn accepts_exact_numeric_boundaries() {
    for (arguments, expected) in [
        (
            ["spike", "--samples", "1"],
            SpikeOptions {
                samples: 1,
                interval_ms: 1_000,
            },
        ),
        (
            ["spike", "--samples", "36000"],
            SpikeOptions {
                samples: 36_000,
                interval_ms: 1_000,
            },
        ),
        (
            ["spike", "--interval-ms", "100"],
            SpikeOptions {
                samples: 10,
                interval_ms: 100,
            },
        ),
        (
            ["spike", "--interval-ms", "60000"],
            SpikeOptions {
                samples: 10,
                interval_ms: 60_000,
            },
        ),
    ] {
        assert_eq!(parse_args(arguments), Ok(Command::Spike(expected)));
    }
}

#[test]
fn enforces_the_ten_hour_total_sampling_span() {
    assert_eq!(
        parse_args(["spike", "--samples", "601", "--interval-ms", "60000"]),
        Ok(Command::Spike(SpikeOptions {
            samples: 601,
            interval_ms: 60_000,
        }))
    );

    for arguments in [
        ["spike", "--samples", "602", "--interval-ms", "60000"],
        ["spike", "--interval-ms", "60000", "--samples", "36000"],
    ] {
        assert_eq!(
            parse_args(arguments),
            Err(ParseError::InvalidArguments),
            "sampling span limit accepted {arguments:?}"
        );
    }
}

#[test]
fn defaults_are_deliberately_short_and_low_overhead() {
    assert_eq!(
        parse_args(["spike"]),
        Ok(Command::Spike(SpikeOptions {
            samples: 10,
            interval_ms: 1_000,
        }))
    );
}

#[test]
fn rejects_unknown_duplicate_and_missing_arguments() {
    for arguments in [
        vec!["unknown"],
        vec!["spike", "--samples"],
        vec!["spike", "--samples", "1", "--samples", "2"],
        vec!["spike", "--other", "1"],
    ] {
        let result = parse_args(arguments.iter().copied());
        assert!(
            matches!(result, Err(ParseError::InvalidArguments)),
            "{arguments:?}: {result:?}"
        );
    }
}

#[test]
fn rejects_each_numeric_validation_failure() {
    for arguments in [
        ["spike", "--samples", "not-a-number"],
        ["spike", "--samples", "0"],
        ["spike", "--samples", "36001"],
        ["spike", "--interval-ms", "not-a-number"],
        ["spike", "--interval-ms", "99"],
        ["spike", "--interval-ms", "60001"],
    ] {
        let result = parse_args(arguments);
        assert_eq!(
            result,
            Err(ParseError::InvalidArguments),
            "numeric validation accepted {arguments:?}"
        );
    }
}

#[test]
fn rejects_a_token_beyond_the_maximum_grammar_without_reading_its_tail() {
    let pulls = Cell::new(0);
    let arguments = poisoned_after(
        &[
            "spike",
            "--samples",
            "1",
            "--interval-ms",
            "100",
            "unexpected",
        ],
        &pulls,
    );

    assert_eq!(parse_args(arguments), Err(ParseError::InvalidArguments));
    assert_eq!(
        pulls.get(),
        5,
        "parser read from the poisoned iterator tail"
    );
}

#[test]
fn rejects_an_overlong_number_without_reading_its_tail() {
    let pulls = Cell::new(0);
    let overlong_number = "9".repeat(1_024);
    let arguments = PoisonedTail {
        arguments: vec!["spike".to_owned(), "--samples".to_owned(), overlong_number].into_iter(),
        pulls: &pulls,
    };

    assert_eq!(parse_args(arguments), Err(ParseError::InvalidArguments));
    assert_eq!(
        pulls.get(),
        3,
        "parser read from the poisoned iterator tail"
    );
}
