# Apple-silicon candidate telemetry — code-only result

## Status

**Go for implementation on the tested Apple-silicon laptop, with explicit limits.** One bracketed five-minute idle,
CPU-load, and GPU-load run in each of AC and battery mode passes the code-only direct consistency, per-counter
freshness, accumulator, workload-response, CPU, and memory criteria. Both physical mode transitions failed closed
while the public and private sources disagreed, then recovered after the next source-owned update.

The production `PowerSource` remains fail-closed. This spike does not implement production source-loss handling,
long-running freshness state, signed unavailable reports, or transport. Those behaviors remain release gates for the
production provider.

Any accepted output is **Apple-reported system power** from the undocumented
`AppleSmartBattery.PowerTelemetryData` property. Code-only qualification cannot establish physical accuracy. The
source is not externally calibrated or billing-grade and must not be used for billing, settlement, or safety-critical
decisions. Physical power meters are outside this project's scope and are not required.

Raw captures remain in the gitignored `spike-data/` directory. This report publishes reviewed aggregate results only,
uses a neutral hardware description, and contains no machine identity or local setup details.

## Candidate selection and direct checks

The spike reads selected integer fields through public IOKit registry functions. Apple does not document the property
or its field names.

- AC selects `SystemPowerIn / 1000` watts so the value includes battery charging.
- Battery selects `SystemLoad / 1000` watts because no external input is present.
- Every selected value must be finite, greater than zero, and no more than 100 kW.
- All direct comparisons use milliwatts and the exact rule
  `abs(a - b) <= max(1 mW, 0.01 * max(abs(a), abs(b)))`.
- `SystemPowerIn` must match `SystemLoad + BatteryPower` in both modes.
- On AC, `SystemPowerIn` must also match the milliwatt conversion of
  `SystemVoltageIn × SystemCurrentIn`.
- On battery, `BatteryPower` must be negative and its magnitude must match `SystemLoad`.

The CSV emits the universal identity as `system_power_balance_relative_error` and the mode-specific check as
`mode_crosscheck_relative_error`. Keeping the residuals separate prevents a passing battery magnitude check from
hiding a failing three-field identity.

## Acquisition and public mode classification

Each candidate is acquired in this order:

1. Read the leading public IOPowerSources state.
2. Read the private `PowerTelemetryData` candidate.
3. Read the trailing public IOPowerSources state.

Both public reads must report the same classifiable mode. The monotonic boundaries must be nondecreasing and the whole
bracket must complete in no more than one second. The six completed runs had matching mode on both sides of every
sample. The maximum observed bracket was 11 ms.

The public reader uses `Type` and `Is Present` only to select exactly one present `InternalBattery`. No matching
battery or multiple matching batteries makes the bracket fail closed. These selection-only fields are not emitted to
CSV. The direct public values retained for validation and CSV output are mode, charging state, and optional documented
battery voltage/current; the CSV also includes the signed terminal and discharge power derived from those values. The
tested platform omitted `Voltage` and reported `Current = 0` in battery mode. The collector preserved those values as
missing/zero and did not infer replacements. They are diagnostic only and are not an admission gate.

## Freshness and accumulator criteria

The mandatory mode-specific tuples are:

| Mode | Accumulated value | Counter | Direct value |
| --- | --- | --- | --- |
| AC | `AccumulatedSystemPowerIn` | `SystemPowerInAccumulatorCount` | `SystemPowerIn` |
| Battery | `AccumulatedSystemLoad` | `SystemLoadAccumulatorCount` | `SystemLoad` |
| Battery | `AccumulatedBatteryDischarge` | `BatteryDischargeAccumulatorCount` | `BatteryPower` |

For each mandatory counter, the first observation starts monotonic freshness age. A positive count delta resets that
age. A zero delta is valid only below 90 seconds; exactly 90 seconds is stale. A decrease or wrap fails immediately,
and one counter cannot refresh another.

A positive count delta closes a source-owned interval. Accumulator delta divided by count delta must be finite, have
the required sign, remain below the hard ceiling, and follow workload direction. Matching battery load/discharge
interval means must be signed inverses under the 1% rule. Direct process reads are not synchronized to Apple's hidden
accumulator boundaries, so this qualification does not assign repeated polled values to those intervals or claim a
pointwise accumulator/direct accuracy comparison.

## Method

A release build sampled once per second for five minutes under each condition:

- Idle: ordinary foreground use, no intentional load.
- CPU: all logical CPUs kept busy.
- GPU: sustained Metal compute workload.

Reporter CPU is process user plus system CPU time divided by elapsed time, expressed as one-core percentage. Memory is
maximum resident set size. No physical-accuracy comparison was performed or is claimed. `powermetrics` was not treated
as system-power ground truth.

## Bracketed AC results

| Condition | Samples / elapsed | Median | Mean | Range | Max system balance | Max mode cross-check | Max freshness age | Max bracket | Reporter CPU | Max RSS |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Idle AC | 300 / 301.1 s | 7.996 W | 8.369 W | 7.462–10.504 W | 0.000% | 0.1424% | 60.4 s | 2 ms | 0.0465% | 6.27 MiB |
| CPU AC | 300 / 301.9 s | 34.718 W | 34.677 W | 7.975–46.999 W | 0.000% | 0.1355% | 60.8 s | 8 ms | 0.0232% | 6.25 MiB |
| GPU AC | 300 / 300.7 s | 58.266 W | 57.032 W | 45.408–58.945 W | 0.000% | 0.0320% | 60.4 s | 1 ms | 0.0200% | 6.22 MiB |

Each run contained five positive `SystemPowerInAccumulatorCount` updates. Accumulator-derived interval values were
positive and bounded:

- Idle: 8.165–10.827 W.
- CPU: 22.259–46.529 W.
- GPU: 42.087–58.881 W.

CPU and GPU medians exceed the idle median. All selected values, direct identities, brackets, freshness ages, and
resource measurements pass.

## Bracketed battery results

| Condition | Samples / elapsed | Median | Mean | Range | Max system balance | Max mode cross-check | Max freshness age | Max bracket | Reporter CPU | Max RSS |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Idle battery | 300 / 300.7 s | 7.162 W | 6.291 W | 2.655–9.078 W | 0.000% | 0.000% | 60.3 s | 2 ms | 0.0366% | 6.23 MiB |
| CPU battery | 300 / 302.8 s | 34.751 W | 32.507 W | 2.655–38.056 W | 0.000% | 0.000% | 60.7 s | 11 ms | 0.0231% | 6.27 MiB |
| GPU battery | 300 / 300.4 s | 63.803 W | 63.811 W | 16.366–77.706 W | 0.000% | 0.000% | 49.2 s | 1 ms | 0.0200% | 6.23 MiB |

The idle and CPU runs each contained five matching load/discharge accumulator updates; GPU contained eight. Positive
load and negative discharge interval values were exact signed inverses in every observed interval:

- Idle magnitude: 3.282–8.759 W.
- CPU magnitude: 11.888–36.528 W.
- GPU magnitude: 52.501–75.800 W.

CPU and GPU medians exceed the idle median. All selected values, direct identities, brackets, per-counter freshness
ages, accumulator signs/inverses, and resource measurements pass.

## Transition results

Immediately after AC was disconnected, both public reads reported battery mode while the private source still exposed
an invalid prior-mode candidate. The collector rejected the sample with exit status 3 and emitted no row. It accepted
battery mode after the next source-owned update, with zero AC input fields and negative `BatteryPower` equal to
`SystemLoad`.

Immediately after AC was reconnected, both public reads reported AC while the private source still exposed battery-mode
input fields. The collector again rejected the sample with exit status 3 and emitted no row. It accepted AC after the
next source-owned update, with positive input voltage/current and both direct checks passing.

This demonstrates fail-closed physical transitions without cross-mode fallback or stale candidate reuse. The future
runtime must convert these failures into immediate signed `WHOLE_SYSTEM_UNAVAILABLE`, clear prior-mode freshness and
accumulator baselines, and emit a new available value only after a complete new-mode bracket passes.

## Result and remaining release gates

The tested Apple-silicon laptop passes the code-only spike criteria for both AC and battery. This permits proceeding to
the production provider and protocol tasks; it does not make the foreground spike a production `PowerSource`.

Before reporter release:

1. Implement the mode-specific selection, direct checks, per-counter 90-second freshness, accumulator sign/bounds,
   transition reset, and source-loss handling in the production runtime.
2. Verify immediate signed `WHOLE_SYSTEM_UNAVAILABLE` behavior for source loss, stale data, unclassifiable/changing
   brackets, and physical mode transitions.
3. Re-run the matrix on at least one additional Apple-silicon laptop before describing support as general rather than
   limited to tested hardware.
4. Probe Intel separately. Apple-silicon evidence does not qualify Intel.

Until those production gates pass, `cargo run` continues to return `WHOLE_SYSTEM_UNAVAILABLE`; only the explicit
foreground `spike` command reads candidate values.
