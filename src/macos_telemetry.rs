//! macOS IOKit reader for the experimental Apple-silicon laptop telemetry spike.
//!
//! `PowerTelemetryData` and its keys are undocumented by Apple. This module deliberately returns
//! [`RawPowerTelemetry`](crate::spike::RawPowerTelemetry), not a qualified
//! [`PowerSource`](crate::power::PowerSource). Code-only qualification can establish source
//! behavior and internal consistency, but not externally calibrated or billing-grade accuracy.

use std::error::Error;
use std::ffi::CString;
use std::fmt::{self, Display, Formatter};

use core_foundation::array::{CFArray, CFIndex};
use core_foundation::base::{CFType, CFTypeRef, TCFType, kCFAllocatorDefault};
use core_foundation::boolean::CFBoolean;
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::{CFNumber, CFNumberIsFloatType};
use core_foundation::string::CFString;
use io_kit_sys::ps::power_sources::{
    IOPSCopyPowerSourcesInfo, IOPSCopyPowerSourcesList, IOPSGetPowerSourceDescription,
    IOPSGetProvidingPowerSourceType,
};
use io_kit_sys::{
    IOObjectRelease, IORegistryEntryCreateCFProperty, IOServiceGetMatchingService,
    IOServiceMatching, kIOMasterPortDefault,
};

use crate::spike::{
    PlatformPowerMode, RawBatteryReference, RawPowerTelemetry, TelemetryAcquisition,
};

const SERVICE_CLASS: &str = "AppleSmartBattery";
const TELEMETRY_PROPERTY: &str = "PowerTelemetryData";
/// IOPowerSources normally exposes only the internal battery and a small number of UPS devices.
/// Bound the untrusted Core Foundation list before allocating or reading any entries.
const MAX_POWER_SOURCES: usize = 16;

/// Owns one retained IOKit service handle for the duration of a spike run.
pub struct AppleBatteryTelemetryReader {
    service: u32,
}

impl AppleBatteryTelemetryReader {
    /// Find the AppleSmartBattery IOService.
    pub fn open() -> Result<Self, MacTelemetryReadError> {
        let class = CString::new(SERVICE_CLASS).expect("static service class carries no NUL");
        // SAFETY: class is a NUL-terminated static string. IOServiceMatching returns a Create-rule
        // dictionary consumed by IOServiceGetMatchingService. The master port constant is provided
        // by IOKit, and a non-zero returned service is released in Drop.
        let service = unsafe {
            let matching = IOServiceMatching(class.as_ptr());
            if matching.is_null() {
                return Err(MacTelemetryReadError::MatchingDictionaryUnavailable);
            }
            IOServiceGetMatchingService(kIOMasterPortDefault, matching)
        };
        if service == 0 {
            return Err(MacTelemetryReadError::AppleSmartBatteryUnavailable);
        }
        Ok(Self { service })
    }

    /// Read a public, allowlisted internal-battery voltage/current reference.
    ///
    /// The snapshot and list are both Create-rule values. Power-source descriptions are Get-rule
    /// values tied to the snapshot; wrapping them under the Get rule retains only the selected
    /// dictionaries and does not enumerate or serialize identity-bearing fields.
    pub fn read_public_battery_reference(
        &mut self,
    ) -> Result<RawBatteryReference, MacTelemetryReadError> {
        // SAFETY: IOPSCopyPowerSourcesInfo takes no arguments and returns a Create-rule CF object.
        let snapshot_ref = unsafe { IOPSCopyPowerSourcesInfo() };
        if snapshot_ref.is_null() {
            return Err(MacTelemetryReadError::PowerSourcesSnapshotUnavailable);
        }
        // SAFETY: the non-null object was returned under the Create rule.
        let snapshot = unsafe { CFType::wrap_under_create_rule(snapshot_ref) };

        // SAFETY: snapshot is the live object returned by IOPSCopyPowerSourcesInfo. The returned
        // string is a borrowed Get-rule value retained by the wrapper below.
        let mode_ref = unsafe { IOPSGetProvidingPowerSourceType(snapshot.as_CFTypeRef()) };
        if mode_ref.is_null() {
            return Err(MacTelemetryReadError::ProvidingPowerSourceUnavailable);
        }
        // SAFETY: mode_ref is a non-null Get-rule CFStringRef tied to the live snapshot.
        let mode_string = unsafe { CFString::wrap_under_get_rule(mode_ref) };
        let mode = parse_platform_power_mode(&mode_string)?;

        // SAFETY: snapshot is the required live input. A non-null result follows the Create rule.
        let list_ref = unsafe { IOPSCopyPowerSourcesList(snapshot.as_CFTypeRef()) };
        if list_ref.is_null() {
            return Err(MacTelemetryReadError::PowerSourcesListUnavailable);
        }
        // SAFETY: list_ref is a non-null Create-rule CFArrayRef.
        let list: CFArray<CFTypeRef> = unsafe { CFArray::wrap_under_create_rule(list_ref) };
        let source_count = checked_power_source_count(list.len())?;
        let mut descriptions = Vec::with_capacity(source_count);
        for source in &list {
            // SAFETY: source is one of the opaque handles from the live list and snapshot. The
            // description is a borrowed Get-rule object tied to snapshot.
            let description_ref = unsafe {
                IOPSGetPowerSourceDescription(snapshot.as_CFTypeRef(), *source as CFTypeRef)
            };
            if description_ref.is_null() {
                return Err(MacTelemetryReadError::PowerSourceDescriptionUnavailable);
            }
            // SAFETY: description_ref is a non-null Get-rule dictionary tied to live snapshot.
            descriptions.push(unsafe { CFDictionary::wrap_under_get_rule(description_ref) });
        }

        battery_reference_from_descriptions(mode, &descriptions)
    }

    /// Read the selected raw fields without collecting machine identity or unrelated properties.
    pub fn read_raw(&mut self) -> Result<RawPowerTelemetry, MacTelemetryReadError> {
        let property_name = CFString::new(TELEMETRY_PROPERTY);
        // SAFETY: self.service is a live retained IORegistry entry; property_name and allocator are
        // valid CoreFoundation references. A non-null Create-rule result is immediately wrapped.
        let raw_property = unsafe {
            IORegistryEntryCreateCFProperty(
                self.service,
                property_name.as_concrete_TypeRef(),
                kCFAllocatorDefault,
                0,
            )
        };
        if raw_property.is_null() {
            return Err(MacTelemetryReadError::TelemetryPropertyUnavailable);
        }
        // SAFETY: IORegistryEntryCreateCFProperty returned this non-null object under the Create rule.
        let property = unsafe { CFType::wrap_under_create_rule(raw_property) };
        let dictionary = property
            .downcast_into::<CFDictionary>()
            .ok_or(MacTelemetryReadError::TelemetryPropertyNotDictionary)?;

        Ok(RawPowerTelemetry {
            system_load_mw: integer_field(&dictionary, "SystemLoad")?,
            system_power_in_mw: integer_field(&dictionary, "SystemPowerIn")?,
            system_voltage_mv: integer_field(&dictionary, "SystemVoltageIn")?,
            system_current_ma: integer_field(&dictionary, "SystemCurrentIn")?,
            battery_power_mw: integer_field(&dictionary, "BatteryPower")?,
            adapter_efficiency_loss_mw: integer_field(&dictionary, "AdapterEfficiencyLoss")?,
            system_energy_consumed_raw: integer_field(&dictionary, "SystemEnergyConsumed")?,
            wall_energy_estimate_raw: integer_field(&dictionary, "WallEnergyEstimate")?,
            system_load_count: integer_field(&dictionary, "SystemLoadAccumulatorCount")?,
            accumulated_system_load_raw: integer_field(&dictionary, "AccumulatedSystemLoad")?,
            system_power_in_count: integer_field(&dictionary, "SystemPowerInAccumulatorCount")?,
            accumulated_system_power_in_raw: integer_field(
                &dictionary,
                "AccumulatedSystemPowerIn",
            )?,
            battery_power_count: integer_field(&dictionary, "BatteryPowerAccumulatorCount")?,
            accumulated_battery_power_raw: integer_field(&dictionary, "AccumulatedBatteryPower")?,
            battery_discharge_count: integer_field(
                &dictionary,
                "BatteryDischargeAccumulatorCount",
            )?,
            accumulated_battery_discharge_raw: integer_field(
                &dictionary,
                "AccumulatedBatteryDischarge",
            )?,
            accumulated_system_energy_consumed_raw: integer_field(
                &dictionary,
                "AccumulatedSystemEnergyConsumed",
            )?,
            accumulated_wall_energy_estimate_raw: integer_field(
                &dictionary,
                "AccumulatedWallEnergyEstimate",
            )?,
        })
    }
}

impl TelemetryAcquisition for AppleBatteryTelemetryReader {
    type Error = MacTelemetryReadError;

    fn read_public_battery_reference(&mut self) -> Result<RawBatteryReference, Self::Error> {
        Self::read_public_battery_reference(self)
    }

    fn read_raw(&mut self) -> Result<RawPowerTelemetry, Self::Error> {
        Self::read_raw(self)
    }
}

impl Drop for AppleBatteryTelemetryReader {
    fn drop(&mut self) {
        // SAFETY: open() accepts only a non-zero service returned under IOKit's ownership rule and
        // this Drop runs exactly once for that handle.
        let _ = unsafe { IOObjectRelease(self.service) };
    }
}

/// Read one integer-only field from an untyped Core Foundation dictionary.
pub(crate) fn integer_field(
    dictionary: &CFDictionary,
    field: &'static str,
) -> Result<i64, MacTelemetryReadError> {
    let key = CFString::new(field);
    let key_ref = key.as_CFTypeRef();
    let value = dictionary
        .find(key_ref)
        .ok_or(MacTelemetryReadError::MissingField(field))?;
    let value_ref = *value as CFTypeRef;
    if value_ref.is_null() {
        return Err(MacTelemetryReadError::MissingField(field));
    }
    // SAFETY: CFDictionary's get-rule value remains alive for dictionary's lifetime. The wrapper
    // retains it, so the downcast number remains valid independently of the ItemRef.
    let value = unsafe { CFType::wrap_under_get_rule(value_ref) };
    let number = value
        .downcast::<CFNumber>()
        .ok_or(MacTelemetryReadError::FieldNotInteger(field))?;
    // SAFETY: number is a live CFNumber retained by the downcast wrapper.
    if unsafe { CFNumberIsFloatType(number.as_concrete_TypeRef()) } != 0 {
        return Err(MacTelemetryReadError::FieldNotInteger(field));
    }
    number
        .to_i64()
        .ok_or(MacTelemetryReadError::FieldNotInteger(field))
}

fn checked_power_source_count(count: CFIndex) -> Result<usize, MacTelemetryReadError> {
    let count =
        usize::try_from(count).map_err(|_| MacTelemetryReadError::InvalidPowerSourcesListLength)?;
    if count > MAX_POWER_SOURCES {
        return Err(MacTelemetryReadError::InvalidPowerSourcesListLength);
    }
    Ok(count)
}

fn optional_integer_field(
    dictionary: &CFDictionary,
    field: &'static str,
) -> Result<Option<i64>, MacTelemetryReadError> {
    let key = CFString::new(field);
    if dictionary.find(key.as_CFTypeRef()).is_none() {
        return Ok(None);
    }
    integer_field(dictionary, field).map(Some)
}

fn string_field(
    dictionary: &CFDictionary,
    field: &'static str,
) -> Result<CFString, MacTelemetryReadError> {
    let key = CFString::new(field);
    let value = dictionary
        .find(key.as_CFTypeRef())
        .ok_or(MacTelemetryReadError::MissingField(field))?;
    let value_ref = *value as CFTypeRef;
    if value_ref.is_null() {
        return Err(MacTelemetryReadError::MissingField(field));
    }
    // SAFETY: the dictionary owns the Get-rule value. This wrapper retains it for the return value.
    let value = unsafe { CFType::wrap_under_get_rule(value_ref) };
    value
        .downcast_into::<CFString>()
        .ok_or(MacTelemetryReadError::FieldNotString(field))
}

fn boolean_field(
    dictionary: &CFDictionary,
    field: &'static str,
) -> Result<bool, MacTelemetryReadError> {
    let key = CFString::new(field);
    let value = dictionary
        .find(key.as_CFTypeRef())
        .ok_or(MacTelemetryReadError::MissingField(field))?;
    let value_ref = *value as CFTypeRef;
    if value_ref.is_null() {
        return Err(MacTelemetryReadError::MissingField(field));
    }
    // SAFETY: the dictionary owns the Get-rule value. The wrapper retains it for the downcast.
    let value = unsafe { CFType::wrap_under_get_rule(value_ref) };
    let boolean = value
        .downcast_into::<CFBoolean>()
        .ok_or(MacTelemetryReadError::FieldNotBoolean(field))?;
    Ok(bool::from(boolean))
}

fn parse_platform_power_mode(
    source: &CFString,
) -> Result<PlatformPowerMode, MacTelemetryReadError> {
    match source.to_string().as_str() {
        "AC Power" => Ok(PlatformPowerMode::Ac),
        "Battery Power" => Ok(PlatformPowerMode::Battery),
        _ => Err(MacTelemetryReadError::UnsupportedProvidingPowerSource),
    }
}

fn battery_reference_from_descriptions(
    mode: PlatformPowerMode,
    descriptions: &[CFDictionary],
) -> Result<RawBatteryReference, MacTelemetryReadError> {
    let mut selected = None;
    for description in descriptions {
        if string_field(description, "Type")? != "InternalBattery" {
            continue;
        }
        if !boolean_field(description, "Is Present")? {
            continue;
        }
        if selected.is_some() {
            return Err(MacTelemetryReadError::AmbiguousPresentInternalBattery);
        }
        selected = Some(RawBatteryReference {
            mode,
            is_charging: boolean_field(description, "Is Charging")?,
            voltage_mv: optional_integer_field(description, "Voltage")?,
            current_ma: optional_integer_field(description, "Current")?,
        });
    }
    selected.ok_or(MacTelemetryReadError::PresentInternalBatteryUnavailable)
}

/// Why the experimental IOKit snapshot could not be read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacTelemetryReadError {
    /// IOKit could not allocate a matching dictionary.
    MatchingDictionaryUnavailable,
    /// This machine has no AppleSmartBattery service (for example a desktop Mac).
    AppleSmartBatteryUnavailable,
    /// The public IOPowerSources snapshot could not be created.
    PowerSourcesSnapshotUnavailable,
    /// The public IOPowerSources list could not be created.
    PowerSourcesListUnavailable,
    /// The public IOPowerSources list length was negative or exceeded the bounded maximum.
    InvalidPowerSourcesListLength,
    /// A listed public power-source description could not be read.
    PowerSourceDescriptionUnavailable,
    /// The public API did not report the system's providing power source.
    ProvidingPowerSourceUnavailable,
    /// The providing source is neither AC nor the internal battery.
    UnsupportedProvidingPowerSource,
    /// No present internal battery was found in the public snapshot.
    PresentInternalBatteryUnavailable,
    /// More than one present internal battery was found.
    AmbiguousPresentInternalBattery,
    /// AppleSmartBattery exposes no PowerTelemetryData property on this OS/model.
    TelemetryPropertyUnavailable,
    /// The property exists but is not a dictionary.
    TelemetryPropertyNotDictionary,
    /// One selected field is absent.
    MissingField(&'static str),
    /// One selected field is not an integer.
    FieldNotInteger(&'static str),
    /// One selected field is not a string.
    FieldNotString(&'static str),
    /// One selected field is not a Boolean.
    FieldNotBoolean(&'static str),
}

impl Display for MacTelemetryReadError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::MatchingDictionaryUnavailable => {
                formatter.write_str("IOKit matching dictionary unavailable")
            }
            Self::AppleSmartBatteryUnavailable => {
                formatter.write_str("AppleSmartBattery unavailable")
            }
            Self::PowerSourcesSnapshotUnavailable => {
                formatter.write_str("public power-source snapshot unavailable")
            }
            Self::PowerSourcesListUnavailable => {
                formatter.write_str("public power-source list unavailable")
            }
            Self::InvalidPowerSourcesListLength => {
                formatter.write_str("public power-source list length is invalid")
            }
            Self::PowerSourceDescriptionUnavailable => {
                formatter.write_str("public power-source description unavailable")
            }
            Self::ProvidingPowerSourceUnavailable => {
                formatter.write_str("providing power source unavailable")
            }
            Self::UnsupportedProvidingPowerSource => {
                formatter.write_str("providing power source is unsupported")
            }
            Self::PresentInternalBatteryUnavailable => {
                formatter.write_str("present internal battery unavailable")
            }
            Self::AmbiguousPresentInternalBattery => {
                formatter.write_str("multiple present internal batteries")
            }
            Self::TelemetryPropertyUnavailable => {
                formatter.write_str("PowerTelemetryData unavailable")
            }
            Self::TelemetryPropertyNotDictionary => {
                formatter.write_str("PowerTelemetryData is not a dictionary")
            }
            Self::MissingField(field) => {
                write!(formatter, "required telemetry field is missing: {field}")
            }
            Self::FieldNotInteger(field) => {
                write!(formatter, "telemetry field is not an integer: {field}")
            }
            Self::FieldNotString(field) => {
                write!(formatter, "telemetry field is not a string: {field}")
            }
            Self::FieldNotBoolean(field) => {
                write!(formatter, "telemetry field is not a Boolean: {field}")
            }
        }
    }
}

impl Error for MacTelemetryReadError {}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use core_foundation::boolean::CFBoolean;

    use super::*;

    const FIELD: &str = "TestField";

    fn dictionary_with(value: CFType) -> CFDictionary {
        CFDictionary::from_CFType_pairs(&[(CFString::new(FIELD), value)]).into_untyped()
    }

    fn power_source_description(
        source_type: CFType,
        present: CFType,
        charging: CFType,
        voltage: CFType,
        current: CFType,
    ) -> CFDictionary {
        CFDictionary::from_CFType_pairs(&[
            (CFString::new("Type"), source_type),
            (CFString::new("Is Present"), present),
            (CFString::new("Is Charging"), charging),
            (CFString::new("Voltage"), voltage),
            (CFString::new("Current"), current),
        ])
        .into_untyped()
    }

    fn battery_description(present: bool) -> CFDictionary {
        power_source_description(
            CFString::new("InternalBattery").into_CFType(),
            CFBoolean::from(present).into_CFType(),
            CFBoolean::from(false).into_CFType(),
            CFNumber::from(12_000_i64).into_CFType(),
            CFNumber::from(-2_500_i64).into_CFType(),
        )
    }

    fn battery_description_with_optional_terminal(
        voltage_mv: Option<i64>,
        current_ma: Option<i64>,
    ) -> CFDictionary {
        let mut pairs = vec![
            (
                CFString::new("Type"),
                CFString::new("InternalBattery").into_CFType(),
            ),
            (
                CFString::new("Is Present"),
                CFBoolean::from(true).into_CFType(),
            ),
            (
                CFString::new("Is Charging"),
                CFBoolean::from(false).into_CFType(),
            ),
        ];
        if let Some(voltage_mv) = voltage_mv {
            pairs.push((
                CFString::new("Voltage"),
                CFNumber::from(voltage_mv).into_CFType(),
            ));
        }
        if let Some(current_ma) = current_ma {
            pairs.push((
                CFString::new("Current"),
                CFNumber::from(current_ma).into_CFType(),
            ));
        }
        CFDictionary::from_CFType_pairs(&pairs).into_untyped()
    }

    #[test]
    fn power_source_count_rejects_negative_and_oversized_lists() {
        assert_eq!(checked_power_source_count(0), Ok(0));
        assert_eq!(
            checked_power_source_count(MAX_POWER_SOURCES as CFIndex),
            Ok(MAX_POWER_SOURCES)
        );
        for count in [-1, MAX_POWER_SOURCES as CFIndex + 1] {
            assert_eq!(
                checked_power_source_count(count),
                Err(MacTelemetryReadError::InvalidPowerSourcesListLength)
            );
        }
    }

    #[test]
    fn integer_field_accepts_an_integer_cfnumber() {
        let dictionary = dictionary_with(CFNumber::from(42_i64).into_CFType());

        assert_eq!(integer_field(&dictionary, FIELD), Ok(42));
    }

    #[test]
    fn integer_field_rejects_integral_and_fractional_float_cfnumbers() {
        for value in [42.0_f64, 42.5_f64] {
            let dictionary = dictionary_with(CFNumber::from(value).into_CFType());

            assert_eq!(
                integer_field(&dictionary, FIELD),
                Err(MacTelemetryReadError::FieldNotInteger(FIELD))
            );
        }
    }

    #[test]
    fn integer_field_rejects_a_missing_value() {
        let dictionary = CFDictionary::<CFString, CFType>::from_CFType_pairs(&[]).into_untyped();

        assert_eq!(
            integer_field(&dictionary, FIELD),
            Err(MacTelemetryReadError::MissingField(FIELD))
        );
    }

    #[test]
    fn integer_field_rejects_a_non_number_value() {
        let dictionary = dictionary_with(CFString::new("not a number").into_CFType());

        assert_eq!(
            integer_field(&dictionary, FIELD),
            Err(MacTelemetryReadError::FieldNotInteger(FIELD))
        );
    }

    #[test]
    fn public_reference_selects_one_present_internal_battery_and_ignores_ups() {
        let ups = power_source_description(
            CFString::new("UPS").into_CFType(),
            CFBoolean::from(true).into_CFType(),
            CFBoolean::from(false).into_CFType(),
            CFNumber::from(24_000_i64).into_CFType(),
            CFNumber::from(1_000_i64).into_CFType(),
        );
        let battery = battery_description(true);

        assert_eq!(
            battery_reference_from_descriptions(PlatformPowerMode::Battery, &[ups, battery],),
            Ok(RawBatteryReference {
                mode: PlatformPowerMode::Battery,
                is_charging: false,
                voltage_mv: Some(12_000),
                current_ma: Some(-2_500),
            })
        );
    }

    #[test]
    fn public_reference_preserves_omitted_terminal_fields() {
        for (voltage_mv, current_ma) in [(None, Some(-2_500)), (Some(12_000), None), (None, None)] {
            let description = battery_description_with_optional_terminal(voltage_mv, current_ma);

            assert_eq!(
                battery_reference_from_descriptions(PlatformPowerMode::Battery, &[description],),
                Ok(RawBatteryReference {
                    mode: PlatformPowerMode::Battery,
                    is_charging: false,
                    voltage_mv,
                    current_ma,
                })
            );
        }
    }

    #[test]
    fn public_reference_rejects_missing_or_ambiguous_present_batteries() {
        assert_eq!(
            battery_reference_from_descriptions(
                PlatformPowerMode::Battery,
                &[battery_description(false)],
            ),
            Err(MacTelemetryReadError::PresentInternalBatteryUnavailable)
        );
        assert_eq!(
            battery_reference_from_descriptions(
                PlatformPowerMode::Battery,
                &[battery_description(true), battery_description(true)],
            ),
            Err(MacTelemetryReadError::AmbiguousPresentInternalBattery)
        );
    }

    #[test]
    fn public_reference_requires_declared_field_types() {
        let wrong_boolean = power_source_description(
            CFString::new("InternalBattery").into_CFType(),
            CFNumber::from(1_i64).into_CFType(),
            CFBoolean::from(false).into_CFType(),
            CFNumber::from(12_000_i64).into_CFType(),
            CFNumber::from(-2_500_i64).into_CFType(),
        );
        assert_eq!(
            battery_reference_from_descriptions(PlatformPowerMode::Battery, &[wrong_boolean]),
            Err(MacTelemetryReadError::FieldNotBoolean("Is Present"))
        );

        let wrong_string = power_source_description(
            CFNumber::from(1_i64).into_CFType(),
            CFBoolean::from(true).into_CFType(),
            CFBoolean::from(false).into_CFType(),
            CFNumber::from(12_000_i64).into_CFType(),
            CFNumber::from(-2_500_i64).into_CFType(),
        );
        assert_eq!(
            battery_reference_from_descriptions(PlatformPowerMode::Battery, &[wrong_string]),
            Err(MacTelemetryReadError::FieldNotString("Type"))
        );
    }

    #[test]
    fn public_reference_requires_integer_voltage_and_current() {
        for field in ["Voltage", "Current"] {
            let (voltage, current) = if field == "Voltage" {
                (
                    CFNumber::from(12_000.0_f64).into_CFType(),
                    CFNumber::from(-2_500_i64).into_CFType(),
                )
            } else {
                (
                    CFNumber::from(12_000_i64).into_CFType(),
                    CFNumber::from(-2_500.0_f64).into_CFType(),
                )
            };
            let description = power_source_description(
                CFString::new("InternalBattery").into_CFType(),
                CFBoolean::from(true).into_CFType(),
                CFBoolean::from(false).into_CFType(),
                voltage,
                current,
            );
            assert_eq!(
                battery_reference_from_descriptions(PlatformPowerMode::Battery, &[description],),
                Err(MacTelemetryReadError::FieldNotInteger(field))
            );
        }
    }

    #[test]
    fn public_power_mode_accepts_only_ac_or_battery() {
        assert_eq!(
            parse_platform_power_mode(&CFString::new("AC Power")),
            Ok(PlatformPowerMode::Ac)
        );
        assert_eq!(
            parse_platform_power_mode(&CFString::new("Battery Power")),
            Ok(PlatformPowerMode::Battery)
        );
        assert_eq!(
            parse_platform_power_mode(&CFString::new("UPS Power")),
            Err(MacTelemetryReadError::UnsupportedProvidingPowerSource)
        );
    }
}
