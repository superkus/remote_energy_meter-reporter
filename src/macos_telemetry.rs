//! macOS IOKit reader for the experimental Apple-silicon laptop telemetry spike.
//!
//! `PowerTelemetryData` and its keys are undocumented by Apple. This module deliberately returns
//! [`RawPowerTelemetry`](crate::spike::RawPowerTelemetry), not a qualified
//! [`PowerSource`](crate::power::PowerSource). External wall-meter qualification is required before
//! any value can cross the reporting protocol.

use std::error::Error;
use std::ffi::CString;
use std::fmt::{self, Display, Formatter};

use core_foundation::base::{CFType, CFTypeRef, TCFType, kCFAllocatorDefault};
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::{CFNumber, CFNumberIsFloatType};
use core_foundation::string::CFString;
use io_kit_sys::{
    IOObjectRelease, IORegistryEntryCreateCFProperty, IOServiceGetMatchingService,
    IOServiceMatching, kIOMasterPortDefault,
};

use crate::spike::RawPowerTelemetry;

const SERVICE_CLASS: &str = "AppleSmartBattery";
const TELEMETRY_PROPERTY: &str = "PowerTelemetryData";

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
        })
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

/// Why the experimental IOKit snapshot could not be read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacTelemetryReadError {
    /// IOKit could not allocate a matching dictionary.
    MatchingDictionaryUnavailable,
    /// This machine has no AppleSmartBattery service (for example a desktop Mac).
    AppleSmartBatteryUnavailable,
    /// AppleSmartBattery exposes no PowerTelemetryData property on this OS/model.
    TelemetryPropertyUnavailable,
    /// The property exists but is not a dictionary.
    TelemetryPropertyNotDictionary,
    /// One selected field is absent.
    MissingField(&'static str),
    /// One selected field is not an integer.
    FieldNotInteger(&'static str),
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
        }
    }
}

impl Error for MacTelemetryReadError {}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    const FIELD: &str = "TestField";

    fn dictionary_with(value: CFType) -> CFDictionary {
        CFDictionary::from_CFType_pairs(&[(CFString::new(FIELD), value)]).into_untyped()
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
}
