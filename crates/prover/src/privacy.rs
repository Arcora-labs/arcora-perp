//! Reject SP1 diagnostic output switches before releasing private witness data.
//!
//! SP1 6.1.0's CPU SDK writes `stdin.bin` and exits without unwinding when
//! `SP1_DUMP` is enabled. Its worker can serialize execution records through
//! `SP1_DUMP_SHARD_DIR`; the optional executor profiler writes a control-flow
//! trace through `TRACE_FILE`. None belongs on this private proving path.
use std::{ffi::OsString, fmt};

/// Public configuration name only: never retain or print the supplied value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sp1PrivacyError {
    pub variable: &'static str,
}

impl fmt::Display for Sp1PrivacyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.variable == "SP1_DUMP" {
            f.write_str("SP1_DUMP must be unset or explicitly 0/false for private proving")
        } else {
            write!(f, "{} must be unset for private proving", self.variable)
        }
    }
}

impl std::error::Error for Sp1PrivacyError {}

/// Validate at service boot (before SP1 captures worker configuration) and again
/// before every private proof. Reject unknown/non-UTF8 values instead of relying
/// on the SDK silently treating them as false. Path switches reject even empty,
/// `false`, or `0` values: the SDK interprets those as paths, not booleans.
///
/// This is a guard against inherited debug configuration, not a sandbox against
/// code that can mutate process environment concurrently. It does not scrub SDK
/// allocations, disable OS core dumps/swap, or establish hardware confidentiality.
pub fn validate_sp1_environment() -> Result<(), Sp1PrivacyError> {
    validate_with(|name| std::env::var_os(name))
}

fn validate_with(mut get: impl FnMut(&str) -> Option<OsString>) -> Result<(), Sp1PrivacyError> {
    if let Some(value) = get("SP1_DUMP") {
        let explicitly_disabled = value
            .to_str()
            .is_some_and(|v| v == "0" || v.eq_ignore_ascii_case("false"));
        if !explicitly_disabled {
            return Err(Sp1PrivacyError {
                variable: "SP1_DUMP",
            });
        }
    }
    for variable in ["SP1_DUMP_SHARD_DIR", "TRACE_FILE"] {
        if get(variable).is_some() {
            return Err(Sp1PrivacyError { variable });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostics_name_only_the_blocked_configuration() {
        for variable in ["SP1_DUMP", "SP1_DUMP_SHARD_DIR", "TRACE_FILE"] {
            let error = validate_with(|name| {
                (name == variable).then(|| OsString::from("private-sentinel-do-not-print"))
            })
            .unwrap_err();
            assert_eq!(error.variable, variable);
            assert!(error.to_string().contains(variable));
            assert!(!error.to_string().contains("private-sentinel"));
            assert!(!format!("{error:?}").contains("private-sentinel"));
        }
    }
}
