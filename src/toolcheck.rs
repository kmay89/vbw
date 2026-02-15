//! External tool availability detection.
//!
//! VBW delegates cryptographic verification to three external tools:
//! `slsa-verifier`, `in-toto-verify`, and `cosign`. This module probes
//! whether each tool is installed and reachable on `$PATH` before the
//! verification pipeline attempts to invoke them.
//!
//! ## Design Rationale
//!
//! Rather than failing with an opaque OS error ("No such file or directory")
//! when a tool is missing, VBW probes tool availability up front and produces
//! clear, actionable diagnostics. This follows the principle that a security
//! tool must never silently degrade -- every limitation must be visible.
//!
//! ## Implementation
//!
//! Each tool is probed by running `<tool> --version` (or `version` for
//! `slsa-verifier`) and checking whether the subprocess launches
//! successfully. A non-zero exit code is acceptable (the tool exists but
//! may not support `--version`); only a launch failure (binary not found)
//! counts as "unavailable".

use std::process::Command;

/// Summary of which external tools are available on `$PATH`.
#[derive(Debug, Clone)]
pub struct ToolAvailability {
    /// `slsa-verifier` is installed and executable.
    pub slsa_verifier: bool,
    /// `in-toto-verify` is installed and executable (Python `in-toto` package).
    pub in_toto_verify: bool,
    /// `cosign` is installed and executable (Sigstore).
    pub cosign: bool,
}

impl ToolAvailability {
    /// Returns true if all three external tools are available.
    #[allow(dead_code)]
    pub fn all_available(&self) -> bool {
        self.slsa_verifier && self.in_toto_verify && self.cosign
    }

    /// Returns a human-readable summary of missing tools with install hints.
    pub fn missing_tools_report(&self) -> Vec<String> {
        let mut missing = Vec::new();
        if !self.slsa_verifier {
            missing.push(
                "slsa-verifier: not found. Install: https://github.com/slsa-framework/slsa-verifier#installation".to_string()
            );
        }
        if !self.in_toto_verify {
            missing.push("in-toto-verify: not found. Install: pip install in-toto".to_string());
        }
        if !self.cosign {
            missing.push(
                "cosign: not found. Install: https://docs.sigstore.dev/cosign/system_config/installation/"
                    .to_string(),
            );
        }
        missing
    }
}

/// Probes `$PATH` for the three external tools VBW delegates to.
///
/// Each tool is tested by attempting to spawn it with a version flag.
/// The version output is discarded; only the ability to launch matters.
///
/// This function never fails -- a missing tool is reported as `false`,
/// not as an error.
pub fn detect_tools() -> ToolAvailability {
    ToolAvailability {
        slsa_verifier: probe("slsa-verifier", &["version"]),
        in_toto_verify: probe("in-toto-verify", &["--version"]),
        cosign: probe("cosign", &["version"]),
    }
}

/// Attempts to spawn `cmd args...` and returns `true` if the process
/// launched (regardless of exit code). Returns `false` only when the
/// binary cannot be found or executed.
fn probe(cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_tools_does_not_panic() {
        // Smoke test: detect_tools must never fail, even when no tools
        // are installed.
        let tools = detect_tools();
        // We can't assert specific availability in CI, but the struct
        // must be constructable.
        let _ = tools.all_available();
    }

    #[test]
    fn test_missing_tools_report_lists_all_when_none_available() {
        let tools = ToolAvailability {
            slsa_verifier: false,
            in_toto_verify: false,
            cosign: false,
        };
        let report = tools.missing_tools_report();
        assert_eq!(report.len(), 3);
        assert!(report[0].contains("slsa-verifier"));
        assert!(report[1].contains("in-toto-verify"));
        assert!(report[2].contains("cosign"));
    }

    #[test]
    fn test_missing_tools_report_empty_when_all_available() {
        let tools = ToolAvailability {
            slsa_verifier: true,
            in_toto_verify: true,
            cosign: true,
        };
        assert!(tools.missing_tools_report().is_empty());
    }

    #[test]
    fn test_probe_returns_false_for_nonexistent_binary() {
        assert!(!probe(
            "vbw-nonexistent-tool-that-should-never-exist",
            &["--version"]
        ));
    }

    #[test]
    fn test_all_available_requires_all_three() {
        let partial = ToolAvailability {
            slsa_verifier: true,
            in_toto_verify: true,
            cosign: false,
        };
        assert!(!partial.all_available());
    }
}
