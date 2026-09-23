//! Disabling a persistence unit on Linux and macOS.
//!
//! The counterpart to the Windows service action in [`super::windows`]. On
//! Linux that means a systemd unit; on macOS a launchd job, which is what a
//! LaunchAgent or LaunchDaemon plist becomes once it is loaded.
//!
//! # Why this exists on macOS in particular
//!
//! Phil Stokes, *A Guide to macOS Threat Hunting and Incident Response*
//! (SentinelOne, 2020), chapter 1: the LaunchAgent is "by far the most common
//! way malware persists on macOS", and a per-user one needs no privileges to
//! install. `crate::sensor::persistence` classifies the write that installs
//! one; this is what can be done about it afterwards.
//!
//! Killing the process such a job started accomplishes nothing on its own —
//! launchd starts it again, which is the entire point of a launch item. The
//! job has to be unloaded or the file has to go.
//!
//! # Disable, never delete
//!
//! Both backends stop and disable; neither removes the unit file. The file is
//! the evidence of how the host was persisted on, and an uninstall that erases
//! it destroys the incident record. Quarantine is the action that takes a
//! file, and it keeps a restorable copy when it does.

use super::{ActionExecutor, Capabilities};
use crate::response::action::{
    ActionError, ActionKind, ActionReceipt, Enforcement, ResponseAction,
};

/// Units that will never be disabled, whatever a rule asks for.
///
/// Compiled in rather than configured, for the same reason the agent's own
/// directories are: an engine that can disable its own launch item, or the
/// thing that starts the machine's network, can be steered into disarming the
/// host it is protecting.
const PROTECTED_UNITS: &[&str] = &[
    // Rustinel itself, under both platforms' naming conventions.
    "rustinel",
    "rustinel.service",
    "io.rustinel.agent",
    "com.rustinel.agent",
    // Losing any of these costs the operator the machine.
    "systemd-journald",
    "systemd-journald.service",
    "systemd-logind",
    "systemd-logind.service",
    "systemd-networkd",
    "systemd-networkd.service",
    "sshd",
    "sshd.service",
    "ssh",
    "ssh.service",
    "networkmanager",
    "networkmanager.service",
    "dbus",
    "dbus.service",
    "com.openssh.sshd",
    "com.apple.loginwindow",
    "com.apple.launchd",
    "com.apple.opendirectoryd",
    "com.apple.securityd",
    "com.apple.configd",
    "com.apple.mDNSResponder",
];

/// Whether a unit may be disabled.
///
/// Compared case-insensitively: systemd unit names are case-sensitive but
/// launchd labels are handled inconsistently across tools, and the safe
/// direction for a refusal list is to refuse more rather than fewer.
pub(crate) fn is_protected_unit(name: &str) -> bool {
    let lowered = name.trim().to_ascii_lowercase();
    if lowered.is_empty() {
        return true;
    }
    PROTECTED_UNITS
        .iter()
        .any(|protected| *protected == lowered)
}

/// Executor for the service action on Linux and macOS.
#[derive(Debug)]
pub struct UnixServiceExecutor {
    capabilities: Capabilities,
}

impl Default for UnixServiceExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl UnixServiceExecutor {
    /// Build the executor.
    pub fn new() -> Self {
        Self {
            // Post-hoc, and honestly so: the unit has already run by the time
            // anything here happens. What it buys is that it does not run
            // again, which is the part that matters for persistence.
            capabilities: Capabilities::none("handled by another executor")
                .supporting(ActionKind::DisableService, Enforcement::PostHoc),
        }
    }
}

impl ActionExecutor for UnixServiceExecutor {
    fn name(&self) -> &'static str {
        "unix_service"
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    fn execute(&self, action: &ResponseAction) -> Result<ActionReceipt, ActionError> {
        let enforcement = self.reject_unsupported(action)?;
        let kind = action.kind();

        match action {
            ResponseAction::DisableService { name } => {
                if is_protected_unit(name) {
                    return Err(ActionError::Failed {
                        kind,
                        reason: format!("{name} is protected and will not be disabled"),
                    });
                }

                platform::disable(name).map_err(|reason| ActionError::Failed { kind, reason })?;

                Ok(
                    ActionReceipt::new(kind, enforcement, "unix_service", action.target_key())
                        .with_detail(format!("disabled {name}")),
                )
            }
            other => Err(ActionError::Unsupported {
                kind: other.kind(),
                reason: "not a service action",
            }),
        }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use std::process::{Command, Stdio};

    /// Stop the unit and keep it from starting again.
    ///
    /// `disable --now` is one call that does both. Stopping without disabling
    /// leaves something that returns at the next boot, which for a persistence
    /// unit is the whole problem.
    pub(super) fn disable(name: &str) -> Result<(), String> {
        let output = Command::new("systemctl")
            .args(["disable", "--now", name])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .map_err(|err| format!("cannot run systemctl: {err}"))?;

        if !output.status.success() {
            return Err(format!(
                "systemctl could not disable {name}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use std::process::{Command, Stdio};

    /// Unload the job and mark it disabled.
    ///
    /// `bootout` unloads it now; `disable` is what stops launchd loading it
    /// again at the next login or boot. Both are needed: `bootout` alone lasts
    /// until the next time the plist is read, which for a LaunchAgent is the
    /// user's next login.
    pub(super) fn disable(label: &str) -> Result<(), String> {
        // system/ is the right domain for a LaunchDaemon. A per-user agent
        // lives in gui/<uid>, and the agent does not know which user's session
        // to target from the label alone; the failure names the label so an
        // operator can finish it by hand.
        let disabled = Command::new("launchctl")
            .args(["disable", &format!("system/{label}")])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .map_err(|err| format!("cannot run launchctl: {err}"))?;

        let booted_out = Command::new("launchctl")
            .args(["bootout", &format!("system/{label}")])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .map_err(|err| format!("cannot run launchctl: {err}"))?;

        // Either succeeding is enough: a job that is loaded but not disabled,
        // and one disabled but not currently loaded, are both states where one
        // of the two calls legitimately fails.
        if disabled.status.success() || booted_out.status.success() {
            return Ok(());
        }

        Err(format!(
            "launchctl could not disable {label}: {}",
            String::from_utf8_lossy(&booted_out.stderr).trim()
        ))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod platform {
    /// Windows disables services through the service control manager instead.
    pub(super) fn disable(_name: &str) -> Result<(), String> {
        Err("unix service control is Linux and macOS only".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The agent must not be able to disable itself.
    ///
    /// Anyone who can steer a detection could otherwise point the service
    /// action at Rustinel and disarm the host.
    #[test]
    fn the_agent_cannot_be_disabled_through_its_own_action() {
        for name in [
            "rustinel",
            "rustinel.service",
            "io.rustinel.agent",
            "RUSTINEL.SERVICE",
        ] {
            assert!(is_protected_unit(name), "{name} must be protected");
        }
    }

    /// Losing these costs the operator the machine, which is a worse outcome
    /// than the persistence that prompted the action.
    #[test]
    fn units_that_would_strand_the_operator_are_protected() {
        for name in [
            "sshd.service",
            "systemd-logind",
            "NetworkManager.service",
            "com.openssh.sshd",
            "com.apple.loginwindow",
        ] {
            assert!(is_protected_unit(name), "{name} must be protected");
        }
    }

    /// An empty name is refused rather than passed to the shell.
    #[test]
    fn an_empty_or_blank_name_is_refused() {
        assert!(is_protected_unit(""));
        assert!(is_protected_unit("   "));
    }

    #[test]
    fn an_ordinary_unit_is_not_protected() {
        assert!(!is_protected_unit("com.evil.persistence"));
        assert!(!is_protected_unit("cryptominer.service"));
    }

    #[test]
    fn only_the_service_action_is_claimed() {
        let executor = UnixServiceExecutor::new();
        let kinds = executor.capabilities().supported_kinds();

        assert_eq!(kinds, vec![ActionKind::DisableService]);
    }

    /// Refused before anything runs, so a protected unit costs no process
    /// spawn and no chance of a partial disable.
    #[test]
    fn a_protected_unit_is_refused_without_running_anything() {
        let executor = UnixServiceExecutor::new();

        let error = executor
            .execute(&ResponseAction::DisableService {
                name: "rustinel.service".to_string(),
            })
            .expect_err("the agent's own unit must be refused");

        match error {
            ActionError::Failed { reason, .. } => assert!(reason.contains("protected")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn a_non_service_action_is_not_claimed() {
        let executor = UnixServiceExecutor::new();

        let error = executor
            .execute(&ResponseAction::IsolateHost)
            .expect_err("isolation is not this executor's action");
        assert!(matches!(error, ActionError::Unsupported { .. }));
    }
}
