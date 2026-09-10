//! Kernel-mode executor.
//!
//! Everything else in this module tree acts after the operation it responds to.
//! This is the seam for acting *instead of* it, which on Windows means a kernel
//! driver, because the four APIs that can refuse an operation while it is
//! happening are all kernel-mode callbacks:
//!
//! | Action | Kernel API | What it denies |
//! | --- | --- | --- |
//! | [`ActionKind::TerminateProcess`] | `ObRegisterCallbacks` pre-operation | Strips `PROCESS_VM_READ`/`VM_WRITE`/`CREATE_THREAD` on handle open, so the dump or the injection never starts |
//! | [`ActionKind::RevertRegistry`] | `CmRegisterCallbackEx` pre-operation | Fails the `RegSetValue`, so the Run key is never written |
//! | [`ActionKind::QuarantineFile`] | Minifilter pre-operation | Completes the IRP with `STATUS_ACCESS_DENIED`, so the ransomware write never lands |
//! | [`ActionKind::BlockProcessNetwork`] | WFP callout | Drops the packet after inspecting its payload |
//!
//! The driver source is in `driver/` and its interface is
//! `driver/include/rustinel_ioctl.h`. This module mirrors that header; the two
//! must agree exactly, because a struct that disagrees across the boundary is a
//! kernel memory-corruption bug rather than a parse error.
//!
//! # What this does when no driver is loaded
//!
//! Reports every action unsupported, which is what makes the rest of the engine
//! fall through to the user-mode executors. Nothing here fails loudly on a
//! machine without the driver, because that is the normal case: the driver is
//! optional and most deployments will not have one.
//!
//! # Why most deployments will not have one
//!
//! A driver loads on 64-bit Windows only with a signature chaining to a
//! Microsoft cross-signing certificate, obtained through attestation signing or
//! WHQL with an EV certificate. `ObRegisterCallbacks` additionally refuses to
//! register for an image not linked with `/INTEGRITYCHECK`. Neither is a coding
//! problem, which is why the seam exists and the driver does not ship.
//!
//! Note that the network action is listed above for completeness only. WFP
//! *filters*, which block by address, port, and application, are installed from
//! user mode by [`super::wfp`] and are already enforced by the kernel; a callout
//! adds payload inspection, which Rustinel does not do.

use super::{ActionExecutor, Capabilities};
use crate::response::action::{
    ActionError, ActionKind, ActionReceipt, Enforcement, ResponseAction,
};

/// Reason reported for every action while no driver is present.
const NO_DRIVER: &str = "kernel driver is not installed";

/// Device the driver exposes, mirroring `RUSTINEL_USER_PATH`.
pub const DEVICE_PATH: &str = r"\\.\Rustinel";

/// Policy structure version, mirroring `RUSTINEL_POLICY_VERSION`.
pub const POLICY_VERSION: u32 = 1;

/// What the driver should do when a rule matches.
///
/// Mirrors `RUSTINEL_DISPOSITION`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Report only; the operation proceeds untouched.
    Audit = 0,
    /// Remove the dangerous rights and let the open succeed.
    ///
    /// Preferred over outright denial for process handles: a caller refused
    /// entirely knows it was blocked, whereas one handed a handle without
    /// `PROCESS_VM_READ` sees something indistinguishable from an ordinary
    /// permissions problem.
    Strip = 1,
    /// Fail the operation.
    Deny = 2,
}

/// Executor that would delegate to the Rustinel kernel driver.
#[derive(Debug)]
pub struct KernelDriverExecutor {
    capabilities: Capabilities,
    device_present: bool,
}

impl Default for KernelDriverExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl KernelDriverExecutor {
    /// Build the executor, probing for the driver.
    ///
    /// The probe is a device open, which is the only reliable answer: a service
    /// entry can exist for a driver that failed to register its callbacks, and
    /// a driver that registered nothing should not be treated as present.
    pub fn new() -> Self {
        let device_present = platform::device_present();

        // Until a driver is actually loaded, claiming any capability would
        // route actions here and strand them.
        let capabilities = if device_present {
            Capabilities::none("not implemented by the driver yet")
                .supporting(ActionKind::TerminateProcess, Enforcement::Inline)
                .supporting(ActionKind::RevertRegistry, Enforcement::Inline)
        } else {
            Capabilities::none(NO_DRIVER)
        };

        Self {
            capabilities,
            device_present,
        }
    }

    /// Whether a Rustinel kernel driver is loaded.
    pub fn driver_present(&self) -> bool {
        self.device_present
    }
}

impl ActionExecutor for KernelDriverExecutor {
    fn name(&self) -> &'static str {
        "kernel_driver"
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    fn execute(&self, action: &ResponseAction) -> Result<ActionReceipt, ActionError> {
        let enforcement = self.reject_unsupported(action)?;

        // Reached only when a driver is present and claims this kind. The
        // policy push itself is not implemented, so the action is reported
        // rather than silently treated as done.
        let _ = enforcement;
        Err(ActionError::Unsupported {
            kind: action.kind(),
            reason: "the driver policy interface is not implemented yet",
        })
    }
}

#[cfg(windows)]
mod platform {
    use super::DEVICE_PATH;

    /// Whether the driver's control device can be opened.
    pub(super) fn device_present() -> bool {
        use windows::core::HSTRING;
        use windows::Win32::Foundation::{CloseHandle, GENERIC_READ};
        use windows::Win32::Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
        };

        let handle = unsafe {
            CreateFileW(
                &HSTRING::from(DEVICE_PATH),
                GENERIC_READ.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        };

        match handle {
            Ok(handle) => {
                unsafe {
                    let _ = CloseHandle(handle);
                }
                true
            }
            Err(_) => false,
        }
    }
}

#[cfg(not(windows))]
mod platform {
    /// The driver is Windows-only.
    pub(super) fn device_present() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::ProcessIdentity;

    #[test]
    fn without_a_driver_every_action_is_unsupported() {
        let executor = KernelDriverExecutor::new();

        // No driver ships, so this is the state on every machine that runs
        // the test suite.
        assert!(!executor.driver_present());
        assert!(executor.capabilities().supported_kinds().is_empty());

        let action = ResponseAction::TerminateProcess {
            target: ProcessIdentity {
                pid: 4242,
                image: "C:\\tmp\\target.exe".to_string(),
                start_time: None,
                command_line_hash: None,
            },
        };

        assert_eq!(
            executor.execute(&action),
            Err(ActionError::Unsupported {
                kind: ActionKind::TerminateProcess,
                reason: NO_DRIVER,
            })
        );
    }

    #[test]
    fn the_device_path_matches_the_driver_header() {
        // `RUSTINEL_USER_PATH` in driver/include/rustinel_ioctl.h. A mismatch
        // means the agent probes a device the driver never created, and the
        // driver silently never gets used.
        assert_eq!(DEVICE_PATH, r"\\.\Rustinel");
    }

    #[test]
    fn dispositions_match_the_driver_enum() {
        // These are sent as integers over the IOCTL boundary, so the values
        // matter more than the names.
        assert_eq!(Disposition::Audit as u32, 0);
        assert_eq!(Disposition::Strip as u32, 1);
        assert_eq!(Disposition::Deny as u32, 2);
    }
}
