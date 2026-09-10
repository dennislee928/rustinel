//! Seam for a future kernel-mode executor.
//!
//! Nothing here talks to a driver, because Rustinel does not ship one. The
//! module exists so the boundary a driver would sit behind is written down and
//! type-checked rather than imagined, and so the policy, safety, and audit
//! layers need no change on the day one arrives.
//!
//! # What a driver would add
//!
//! User mode can only react: by the time an ETW event reaches Rustinel, the
//! kernel has already opened the handle, written the value, or encrypted the
//! file. Denial has to happen inside the operation, and Windows exposes
//! exactly four supported ways to do that, none reachable from Ring 3:
//!
//! | Action | Kernel API | What it denies |
//! | --- | --- | --- |
//! | [`ActionKind::TerminateProcess`] | `ObRegisterCallbacks` pre-operation | Strips or denies `PROCESS_VM_WRITE`/`PROCESS_CREATE_THREAD` on handle open, so the injection never starts |
//! | [`ActionKind::RevertRegistry`] | `CmRegisterCallbackEx` pre-operation | Returns `STATUS_ACCESS_DENIED` for the `RegSetValue`, so the Run key is never written |
//! | [`ActionKind::QuarantineFile`] | Minifilter `FltRegisterFilter` pre-operation | Completes the IRP with `STATUS_ACCESS_DENIED`, so the ransomware write never lands |
//! | [`ActionKind::BlockProcessNetwork`] | WFP callout `FwpsCalloutRegister` | Drops the packet rather than the connection |
//!
//! A driver would also unlock `Microsoft-Windows-Threat-Intelligence`, the
//! only source of cross-process memory-write and APC-injection telemetry,
//! which additionally requires the agent to run as a Protected Process Light
//! under an ELAM driver signed through the Microsoft Virus Initiative.
//!
//! # Why it is not implemented
//!
//! Loading a kernel driver on 64-bit Windows requires an Authenticode
//! signature chaining to a Microsoft cross-signing certificate, obtained
//! through attestation or WHQL signing with an EV certificate. That is an
//! organisational prerequisite, not a coding one. Until it is met, this
//! executor reports every action as unsupported and
//! [`super::ring3::Ring3Executor`] does the work after the fact.
//!
//! # Contract for the implementation
//!
//! The driver would expose a single control device, and `execute` would
//! marshal the [`ResponseAction`] into one IOCTL per action kind, with the
//! driver holding the policy state (protected PIDs, allowlisted images) that
//! the pre-operation callbacks consult on the calling thread. `execute` must
//! stay non-blocking: pre-operation callbacks run at `PASSIVE_LEVEL` in the
//! context of the requesting thread, so a slow round trip stalls the very
//! process being evaluated.

use super::{ActionExecutor, Capabilities};
use crate::response::action::{ActionError, ActionReceipt, ResponseAction};

/// Reason reported for every action while no driver is present.
const NO_DRIVER: &str = "kernel driver is not installed";

/// Executor that would delegate to a Rustinel kernel driver.
///
/// Construct it to ask what a driver would provide; it never acts.
#[derive(Debug)]
pub struct KernelDriverExecutor {
    capabilities: Capabilities,
}

impl Default for KernelDriverExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl KernelDriverExecutor {
    /// Build the executor. Always reports every action unsupported, because
    /// there is no driver to delegate to.
    pub fn new() -> Self {
        Self {
            capabilities: Capabilities::none(NO_DRIVER),
        }
    }

    /// Whether a Rustinel kernel driver is loaded.
    ///
    /// Always `false`. Kept as a named predicate so the call sites that will
    /// need it read correctly today.
    pub fn driver_present(&self) -> bool {
        false
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
        Err(ActionError::Unsupported {
            kind: action.kind(),
            reason: NO_DRIVER,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::response::action::ActionKind;
    use crate::utils::ProcessIdentity;

    #[test]
    fn driver_executor_supports_nothing_and_says_why() {
        let executor = KernelDriverExecutor::new();
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
}
