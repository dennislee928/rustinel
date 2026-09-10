//! User-mode (Ring 3) executor.
//!
//! This is what Rustinel actually runs. Every action here is
//! [`Enforcement::PostHoc`]: the sensor reports an operation the kernel has
//! already completed, and the executor reacts to it. Denying the operation
//! itself needs a kernel driver, which is the job of
//! [`super::driver::KernelDriverExecutor`].
//!
//! Process termination on Windows is `OpenProcess(PROCESS_TERMINATE)` followed
//! by `TerminateProcess`, and on Unix a `SIGKILL`. Neither is attempted here
//! without the caller having revalidated the target's identity first: the
//! response worker does that immediately before calling, so a recycled PID
//! cannot be killed in place of the process that actually alerted.

use super::{ActionExecutor, Capabilities};
use crate::response::action::{
    ActionError, ActionKind, ActionReceipt, Enforcement, ResponseAction,
};

/// Executor backed by ordinary user-mode operating system APIs.
#[derive(Debug)]
pub struct Ring3Executor {
    capabilities: Capabilities,
}

impl Default for Ring3Executor {
    fn default() -> Self {
        Self::new()
    }
}

impl Ring3Executor {
    /// Build the executor with this platform's capability table.
    pub fn new() -> Self {
        Self {
            capabilities: platform::capabilities(),
        }
    }
}

impl ActionExecutor for Ring3Executor {
    fn name(&self) -> &'static str {
        "ring3"
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    fn execute(&self, action: &ResponseAction) -> Result<ActionReceipt, ActionError> {
        let enforcement = self.reject_unsupported(action)?;
        let receipt = |detail: Option<String>| {
            let receipt =
                ActionReceipt::new(action.kind(), enforcement, "ring3", action.target_key());
            match detail {
                Some(detail) => receipt.with_detail(detail),
                None => receipt,
            }
        };

        match action {
            ResponseAction::TerminateProcess { target } => {
                platform::terminate_process(target.pid).map_err(|reason| ActionError::Failed {
                    kind: ActionKind::TerminateProcess,
                    reason,
                })?;
                Ok(receipt(None))
            }
            other => Err(ActionError::Unsupported {
                kind: other.kind(),
                reason: "not implemented by the user-mode executor yet",
            }),
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::{ActionKind, Capabilities, Enforcement};

    pub(super) fn capabilities() -> Capabilities {
        Capabilities::none("not implemented by the user-mode executor yet")
            .supporting(ActionKind::TerminateProcess, Enforcement::PostHoc)
    }

    pub(super) fn terminate_process(pid: u32) -> Result<(), String> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

        let handle = unsafe { OpenProcess(PROCESS_TERMINATE, false, pid) }
            .map_err(|err| format!("OpenProcess failed: {}", err))?;

        let result = unsafe { TerminateProcess(handle, 1) };
        unsafe {
            let _ = CloseHandle(handle);
        }

        match result {
            Ok(()) => Ok(()),
            Err(err) => Err(format!("TerminateProcess failed: {}", err)),
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod platform {
    use super::{ActionKind, Capabilities, Enforcement};

    pub(super) fn capabilities() -> Capabilities {
        Capabilities::none("not implemented by the user-mode executor yet")
            .supporting(ActionKind::TerminateProcess, Enforcement::PostHoc)
    }

    pub(super) fn terminate_process(pid: u32) -> Result<(), String> {
        let ret = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        if ret == 0 {
            Ok(())
        } else {
            let err = std::io::Error::last_os_error();
            Err(format!("kill({}, SIGKILL) failed: {}", pid, err))
        }
    }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
mod platform {
    use super::Capabilities;

    pub(super) fn capabilities() -> Capabilities {
        Capabilities::none("active response is not supported on this platform")
    }

    pub(super) fn terminate_process(_pid: u32) -> Result<(), String> {
        Err("Active response termination is not supported on this platform".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::ProcessIdentity;

    #[test]
    fn terminate_is_the_only_supported_action_today() {
        let executor = Ring3Executor::new();

        #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
        {
            assert_eq!(
                executor.capabilities().supported_kinds(),
                vec![ActionKind::TerminateProcess]
            );
            assert_eq!(
                executor.capabilities().enforcement(ActionKind::TerminateProcess),
                Some(Enforcement::PostHoc),
                "user mode always acts after the fact"
            );
        }

        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        assert!(executor.capabilities().supported_kinds().is_empty());
    }

    #[test]
    fn unimplemented_actions_report_unsupported_rather_than_failing_silently() {
        let executor = Ring3Executor::new();
        let action = ResponseAction::SuspendProcess {
            target: ProcessIdentity {
                pid: 4242,
                image: "C:\\tmp\\target.exe".to_string(),
                start_time: None,
                command_line_hash: None,
            },
        };

        assert!(matches!(
            executor.execute(&action),
            Err(ActionError::Unsupported {
                kind: ActionKind::SuspendProcess,
                ..
            })
        ));
    }
}
