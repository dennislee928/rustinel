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
            ResponseAction::SuspendProcess { target } => {
                platform::suspend_process(target.pid).map_err(|reason| ActionError::Failed {
                    kind: ActionKind::SuspendProcess,
                    reason,
                })?;
                Ok(receipt(Some(
                    "process suspended; resume it to release".to_string(),
                )))
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
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Threading::{
        OpenProcess, TerminateProcess, PROCESS_SUSPEND_RESUME, PROCESS_TERMINATE,
    };

    /// `NtSuspendProcess`, which has no documented Win32 wrapper.
    type NtSuspendProcessFn = unsafe extern "system" fn(HANDLE) -> i32;

    pub(super) fn capabilities() -> Capabilities {
        Capabilities::none("not implemented by the user-mode executor yet")
            .supporting(ActionKind::TerminateProcess, Enforcement::PostHoc)
            .supporting(ActionKind::SuspendProcess, Enforcement::PostHoc)
    }

    pub(super) fn terminate_process(pid: u32) -> Result<(), String> {
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

    /// Freeze every thread in the process.
    ///
    /// Windows exposes no documented Win32 call for this: `DebugActiveProcess`
    /// would work but kills the target when the debugger detaches, which is
    /// the opposite of preserving it for triage. `NtSuspendProcess` is the
    /// undocumented but stable ntdll export the platform itself uses, resolved
    /// at runtime so a missing export degrades to an error rather than a
    /// failure to load.
    pub(super) fn suspend_process(pid: u32) -> Result<(), String> {
        let routine = nt_suspend_process().ok_or("NtSuspendProcess is unavailable")?;

        let handle = unsafe { OpenProcess(PROCESS_SUSPEND_RESUME, false, pid) }
            .map_err(|err| format!("OpenProcess failed: {}", err))?;

        let status = unsafe { routine(handle) };
        unsafe {
            let _ = CloseHandle(handle);
        }

        if status >= 0 {
            Ok(())
        } else {
            Err(format!("NtSuspendProcess failed: {status:#010x}"))
        }
    }

    /// Resolve and cache the ntdll export.
    fn nt_suspend_process() -> Option<NtSuspendProcessFn> {
        use std::sync::OnceLock;
        use windows::core::{s, w};
        use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

        static ROUTINE: OnceLock<Option<NtSuspendProcessFn>> = OnceLock::new();

        *ROUTINE.get_or_init(|| {
            // ntdll is mapped into every process, so this is a lookup rather
            // than a load.
            let ntdll = unsafe { GetModuleHandleW(w!("ntdll.dll")) }.ok()?;
            let address = unsafe { GetProcAddress(ntdll, s!("NtSuspendProcess")) }?;

            // SAFETY: the address is the documented-by-use signature of
            // NtSuspendProcess, which takes a process handle and returns an
            // NTSTATUS.
            Some(unsafe {
                std::mem::transmute::<unsafe extern "system" fn() -> isize, NtSuspendProcessFn>(
                    address,
                )
            })
        })
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod platform {
    use super::{ActionKind, Capabilities, Enforcement};

    pub(super) fn capabilities() -> Capabilities {
        Capabilities::none("not implemented by the user-mode executor yet")
            .supporting(ActionKind::TerminateProcess, Enforcement::PostHoc)
            .supporting(ActionKind::SuspendProcess, Enforcement::PostHoc)
    }

    pub(super) fn terminate_process(pid: u32) -> Result<(), String> {
        signal(pid, libc::SIGKILL, "SIGKILL")
    }

    pub(super) fn suspend_process(pid: u32) -> Result<(), String> {
        signal(pid, libc::SIGSTOP, "SIGSTOP")
    }

    fn signal(pid: u32, signal: libc::c_int, name: &str) -> Result<(), String> {
        let ret = unsafe { libc::kill(pid as libc::pid_t, signal) };
        if ret == 0 {
            Ok(())
        } else {
            let err = std::io::Error::last_os_error();
            Err(format!("kill({}, {}) failed: {}", pid, name, err))
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

    pub(super) fn suspend_process(_pid: u32) -> Result<(), String> {
        Err("Active response suspension is not supported on this platform".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::ProcessIdentity;

    #[test]
    fn process_actions_are_supported_and_always_act_after_the_fact() {
        let executor = Ring3Executor::new();

        #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
        {
            assert_eq!(
                executor.capabilities().supported_kinds(),
                vec![ActionKind::TerminateProcess, ActionKind::SuspendProcess]
            );
            for kind in [ActionKind::TerminateProcess, ActionKind::SuspendProcess] {
                assert_eq!(
                    executor.capabilities().enforcement(kind),
                    Some(Enforcement::PostHoc),
                    "user mode cannot deny an operation, only react to it"
                );
            }
        }

        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        assert!(executor.capabilities().supported_kinds().is_empty());
    }

    #[test]
    fn unimplemented_actions_report_unsupported_rather_than_failing_silently() {
        let executor = Ring3Executor::new();
        let action = ResponseAction::QuarantineFile {
            path: std::path::PathBuf::from("C:\\tmp\\dropper.exe"),
        };

        assert!(matches!(
            executor.execute(&action),
            Err(ActionError::Unsupported {
                kind: ActionKind::QuarantineFile,
                ..
            })
        ));
    }

    #[test]
    fn suspending_a_process_that_does_not_exist_reports_a_failure() {
        let executor = Ring3Executor::new();
        let action = ResponseAction::SuspendProcess {
            target: ProcessIdentity {
                // A PID this high is not in use; the point is that the
                // executor surfaces the OS refusal rather than claiming success.
                pid: u32::MAX - 4,
                image: "C:\\tmp\\target.exe".to_string(),
                start_time: None,
                command_line_hash: None,
            },
        };

        #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
        assert!(matches!(
            executor.execute(&action),
            Err(ActionError::Failed {
                kind: ActionKind::SuspendProcess,
                ..
            })
        ));

        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        assert!(executor.execute(&action).is_err());
    }
}
