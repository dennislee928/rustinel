//! Action executors: the *how* behind a [`ResponseAction`].
//!
//! Rustinel runs entirely in user mode (Ring 3), so [`ring3::Ring3Executor`]
//! is what actually carries out containment today, and every process, file,
//! and registry action it performs is [`Enforcement::PostHoc`]: the kernel has
//! already completed the operation by the time the sensor sees it.
//!
//! The Windows kernel offers genuine inline denial through
//! `ObRegisterCallbacks`, `CmRegisterCallbackEx`, a filesystem minifilter, and
//! a WFP callout, but all four require a loaded kernel driver, and a driver
//! requires a signing certificate Rustinel does not have. Rather than pretend
//! otherwise, the capability table makes the difference explicit: an executor
//! declares, per action kind, whether it can act at all and whether acting
//! denies the operation or cleans up after it. [`driver::KernelDriverExecutor`]
//! is the seam a future signed driver would fill, and it reports every action
//! as unsupported until that driver exists.

pub mod asep;
pub mod quarantine;
pub mod ring3;
pub mod wfp;

#[cfg(windows)]
pub mod windows;

#[cfg(windows)]
pub mod driver;

use super::action::{ActionError, ActionKind, ActionReceipt, Enforcement, ResponseAction};
use std::fmt;
use std::sync::{Arc, Mutex};

/// Whether an executor can perform one kind of action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionSupport {
    /// The executor can perform it, with this enforcement strength.
    Supported(Enforcement),
    /// The executor cannot perform it, for this reason.
    Unsupported(&'static str),
}

impl ActionSupport {
    /// Enforcement strength, when supported.
    pub fn enforcement(self) -> Option<Enforcement> {
        match self {
            ActionSupport::Supported(enforcement) => Some(enforcement),
            ActionSupport::Unsupported(_) => None,
        }
    }

    /// Whether the action is supported at all.
    pub fn is_supported(self) -> bool {
        matches!(self, ActionSupport::Supported(_))
    }
}

/// What an executor can do, one entry per [`ActionKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    entries: [ActionSupport; ActionKind::COUNT],
}

impl Capabilities {
    /// A table where nothing is supported, all for the same reason.
    pub const fn none(reason: &'static str) -> Self {
        Self {
            entries: [ActionSupport::Unsupported(reason); ActionKind::COUNT],
        }
    }

    /// A table where every action is supported with the same enforcement.
    pub const fn all(enforcement: Enforcement) -> Self {
        Self {
            entries: [ActionSupport::Supported(enforcement); ActionKind::COUNT],
        }
    }

    /// Declare support for one kind. Chainable, for use in a constructor.
    pub const fn with(mut self, kind: ActionKind, support: ActionSupport) -> Self {
        self.entries[kind.index()] = support;
        self
    }

    /// Declare an action supported with the given enforcement.
    pub const fn supporting(self, kind: ActionKind, enforcement: Enforcement) -> Self {
        self.with(kind, ActionSupport::Supported(enforcement))
    }

    /// Support entry for one kind.
    pub fn support(&self, kind: ActionKind) -> ActionSupport {
        self.entries[kind.index()]
    }

    /// Whether one kind is supported.
    pub fn supports(&self, kind: ActionKind) -> bool {
        self.support(kind).is_supported()
    }

    /// Enforcement strength for one kind, when supported.
    pub fn enforcement(&self, kind: ActionKind) -> Option<Enforcement> {
        self.support(kind).enforcement()
    }

    /// Every supported kind, in [`ActionKind::ALL`] order.
    pub fn supported_kinds(&self) -> Vec<ActionKind> {
        ActionKind::ALL
            .into_iter()
            .filter(|kind| self.supports(*kind))
            .collect()
    }
}

/// Carries out response actions.
///
/// Implementations must be safe to call from the response worker thread and
/// must not block for long: the worker is a single consumer, so a slow
/// executor delays every later action.
pub trait ActionExecutor: Send + Sync + fmt::Debug {
    /// Short name, recorded on every receipt and audit line.
    fn name(&self) -> &'static str;

    /// What this executor can do.
    fn capabilities(&self) -> &Capabilities;

    /// Perform the action.
    fn execute(&self, action: &ResponseAction) -> Result<ActionReceipt, ActionError>;

    /// Undo a previously performed action.
    ///
    /// Only reversible actions implement this; killing a process cannot be
    /// undone, and the default refuses.
    fn rollback(&self, receipt: &ActionReceipt) -> Result<(), ActionError> {
        Err(ActionError::Unsupported {
            kind: receipt.kind,
            reason: "action is not reversible",
        })
    }

    /// Reject an action this executor does not support.
    ///
    /// Call at the top of [`ActionExecutor::execute`] so the capability table
    /// stays the single source of truth for what an executor will attempt.
    fn reject_unsupported(&self, action: &ResponseAction) -> Result<Enforcement, ActionError> {
        let kind = action.kind();
        match self.capabilities().support(kind) {
            ActionSupport::Supported(enforcement) => Ok(enforcement),
            ActionSupport::Unsupported(reason) => Err(ActionError::Unsupported { kind, reason }),
        }
    }
}

/// The executor to use on this platform, assembled from the specialised ones.
///
/// Built once, at engine construction: an executor owns operating-system
/// handles and directories, which are install-time properties rather than
/// things a hot reload should move underneath a running action.
pub fn default_executor(config: &crate::config::ResponseConfig) -> Arc<dyn ActionExecutor> {
    // The driver goes first: when one is loaded it denies the operation
    // outright, and the user-mode executors below only clean up after it.
    #[cfg(windows)]
    let mut executors: Vec<Arc<dyn ActionExecutor>> = vec![
        Arc::new(driver::KernelDriverExecutor::new()),
        Arc::new(ring3::Ring3Executor::new()),
    ];
    #[cfg(not(windows))]
    let mut executors: Vec<Arc<dyn ActionExecutor>> = vec![Arc::new(ring3::Ring3Executor::new())];

    executors.push(Arc::new(quarantine::QuarantineExecutor::new(
        config.quarantine_directory.clone(),
        agent_owned_directories(),
    )));

    executors.push(Arc::new(wfp::WfpExecutor::new(
        wfp::IsolationPolicy {
            allow_cidrs: config.actions.isolate_host.allow_cidrs.clone(),
            allow_dns: config.actions.isolate_host.allow_dns,
            allow_dhcp: config.actions.isolate_host.allow_dhcp,
        },
        config.actions.isolate_host.persistent,
    )));

    #[cfg(windows)]
    {
        executors.push(Arc::new(windows::WindowsExecutor::new()));
    }

    Arc::new(CompositeExecutor::new(executors))
}

/// Directories holding the agent's own files, which no action may touch.
///
/// An engine that can quarantine its own binary or rules can be made to
/// disarm itself by anyone who can steer a detection, so the list is compiled
/// in rather than configured.
fn agent_owned_directories() -> Vec<std::path::PathBuf> {
    let mut dirs = Vec::new();

    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            dirs.push(parent.to_path_buf());
        }
    }

    let layout = crate::config::InstallLayout::managed_current();
    dirs.push(layout.rules_dir.clone());
    dirs.push(layout.logs_dir.clone());
    if let Some(root) = layout.config_file.parent() {
        dirs.push(root.to_path_buf());
    }

    dirs
}

/// Routes each action to the first executor that can perform it.
///
/// This is where a kernel driver would take precedence: when
/// [`driver::KernelDriverExecutor`] reports a kind as `Inline`, placing it
/// ahead of the user-mode executors is all it takes for that action to start
/// denying the operation instead of cleaning up after it.
#[derive(Debug)]
pub struct CompositeExecutor {
    executors: Vec<Arc<dyn ActionExecutor>>,
    capabilities: Capabilities,
}

impl CompositeExecutor {
    /// Compose executors in priority order.
    pub fn new(executors: Vec<Arc<dyn ActionExecutor>>) -> Self {
        let mut capabilities = Capabilities::none("no executor handles this action");

        // First to claim a kind wins, so ordering is the priority.
        for kind in ActionKind::ALL {
            if let Some(support) = executors
                .iter()
                .map(|executor| executor.capabilities().support(kind))
                .find(|support| support.is_supported())
            {
                capabilities = capabilities.with(kind, support);
            }
        }

        Self {
            executors,
            capabilities,
        }
    }

    /// The executor that would handle this kind.
    fn executor_for(&self, kind: ActionKind) -> Option<&Arc<dyn ActionExecutor>> {
        self.executors
            .iter()
            .find(|executor| executor.capabilities().supports(kind))
    }
}

impl ActionExecutor for CompositeExecutor {
    fn name(&self) -> &'static str {
        "composite"
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    fn execute(&self, action: &ResponseAction) -> Result<ActionReceipt, ActionError> {
        self.reject_unsupported(action)?;
        self.executor_for(action.kind())
            .ok_or(ActionError::Unsupported {
                kind: action.kind(),
                reason: "no executor handles this action",
            })?
            .execute(action)
    }

    fn rollback(&self, receipt: &ActionReceipt) -> Result<(), ActionError> {
        self.executor_for(receipt.kind)
            .ok_or(ActionError::Unsupported {
                kind: receipt.kind,
                reason: "no executor handles this action",
            })?
            .rollback(receipt)
    }
}

/// An executor that records what it was asked to do and performs nothing.
///
/// This is the seam the policy and safety tests act through: they assert on
/// the actions that reach an executor without touching a real process. It is
/// public so integration tests under `tests/` can use it too.
#[derive(Debug)]
pub struct MockExecutor {
    capabilities: Capabilities,
    calls: Mutex<Vec<ResponseAction>>,
    fail_with: Option<String>,
}

impl Default for MockExecutor {
    fn default() -> Self {
        Self {
            capabilities: Capabilities::all(Enforcement::PostHoc),
            calls: Mutex::new(Vec::new()),
            fail_with: None,
        }
    }
}

impl MockExecutor {
    /// A mock that supports every action and succeeds.
    pub fn new() -> Self {
        Self::default()
    }

    /// A mock that supports every action and fails with `reason`.
    pub fn failing(reason: impl Into<String>) -> Self {
        Self {
            fail_with: Some(reason.into()),
            ..Self::default()
        }
    }

    /// A mock with an explicit capability table.
    pub fn with_capabilities(capabilities: Capabilities) -> Self {
        Self {
            capabilities,
            ..Self::default()
        }
    }

    /// Actions this mock was asked to perform, in order.
    pub fn calls(&self) -> Vec<ResponseAction> {
        self.calls.lock().expect("mock executor lock").clone()
    }

    /// Kinds this mock was asked to perform, in order.
    pub fn call_kinds(&self) -> Vec<ActionKind> {
        self.calls()
            .into_iter()
            .map(|action| action.kind())
            .collect()
    }
}

impl ActionExecutor for MockExecutor {
    fn name(&self) -> &'static str {
        "mock"
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    fn execute(&self, action: &ResponseAction) -> Result<ActionReceipt, ActionError> {
        let enforcement = self.reject_unsupported(action)?;
        self.calls
            .lock()
            .expect("mock executor lock")
            .push(action.clone());

        match &self.fail_with {
            Some(reason) => Err(ActionError::Failed {
                kind: action.kind(),
                reason: reason.clone(),
            }),
            None => Ok(ActionReceipt::new(
                action.kind(),
                enforcement,
                self.name(),
                action.target_key(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::ProcessIdentity;

    fn identity(pid: u32) -> ProcessIdentity {
        ProcessIdentity {
            pid,
            image: format!("C:\\tmp\\{pid}.exe"),
            start_time: None,
            command_line_hash: None,
        }
    }

    #[test]
    fn capability_table_defaults_to_unsupported() {
        let table = Capabilities::none("no driver");
        for kind in ActionKind::ALL {
            assert!(!table.supports(kind));
            assert_eq!(table.enforcement(kind), None);
            assert_eq!(
                table.support(kind),
                ActionSupport::Unsupported("no driver"),
                "{kind}"
            );
        }
        assert!(table.supported_kinds().is_empty());
    }

    #[test]
    fn capability_table_records_declared_support_only() {
        let table = Capabilities::none("not implemented")
            .supporting(ActionKind::TerminateProcess, Enforcement::PostHoc)
            .supporting(ActionKind::IsolateHost, Enforcement::Inline);

        assert_eq!(
            table.enforcement(ActionKind::TerminateProcess),
            Some(Enforcement::PostHoc)
        );
        assert_eq!(
            table.enforcement(ActionKind::IsolateHost),
            Some(Enforcement::Inline)
        );
        assert!(!table.supports(ActionKind::QuarantineFile));
        assert_eq!(
            table.supported_kinds(),
            vec![ActionKind::TerminateProcess, ActionKind::IsolateHost]
        );
    }

    #[test]
    fn unsupported_action_is_rejected_before_it_runs() {
        let executor = MockExecutor::with_capabilities(Capabilities::none("test executor"));
        let action = ResponseAction::TerminateProcess {
            target: identity(4242),
        };

        let error = executor.execute(&action).expect_err("must reject");
        assert_eq!(
            error,
            ActionError::Unsupported {
                kind: ActionKind::TerminateProcess,
                reason: "test executor",
            }
        );
        assert!(
            executor.calls().is_empty(),
            "rejected action must not be recorded as performed"
        );
    }

    #[test]
    fn mock_records_supported_actions_and_returns_a_receipt() {
        let executor = MockExecutor::new();
        let action = ResponseAction::TerminateProcess {
            target: identity(4242),
        };

        let receipt = executor.execute(&action).expect("receipt");
        assert_eq!(receipt.kind, ActionKind::TerminateProcess);
        assert_eq!(receipt.executor, "mock");
        assert_eq!(receipt.enforcement, Enforcement::PostHoc);
        assert_eq!(executor.call_kinds(), vec![ActionKind::TerminateProcess]);
    }

    #[test]
    fn rollback_of_an_irreversible_action_is_refused() {
        let executor = MockExecutor::new();
        let receipt = ActionReceipt::new(
            ActionKind::TerminateProcess,
            Enforcement::PostHoc,
            "mock",
            "4242".to_string(),
        );

        assert!(matches!(
            executor.rollback(&receipt),
            Err(ActionError::Unsupported { .. })
        ));
    }
}
