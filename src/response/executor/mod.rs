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

pub mod ring3;

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

/// The executor to use on this platform.
pub fn default_executor() -> Arc<dyn ActionExecutor> {
    Arc::new(ring3::Ring3Executor::new())
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
