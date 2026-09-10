//! Response action vocabulary.
//!
//! A [`ResponseAction`] is one unit of containment: the *what*. Carrying out
//! the action is the job of an
//! [`ActionExecutor`](super::executor::ActionExecutor): the *how*. Keeping the
//! two apart is what lets a future signed kernel driver back the same action
//! with an inline denial (`ObRegisterCallbacks`, `CmRegisterCallbackEx`, a
//! minifilter, a WFP callout) while the policy, safety, and audit layers stay
//! exactly as they are.

use crate::utils::ProcessIdentity;
use serde::Deserialize;
use std::fmt;
use std::path::PathBuf;

/// Stable, payload-independent identifier for an action.
///
/// This is the key used by the configuration (`[response.actions.<kind>]`),
/// by the executor capability table, and by the rate limiter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    /// Kill the offending process.
    TerminateProcess,
    /// Freeze the offending process, leaving it available for triage.
    SuspendProcess,
    /// Cut the host off the network except for an operator-defined allowlist.
    IsolateHost,
    /// Deny one image outbound and inbound network access.
    BlockProcessNetwork,
    /// Move a file out of reach and record how to put it back.
    QuarantineFile,
    /// Undo a registry persistence write.
    RevertRegistry,
    /// Stop a service and mark it disabled.
    DisableService,
    /// Disable a scheduled task.
    DisableScheduledTask,
}

impl ActionKind {
    /// Every action kind, in declaration order.
    pub const ALL: [ActionKind; 8] = [
        ActionKind::TerminateProcess,
        ActionKind::SuspendProcess,
        ActionKind::IsolateHost,
        ActionKind::BlockProcessNetwork,
        ActionKind::QuarantineFile,
        ActionKind::RevertRegistry,
        ActionKind::DisableService,
        ActionKind::DisableScheduledTask,
    ];

    /// Number of distinct action kinds; the width of a capability table.
    pub const COUNT: usize = ActionKind::ALL.len();

    /// Dense index for capability lookup.
    pub const fn index(self) -> usize {
        match self {
            ActionKind::TerminateProcess => 0,
            ActionKind::SuspendProcess => 1,
            ActionKind::IsolateHost => 2,
            ActionKind::BlockProcessNetwork => 3,
            ActionKind::QuarantineFile => 4,
            ActionKind::RevertRegistry => 5,
            ActionKind::DisableService => 6,
            ActionKind::DisableScheduledTask => 7,
        }
    }

    /// Configuration and audit spelling of this kind.
    pub const fn as_str(self) -> &'static str {
        match self {
            ActionKind::TerminateProcess => "terminate_process",
            ActionKind::SuspendProcess => "suspend_process",
            ActionKind::IsolateHost => "isolate_host",
            ActionKind::BlockProcessNetwork => "block_process_network",
            ActionKind::QuarantineFile => "quarantine_file",
            ActionKind::RevertRegistry => "revert_registry",
            ActionKind::DisableService => "disable_service",
            ActionKind::DisableScheduledTask => "disable_scheduled_task",
        }
    }

    /// Parse the configuration spelling, ignoring case and surrounding space.
    pub fn parse(value: &str) -> Option<Self> {
        let value = value.trim().to_ascii_lowercase();
        ActionKind::ALL
            .into_iter()
            .find(|kind| kind.as_str() == value)
    }
}

impl fmt::Display for ActionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One containment step, with the payload the executor needs to carry it out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseAction {
    /// Kill `target`, whose identity is revalidated immediately before the call.
    TerminateProcess { target: ProcessIdentity },
    /// Freeze `target` without killing it.
    SuspendProcess { target: ProcessIdentity },
    /// Isolate the whole host.
    IsolateHost,
    /// Block one image's network access.
    BlockProcessNetwork { image: PathBuf },
    /// Quarantine one file.
    QuarantineFile { path: PathBuf },
    /// Delete or restore one registry value.
    RevertRegistry { key: String, value: Option<String> },
    /// Stop and disable one service.
    DisableService { name: String },
    /// Disable one scheduled task.
    DisableScheduledTask { path: String },
}

impl ResponseAction {
    /// Kind of this action, for capability lookup and audit.
    pub fn kind(&self) -> ActionKind {
        match self {
            ResponseAction::TerminateProcess { .. } => ActionKind::TerminateProcess,
            ResponseAction::SuspendProcess { .. } => ActionKind::SuspendProcess,
            ResponseAction::IsolateHost => ActionKind::IsolateHost,
            ResponseAction::BlockProcessNetwork { .. } => ActionKind::BlockProcessNetwork,
            ResponseAction::QuarantineFile { .. } => ActionKind::QuarantineFile,
            ResponseAction::RevertRegistry { .. } => ActionKind::RevertRegistry,
            ResponseAction::DisableService { .. } => ActionKind::DisableService,
            ResponseAction::DisableScheduledTask { .. } => ActionKind::DisableScheduledTask,
        }
    }

    /// Process this action acts on, when it acts on one.
    pub fn process_target(&self) -> Option<&ProcessIdentity> {
        match self {
            ResponseAction::TerminateProcess { target }
            | ResponseAction::SuspendProcess { target } => Some(target),
            _ => None,
        }
    }

    /// Subject of the action, for logs and for the rate-limit bucket key.
    pub fn target_key(&self) -> String {
        match self {
            ResponseAction::TerminateProcess { target }
            | ResponseAction::SuspendProcess { target } => {
                format!("{}:{}", target.pid, target.image)
            }
            ResponseAction::IsolateHost => "host".to_string(),
            ResponseAction::BlockProcessNetwork { image } => image.display().to_string(),
            ResponseAction::QuarantineFile { path } => path.display().to_string(),
            ResponseAction::RevertRegistry { key, value } => match value {
                Some(value) => format!("{key}::{value}"),
                None => key.clone(),
            },
            ResponseAction::DisableService { name } => name.clone(),
            ResponseAction::DisableScheduledTask { path } => path.clone(),
        }
    }
}

/// Everything an alert offers for an action to act on, gathered once.
///
/// Most actions need something the alert names other than the process: a file
/// to quarantine, a registry value to revert, a service to disable. An action
/// whose subject the alert does not carry cannot run, and saying so is better
/// than acting on a substitute.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActionTargets {
    /// Process behind the alert. Present for nearly every event.
    pub process: Option<ProcessIdentity>,
    /// File the event touched.
    pub file: Option<PathBuf>,
    /// Registry key the event wrote.
    pub registry_key: Option<String>,
    /// Registry value name within that key, when the event named one.
    pub registry_value: Option<String>,
    /// Service the event created.
    pub service: Option<String>,
    /// Scheduled task the event registered.
    pub task: Option<String>,
}

impl ActionTargets {
    /// Build the action of this kind, or `None` when the alert names no
    /// subject for it.
    pub fn build(&self, kind: ActionKind) -> Option<ResponseAction> {
        match kind {
            ActionKind::TerminateProcess => Some(ResponseAction::TerminateProcess {
                target: self.process.clone()?,
            }),
            ActionKind::SuspendProcess => Some(ResponseAction::SuspendProcess {
                target: self.process.clone()?,
            }),
            // Isolation has no subject: it acts on the whole host.
            ActionKind::IsolateHost => Some(ResponseAction::IsolateHost),
            ActionKind::BlockProcessNetwork => Some(ResponseAction::BlockProcessNetwork {
                image: PathBuf::from(&self.process.as_ref()?.image),
            }),
            ActionKind::QuarantineFile => Some(ResponseAction::QuarantineFile {
                path: self.file.clone()?,
            }),
            ActionKind::RevertRegistry => Some(ResponseAction::RevertRegistry {
                key: self.registry_key.clone()?,
                value: self.registry_value.clone(),
            }),
            ActionKind::DisableService => Some(ResponseAction::DisableService {
                name: self.service.clone()?,
            }),
            ActionKind::DisableScheduledTask => Some(ResponseAction::DisableScheduledTask {
                path: self.task.clone()?,
            }),
        }
    }

    /// Whether this alert names a subject for the given action.
    pub fn has_target_for(&self, kind: ActionKind) -> bool {
        self.build(kind).is_some()
    }
}

/// Whether an action stopped the operation before it happened, or cleaned up
/// after it.
///
/// Every Ring 3 process, file, and registry action is
/// [`Enforcement::PostHoc`]: user mode sees the event only after the kernel has
/// already carried it out. Host isolation is the exception, because the WFP
/// filters it installs are evaluated in the kernel on every later connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enforcement {
    /// Acted after the operation completed.
    PostHoc,
    /// The operation itself was denied.
    Inline,
}

impl Enforcement {
    /// Audit spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Enforcement::PostHoc => "post_hoc",
            Enforcement::Inline => "inline",
        }
    }
}

impl fmt::Display for Enforcement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Proof that an action ran, and the handle a rollback would need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionReceipt {
    /// Action that ran.
    pub kind: ActionKind,
    /// Whether it denied the operation or cleaned up after it.
    pub enforcement: Enforcement,
    /// Executor that carried it out.
    pub executor: &'static str,
    /// What it acted on.
    pub target: String,
    /// Executor-specific detail, surfaced in the audit record.
    pub detail: Option<String>,
}

impl ActionReceipt {
    /// Receipt for an action that ran without extra detail.
    pub fn new(
        kind: ActionKind,
        enforcement: Enforcement,
        executor: &'static str,
        target: String,
    ) -> Self {
        Self {
            kind,
            enforcement,
            executor,
            target,
            detail: None,
        }
    }

    /// Attach executor-specific detail.
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

/// Why an action did not run, or did not finish.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ActionError {
    /// This executor cannot perform this kind of action at all.
    #[error("{kind} is not supported by this executor: {reason}")]
    Unsupported {
        kind: ActionKind,
        reason: &'static str,
    },
    /// The executor tried and the operating system refused.
    #[error("{kind} failed: {reason}")]
    Failed { kind: ActionKind, reason: String },
}

impl ActionError {
    /// Kind of the action that produced this error.
    pub fn kind(&self) -> ActionKind {
        match self {
            ActionError::Unsupported { kind, .. } | ActionError::Failed { kind, .. } => *kind,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_kind_index_is_dense_and_unique() {
        let mut seen = [false; ActionKind::COUNT];
        for kind in ActionKind::ALL {
            let index = kind.index();
            assert!(index < ActionKind::COUNT, "{kind} index out of range");
            assert!(!seen[index], "{kind} reuses index {index}");
            seen[index] = true;
        }
        assert!(seen.into_iter().all(|used| used));
    }

    #[test]
    fn action_kind_parses_its_own_spelling() {
        for kind in ActionKind::ALL {
            assert_eq!(ActionKind::parse(kind.as_str()), Some(kind));
            assert_eq!(ActionKind::parse(&kind.as_str().to_uppercase()), Some(kind));
        }
        assert_eq!(
            ActionKind::parse("  terminate_process "),
            Some(ActionKind::TerminateProcess)
        );
        assert_eq!(ActionKind::parse("format_the_disk"), None);
    }

    #[test]
    fn action_kind_round_trips_through_config_deserialization() {
        for kind in ActionKind::ALL {
            let parsed: ActionKind =
                serde_json::from_str(&format!("\"{}\"", kind.as_str())).expect("deserialize");
            assert_eq!(parsed, kind);
        }
    }
}
