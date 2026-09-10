//! A durable record of every action the engine considered.
//!
//! Response is the part of an EDR that changes the machine, so what it did has
//! to be reconstructable afterwards from the same stream an analyst already
//! reads. Every attempt is recorded, including the ones that did nothing:
//! a dry run, a suppression, and a failure are each as important to see as a
//! successful kill, and an audit trail that only shows successes cannot answer
//! why something was not stopped.
//!
//! Records go to the alert file as ECS documents with
//! `event.dataset: rustinel.response`, so a SIEM already tailing alerts picks
//! them up without new plumbing.

use super::action::{ActionKind, Enforcement};
use super::safety::SuppressionReason;
use crate::models::{AlertSeverity, DetectionEngine};

/// What became of one action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionOutcome {
    /// Performed successfully.
    Performed {
        executor: &'static str,
        enforcement: Enforcement,
        detail: Option<String>,
    },
    /// Selected, and not performed because prevention is off.
    DryRun,
    /// Selected, and refused by the safety layer.
    Suppressed { reason: SuppressionReason },
    /// Attempted, and the operating system refused.
    Failed { executor: &'static str, error: String },
}

impl ActionOutcome {
    /// ECS `event.outcome`.
    pub const fn event_outcome(&self) -> &'static str {
        match self {
            ActionOutcome::Performed { .. } => "success",
            ActionOutcome::Failed { .. } => "failure",
            ActionOutcome::DryRun | ActionOutcome::Suppressed { .. } => "unknown",
        }
    }

    /// Short decision word for `edr.response.decision`.
    pub const fn decision(&self) -> &'static str {
        match self {
            ActionOutcome::Performed { .. } => "performed",
            ActionOutcome::DryRun => "dry_run",
            ActionOutcome::Suppressed { .. } => "suppressed",
            ActionOutcome::Failed { .. } => "failed",
        }
    }

    /// Why, when there is a why.
    pub fn reason(&self) -> Option<String> {
        match self {
            ActionOutcome::Suppressed { reason } => Some(match reason.detail() {
                Some(detail) => format!("{reason}: {detail}"),
                None => reason.to_string(),
            }),
            ActionOutcome::Failed { error, .. } => Some(error.clone()),
            ActionOutcome::Performed { detail, .. } => detail.clone(),
            ActionOutcome::DryRun => None,
        }
    }

    /// Executor that handled it, where one was reached.
    pub const fn executor(&self) -> Option<&'static str> {
        match self {
            ActionOutcome::Performed { executor, .. } | ActionOutcome::Failed { executor, .. } => {
                Some(executor)
            }
            _ => None,
        }
    }

    /// Enforcement strength, where the action ran.
    pub const fn enforcement(&self) -> Option<Enforcement> {
        match self {
            ActionOutcome::Performed { enforcement, .. } => Some(*enforcement),
            _ => None,
        }
    }
}

/// One attempted action, with the detection that asked for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseAuditRecord {
    /// When the attempt happened, RFC 3339.
    pub timestamp: String,
    /// The action.
    pub action: ActionKind,
    /// What became of it.
    pub outcome: ActionOutcome,
    /// What it acted on.
    pub target: String,
    /// Policy rule that selected it.
    pub policy_rule: String,
    /// Detection rule name that triggered.
    pub rule_name: String,
    /// Detection rule ID, where the engine assigns one.
    pub rule_id: Option<String>,
    /// Detection severity.
    pub severity: AlertSeverity,
    /// Detection engine.
    pub engine: DetectionEngine,
    /// Target process ID, for process actions.
    pub pid: Option<u32>,
    /// Target image, for process actions.
    pub image: Option<String>,
    /// Whether the engine was in prevention mode at the time.
    pub prevention_enabled: bool,
}

impl ResponseAuditRecord {
    /// `edr.response.mode`: what the engine was configured to do.
    pub const fn mode(&self) -> &'static str {
        if self.prevention_enabled {
            "prevention"
        } else {
            "dry_run"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcomes_map_to_ecs_event_outcomes() {
        let performed = ActionOutcome::Performed {
            executor: "ring3",
            enforcement: Enforcement::PostHoc,
            detail: None,
        };
        assert_eq!(performed.event_outcome(), "success");
        assert_eq!(performed.decision(), "performed");
        assert_eq!(performed.executor(), Some("ring3"));

        let failed = ActionOutcome::Failed {
            executor: "ring3",
            error: "OpenProcess failed".to_string(),
        };
        assert_eq!(failed.event_outcome(), "failure");
        assert_eq!(failed.reason().as_deref(), Some("OpenProcess failed"));

        assert_eq!(ActionOutcome::DryRun.event_outcome(), "unknown");
        assert_eq!(ActionOutcome::DryRun.reason(), None);
    }

    #[test]
    fn suppression_reason_carries_its_detail() {
        let suppressed = ActionOutcome::Suppressed {
            reason: SuppressionReason::Unsupported("kernel driver is not installed"),
        };
        assert_eq!(
            suppressed.reason().as_deref(),
            Some("unsupported: kernel driver is not installed")
        );

        let rate_limited = ActionOutcome::Suppressed {
            reason: SuppressionReason::RateLimited,
        };
        assert_eq!(rate_limited.reason().as_deref(), Some("rate_limited"));
    }
}
