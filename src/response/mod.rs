//! Active response engine (optional prevention).
//!
//! Non-blocking alert intake with a background worker that can terminate
//! processes on critical alerts.
//!
//! The engine decides *whether* to act; an
//! [`ActionExecutor`](executor::ActionExecutor) decides *how*. Everything
//! Rustinel can do today runs in user mode and therefore acts after the
//! operation it is responding to has already completed. See [`executor`] for
//! what a kernel driver would change.

pub mod action;
pub mod audit;
pub mod executor;
pub mod policy;
pub mod safety;

#[cfg(test)]
pub(crate) mod tests_support;

use crate::alerts::AlertSink;
use crate::config::ResponseConfig;
use crate::models::{Alert, AlertSeverity, DetectionEngine, EventFields};
use crate::response::action::{ActionKind, ResponseAction};
use crate::response::audit::{ActionOutcome, ResponseAuditRecord};
use crate::response::executor::ActionExecutor;
use crate::response::policy::PreparedPolicy;
use crate::response::safety::SafetyGate;
use crate::utils::{
    hash_command_line, normalize_path_for_comparison, validate_process_identity, ProcessIdentity,
};
use arc_swap::ArcSwap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

const TARGET_RESPONSE: &str = "response";
static IDENTITY_MISMATCH_SKIPS: AtomicU64 = AtomicU64::new(0);

/// One alert's worth of work, queued for the worker.
///
/// The resolved actions travel with the task, but the worker revalidates them
/// against the configuration in force when it runs: a hot reload between
/// queueing and execution must be able to call an action off.
#[derive(Debug)]
struct ResponseTask {
    severity: AlertSeverity,
    rule_name: String,
    rule_id: Option<String>,
    engine: DetectionEngine,
    /// Policy rule that selected the actions, for logs and audit.
    policy_rule: String,
    /// Actions to attempt, already ordered.
    actions: Vec<ActionKind>,
    /// Whether the policy rule itself asked for a dry run.
    rule_dry_run: bool,
    pid: Option<u32>,
    image: Option<String>,
    identity: Option<ProcessIdentity>,
}

#[derive(Clone)]
pub struct ResponseEngine {
    config: Arc<ArcSwap<ResponseConfig>>,
    /// Compiled view of `config`, recompiled only when that pointer changes.
    policy: Arc<ArcSwap<PreparedPolicy>>,
    self_pid: u32,
    tx: mpsc::Sender<ResponseTask>,
    executor: Arc<dyn ActionExecutor>,
}

/// What the engine concluded about one alert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseDecision {
    /// Response is switched off.
    Disabled,
    /// Below `response.min_severity`, in the absence of policy rules.
    BelowSeverity {
        severity: AlertSeverity,
        min_severity: AlertSeverity,
    },
    /// Policy rules are configured and none of them covers this alert.
    NoPolicyMatch { severity: AlertSeverity },
    /// The alert names no process to act on.
    MissingPid,
    /// The target is the agent itself or a system PID.
    ProtectedPid { pid: u32 },
    /// The target's image is unknown, so it cannot be checked against the
    /// allowlist; acting blind is worse than not acting.
    MissingImage { pid: u32 },
    /// The target is allowlisted.
    Allowlisted { pid: u32, image: String },
    /// A rule matched but every action it named is switched off or
    /// unsupported.
    NoEnabledAction {
        pid: u32,
        image: String,
        policy_rule: String,
    },
    /// Actions selected, and reported rather than performed.
    DryRun {
        pid: u32,
        image: String,
        actions: Vec<ActionKind>,
        policy_rule: String,
    },
    /// Actions selected, and to be performed.
    Execute {
        pid: u32,
        image: String,
        actions: Vec<ActionKind>,
        policy_rule: String,
    },
}

impl ResponseDecision {
    /// Whether this decision reaches the worker at all.
    fn is_actionable(&self) -> bool {
        !matches!(
            self,
            ResponseDecision::Disabled
                | ResponseDecision::BelowSeverity { .. }
                | ResponseDecision::NoPolicyMatch { .. }
        )
    }

    /// Actions this decision selected, if any.
    fn actions(&self) -> &[ActionKind] {
        match self {
            ResponseDecision::DryRun { actions, .. } | ResponseDecision::Execute { actions, .. } => {
                actions
            }
            _ => &[],
        }
    }

    /// Policy rule that produced it, if one matched.
    fn policy_rule(&self) -> &str {
        match self {
            ResponseDecision::NoEnabledAction { policy_rule, .. }
            | ResponseDecision::DryRun { policy_rule, .. }
            | ResponseDecision::Execute { policy_rule, .. } => policy_rule,
            _ => "",
        }
    }
}

impl ResponseEngine {
    pub fn new(cfg: Arc<ArcSwap<ResponseConfig>>) -> (Self, tokio::task::JoinHandle<()>) {
        Self::with_options(cfg, executor::default_executor(), None)
    }

    /// Build an engine that acts through a specific executor.
    ///
    /// Tests substitute [`executor::MockExecutor`] to assert on what would
    /// have been done without touching a real process.
    pub fn with_executor(
        cfg: Arc<ArcSwap<ResponseConfig>>,
        executor: Arc<dyn ActionExecutor>,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        Self::with_options(cfg, executor, None)
    }

    /// Build an engine with an audit destination.
    ///
    /// The live pipeline passes its alert sink here so every attempted action
    /// lands in the same stream as the detections that asked for it.
    pub fn with_options(
        cfg: Arc<ArcSwap<ResponseConfig>>,
        executor: Arc<dyn ActionExecutor>,
        audit: Option<AlertSink>,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        let channel_capacity = cfg.load().channel_capacity;
        let (tx, mut rx) = mpsc::channel(channel_capacity);
        let self_pid = std::process::id();
        let worker_cfg = cfg.clone();
        let worker_executor = executor.clone();

        let handle = tokio::spawn(async move {
            let initial = worker_cfg.load();
            debug!(
                target: TARGET_RESPONSE,
                enabled = initial.enabled,
                prevention_enabled = initial.prevention_enabled,
                min_severity = %initial.min_severity,
                executor = worker_executor.name(),
                "Active response worker started"
            );

            let mut policy = PreparedPolicy::from_raw(&worker_cfg.load());
            let mut safety = SafetyGate::new();

            while let Some(task) = rx.recv().await {
                let current_raw = worker_cfg.load();
                policy.refresh_if_changed(&current_raw);

                if !policy.enabled {
                    continue;
                }

                handle_task(
                    task,
                    &policy,
                    &mut safety,
                    self_pid,
                    worker_executor.as_ref(),
                    audit.as_ref(),
                );
            }

            debug!(target: TARGET_RESPONSE, "Active response worker shutting down");
        });

        let policy = Arc::new(ArcSwap::from(Arc::new(PreparedPolicy::from_raw(
            &cfg.load_full(),
        ))));

        (
            Self {
                config: cfg,
                policy,
                self_pid,
                tx,
                executor,
            },
            handle,
        )
    }

    /// Executor this engine acts through.
    pub fn executor(&self) -> &Arc<dyn ActionExecutor> {
        &self.executor
    }

    pub fn handle_alert(&self, alert: &Alert) {
        let decision = self.decision_for_alert(alert);
        if !decision.is_actionable() {
            return;
        }

        let (pid, image) = extract_process_info(alert);
        let policy = self.current_policy();
        let rule_dry_run = policy
            .match_alert(alert)
            .is_some_and(|rule| rule.dry_run);

        let task = ResponseTask {
            severity: effective_alert_severity(alert),
            rule_name: alert.rule_name.clone(),
            rule_id: alert.rule_id.clone(),
            engine: alert.engine,
            policy_rule: decision.policy_rule().to_string(),
            actions: decision.actions().to_vec(),
            rule_dry_run,
            pid,
            image,
            identity: extract_process_identity(alert),
        };

        if let Err(err) =
            crate::telemetry::try_send(crate::telemetry::ChannelId::ActiveResponse, &self.tx, task)
        {
            warn!(
                target: TARGET_RESPONSE,
                error = %err,
                "Active response queue full, dropping task"
            );
        }
    }

    pub fn decision_for_alert(&self, alert: &Alert) -> ResponseDecision {
        decide_response(
            &self.current_policy(),
            alert,
            self.self_pid,
            self.executor.as_ref(),
        )
    }

    /// The compiled policy for the configuration in force right now.
    ///
    /// Recompiles only when the configuration pointer has changed, so the
    /// steady state is a pointer comparison rather than a parse.
    fn current_policy(&self) -> Arc<PreparedPolicy> {
        let current_cfg = self.config.load_full();
        let cached = self.policy.load_full();
        if cached.matches_source(&current_cfg) {
            return cached;
        }

        let fresh = Arc::new(PreparedPolicy::from_raw(&current_cfg));
        self.policy.store(Arc::clone(&fresh));
        fresh
    }
}

fn effective_alert_severity(alert: &Alert) -> AlertSeverity {
    match alert.engine {
        DetectionEngine::Yara => AlertSeverity::Critical,
        DetectionEngine::Sigma | DetectionEngine::Ioc => alert.severity,
    }
}

/// Decide what, if anything, to do about an alert.
///
/// Pure and side-effect free: the rate limiter and the cooldown are consulted
/// by the worker at execution time, not here, so asking what would happen
/// never changes what will.
fn decide_response(
    policy: &PreparedPolicy,
    alert: &Alert,
    self_pid: u32,
    executor: &dyn ActionExecutor,
) -> ResponseDecision {
    if !policy.enabled {
        return ResponseDecision::Disabled;
    }

    let severity = effective_alert_severity(alert);

    let Some(rule) = policy.match_alert(alert) else {
        // In legacy mode the only rule is the severity floor, so saying so is
        // more useful than saying no rule matched.
        return if policy.legacy_mode {
            ResponseDecision::BelowSeverity {
                severity,
                min_severity: policy.min_severity,
            }
        } else {
            ResponseDecision::NoPolicyMatch { severity }
        };
    };

    let (pid, image) = extract_process_info(alert);
    let target = match check_target(pid, image.as_deref(), self_pid, policy) {
        Ok(target) => target,
        Err(decision) => return decision,
    };

    // An action must be selected by the rule, switched on in configuration,
    // and something the executor can actually do.
    let actions: Vec<ActionKind> = rule
        .actions
        .iter()
        .copied()
        .filter(|kind| policy.action_enabled(*kind) && executor.capabilities().supports(*kind))
        .collect();

    if actions.is_empty() {
        return ResponseDecision::NoEnabledAction {
            pid: target.pid,
            image: target.image,
            policy_rule: rule.name.clone(),
        };
    }

    // A rule may ask for a dry run, but it can never turn prevention on.
    if !policy.prevention_enabled || rule.dry_run {
        return ResponseDecision::DryRun {
            pid: target.pid,
            image: target.image,
            actions,
            policy_rule: rule.name.clone(),
        };
    }

    ResponseDecision::Execute {
        pid: target.pid,
        image: target.image,
        actions,
        policy_rule: rule.name.clone(),
    }
}

/// A process the engine is allowed to act on.
struct Target {
    pid: u32,
    image: String,
}

/// Check the target itself, independent of which action is being considered.
fn check_target(
    pid: Option<u32>,
    image: Option<&str>,
    self_pid: u32,
    policy: &PreparedPolicy,
) -> Result<Target, ResponseDecision> {
    let Some(pid) = pid else {
        return Err(ResponseDecision::MissingPid);
    };

    if pid <= 4 || pid == self_pid {
        return Err(ResponseDecision::ProtectedPid { pid });
    }

    let Some(image) = image else {
        return Err(ResponseDecision::MissingImage { pid });
    };

    if is_allowlisted(image, &policy.allowlist_images, &policy.allowlist_paths) {
        return Err(ResponseDecision::Allowlisted {
            pid,
            image: image.to_string(),
        });
    }

    Ok(Target {
        pid,
        image: image.to_string(),
    })
}

/// Perform one task: revalidate, then run each action in turn.
fn handle_task(
    task: ResponseTask,
    policy: &PreparedPolicy,
    safety: &mut SafetyGate,
    self_pid: u32,
    executor: &dyn ActionExecutor,
    audit: Option<&AlertSink>,
) {
    // The configuration may have changed since this task was queued, so the
    // target is checked again against what is in force now.
    let target = match check_target(task.pid, task.image.as_deref(), self_pid, policy) {
        Ok(target) => target,
        Err(decision) => {
            log_skipped_target(&task, &decision);
            return;
        }
    };

    if task.actions.is_empty() {
        info!(
            target: TARGET_RESPONSE,
            pid = target.pid,
            image = %target.image,
            rule = %task.rule_name,
            engine = ?task.engine,
            severity = ?task.severity,
            "Active response skipped: no enabled action"
        );
        return;
    }

    // One identity check covers every action in the set: if the PID was
    // recycled, nothing in the set is safe to run against it.
    let expected_identity = task.identity.clone().unwrap_or_else(|| ProcessIdentity {
        pid: target.pid,
        image: target.image.clone(),
        start_time: None,
        command_line_hash: None,
    });

    let current_identity = match validate_process_identity(&expected_identity) {
        Ok(identity) => identity,
        Err(err) => {
            let skipped_identity_mismatch_count =
                IDENTITY_MISMATCH_SKIPS.fetch_add(1, Ordering::Relaxed) + 1;
            warn!(
                target: TARGET_RESPONSE,
                pid = target.pid,
                image = %target.image,
                rule = %task.rule_name,
                engine = ?task.engine,
                severity = ?task.severity,
                skipped_identity_mismatch_count,
                reason = %err,
                "Active response skipped: process identity mismatch"
            );
            return;
        }
    };

    // A rule dry run tightens; it cannot loosen a global dry run.
    let dry_run = !policy.prevention_enabled || task.rule_dry_run;

    for kind in ordered_actions(&task.actions) {
        let action = match build_action(kind, &current_identity) {
            Some(action) => action,
            None => continue,
        };

        let now = Instant::now();
        let outcome = match safety.check(&action, policy, executor, now) {
            Err(reason) => ActionOutcome::Suppressed { reason },
            Ok(()) if dry_run => ActionOutcome::DryRun,
            Ok(()) => match executor.execute(&action) {
                Ok(receipt) => {
                    safety.commit(&action, now);
                    ActionOutcome::Performed {
                        executor: receipt.executor,
                        enforcement: receipt.enforcement,
                        detail: receipt.detail,
                    }
                }
                Err(err) => ActionOutcome::Failed {
                    executor: executor.name(),
                    error: err.to_string(),
                },
            },
        };

        log_outcome(&task, &target, kind, &outcome);

        if let Some(sink) = audit.filter(|_| policy.audit_to_alerts) {
            sink.write_response(&ResponseAuditRecord {
                timestamp: chrono::Utc::now().to_rfc3339(),
                action: kind,
                outcome,
                target: action.target_key(),
                policy_rule: task.policy_rule.clone(),
                rule_name: task.rule_name.clone(),
                rule_id: task.rule_id.clone(),
                severity: task.severity,
                engine: task.engine,
                pid: Some(target.pid),
                image: Some(target.image.clone()),
                prevention_enabled: policy.prevention_enabled,
            });
        }

        // Once the process is gone, later actions against it are meaningless.
        if kind == ActionKind::TerminateProcess && !dry_run {
            break;
        }
    }
}

/// Order actions so that each one still makes sense after the previous.
///
/// Freezing precedes killing, so a rule asking for both preserves the process
/// long enough for the containment steps between them to run.
fn ordered_actions(actions: &[ActionKind]) -> Vec<ActionKind> {
    let mut ordered = actions.to_vec();
    ordered.sort_by_key(|kind| match kind {
        ActionKind::SuspendProcess => 0,
        ActionKind::IsolateHost => 1,
        ActionKind::BlockProcessNetwork => 2,
        ActionKind::QuarantineFile => 3,
        ActionKind::RevertRegistry => 4,
        ActionKind::DisableService => 5,
        ActionKind::DisableScheduledTask => 6,
        ActionKind::TerminateProcess => 7,
    });
    ordered
}

/// Build the action payload for one kind.
///
/// Only the process actions can be built from an alert alone; the rest need
/// context the engine does not carry yet and are filtered out well before
/// here by the executor capability check.
fn build_action(kind: ActionKind, identity: &ProcessIdentity) -> Option<ResponseAction> {
    match kind {
        ActionKind::TerminateProcess => Some(ResponseAction::TerminateProcess {
            target: identity.clone(),
        }),
        ActionKind::SuspendProcess => Some(ResponseAction::SuspendProcess {
            target: identity.clone(),
        }),
        _ => None,
    }
}

/// Log a task that never reached an action.
fn log_skipped_target(task: &ResponseTask, decision: &ResponseDecision) {
    match decision {
        ResponseDecision::MissingPid => warn!(
            target: TARGET_RESPONSE,
            rule = %task.rule_name,
            engine = ?task.engine,
            severity = ?task.severity,
            "Active response skipped: missing pid"
        ),
        ResponseDecision::ProtectedPid { pid } => info!(
            target: TARGET_RESPONSE,
            pid = *pid,
            rule = %task.rule_name,
            engine = ?task.engine,
            severity = ?task.severity,
            "Active response skipped: protected pid"
        ),
        ResponseDecision::MissingImage { pid } => warn!(
            target: TARGET_RESPONSE,
            pid = *pid,
            rule = %task.rule_name,
            engine = ?task.engine,
            severity = ?task.severity,
            "Active response skipped: missing image"
        ),
        ResponseDecision::Allowlisted { pid, image } => info!(
            target: TARGET_RESPONSE,
            pid = *pid,
            image = %image,
            rule = %task.rule_name,
            engine = ?task.engine,
            severity = ?task.severity,
            "Active response skipped: allowlisted"
        ),
        other => debug!(
            target: TARGET_RESPONSE,
            rule = %task.rule_name,
            decision = ?other,
            "Active response took no action"
        ),
    }
}

/// Log what became of one action.
fn log_outcome(
    task: &ResponseTask,
    target: &Target,
    kind: ActionKind,
    outcome: &ActionOutcome,
) {
    match outcome {
        ActionOutcome::Performed {
            executor,
            enforcement,
            ..
        } => info!(
            target: TARGET_RESPONSE,
            pid = target.pid,
            image = %target.image,
            action = %kind,
            policy_rule = %task.policy_rule,
            rule = %task.rule_name,
            engine = ?task.engine,
            severity = ?task.severity,
            executor = *executor,
            enforcement = %enforcement,
            "Active response performed action"
        ),
        ActionOutcome::DryRun => info!(
            target: TARGET_RESPONSE,
            pid = target.pid,
            image = %target.image,
            action = %kind,
            policy_rule = %task.policy_rule,
            rule = %task.rule_name,
            engine = ?task.engine,
            severity = ?task.severity,
            dry_run = true,
            "Active response would perform action"
        ),
        ActionOutcome::Suppressed { reason } => info!(
            target: TARGET_RESPONSE,
            pid = target.pid,
            image = %target.image,
            action = %kind,
            policy_rule = %task.policy_rule,
            rule = %task.rule_name,
            engine = ?task.engine,
            severity = ?task.severity,
            reason = %reason,
            "Active response suppressed action"
        ),
        ActionOutcome::Failed { executor, error } => error!(
            target: TARGET_RESPONSE,
            pid = target.pid,
            image = %target.image,
            action = %kind,
            policy_rule = %task.policy_rule,
            rule = %task.rule_name,
            engine = ?task.engine,
            severity = ?task.severity,
            executor = *executor,
            error = %error,
            "Active response failed to perform action"
        ),
    }
}

fn extract_process_info(alert: &Alert) -> (Option<u32>, Option<String>) {
    let mut pid = None;
    let mut image = None;

    match &alert.event.fields {
        EventFields::ProcessCreation(f) => {
            pid = parse_pid(f.process_id.as_deref());
            image = f.image.clone();
        }
        EventFields::FileEvent(f) => {
            pid = parse_pid(f.process_id.as_deref());
            image = f.image.clone();
        }
        EventFields::RegistryEvent(f) => {
            pid = parse_pid(f.process_id.as_deref());
            image = f.image.clone();
        }
        EventFields::NetworkConnection(f) => {
            pid = parse_pid(f.process_id.as_deref());
            image = f.image.clone();
        }
        EventFields::DnsQuery(f) => {
            pid = parse_pid(f.process_id.as_deref());
            image = f.image.clone();
        }
        EventFields::ImageLoad(f) => {
            pid = parse_pid(f.process_id.as_deref());
            image = f.image.clone();
        }
        EventFields::PowerShellScript(f) => {
            pid = parse_pid(f.process_id.as_deref());
            image = f.image.clone();
        }
        EventFields::PowerShellModule(f) => {
            pid = parse_pid(f.process_id.as_deref());
            image = f.image.clone();
        }
        EventFields::WmiEvent(f) => {
            pid = parse_pid(f.process_id.as_deref());
            image = f.image.clone();
        }
        EventFields::ServiceCreation(f) => {
            pid = parse_pid(f.process_id.as_deref());
            image = f.image.clone();
        }
        EventFields::TaskCreation(f) => {
            pid = parse_pid(f.process_id.as_deref());
            image = f.image.clone();
        }
        EventFields::RemoteThread(f) => {
            if let Some(target_pid) = parse_pid(f.target_process_id.as_deref()) {
                pid = Some(target_pid);
                image = f.target_image.clone();
            } else {
                pid = parse_pid(f.source_process_id.as_deref());
                image = f.source_image.clone();
            }
        }
        EventFields::SecurityAudit(f) => {
            pid = f.process_id();
            image = f.get("ProcessName").map(str::to_string);
        }
        EventFields::Generic(_) => {}
    }

    if pid.is_none() {
        pid = alert
            .event
            .process_context
            .as_ref()
            .and_then(|ctx| parse_pid(ctx.process_id.as_deref()));
    }

    if image.is_none() {
        image = alert
            .event
            .process_context
            .as_ref()
            .and_then(|ctx| ctx.image.clone());
    }

    (pid, image)
}

fn extract_process_identity(alert: &Alert) -> Option<ProcessIdentity> {
    let (pid, image, start_time, command_line) = match &alert.event.fields {
        EventFields::ProcessCreation(f) => (
            parse_pid(f.process_id.as_deref()),
            f.image.clone(),
            f.process_start_time,
            f.command_line.as_deref(),
        ),
        _ => (
            alert
                .event
                .process_context
                .as_ref()
                .and_then(|ctx| parse_pid(ctx.process_id.as_deref())),
            alert
                .event
                .process_context
                .as_ref()
                .and_then(|ctx| ctx.image.clone()),
            alert
                .event
                .process_context
                .as_ref()
                .and_then(|ctx| ctx.process_start_time),
            alert
                .event
                .process_context
                .as_ref()
                .and_then(|ctx| ctx.command_line.as_deref()),
        ),
    };

    Some(ProcessIdentity {
        pid: pid?,
        image: image?,
        start_time,
        command_line_hash: command_line.map(hash_command_line),
    })
}

fn parse_pid(value: Option<&str>) -> Option<u32> {
    let value = value?.trim();
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16).ok()
    } else {
        value.parse::<u32>().ok()
    }
}

fn normalize_allowlist_paths(values: &[String]) -> Vec<String> {
    crate::utils::path_allowlist::PathAllowlistPolicy::ResponseDirectory.normalize_prefixes(values)
}

fn normalize_allowlist_images(values: &[String]) -> Vec<String> {
    values
        .iter()
        .filter(|v| !v.trim().is_empty())
        .map(|value| normalize_path_for_comparison(value))
        .collect()
}

fn image_basename(path: &str) -> &str {
    let path = path.trim_end_matches('\\').trim_end_matches('/');
    let separator = path.rfind('\\').or_else(|| path.rfind('/'));
    match separator {
        Some(idx) => &path[idx + 1..],
        None => path,
    }
}

fn is_allowlisted(image: &str, allowlist_images: &[String], allowlist_paths: &[String]) -> bool {
    let normalized = normalize_path_for_comparison(image);

    if crate::utils::path_allowlist::matches_normalized(&normalized, allowlist_paths) {
        return true;
    }

    let basename = image_basename(&normalized);
    for entry in allowlist_images {
        if entry.contains('\\') || entry.contains('/') {
            if normalized == *entry {
                return true;
            }
        } else if basename == entry {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        Alert, AlertSeverity, DetectionEngine, EventCategory, EventFields, NormalizedEvent,
        ProcessCreationFields,
    };
    use crate::sensor::Platform;
    use std::{
        io::{self, Write},
        sync::{Arc, Mutex},
    };
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone, Default)]
    struct LogBuffer(Arc<Mutex<Vec<u8>>>);

    struct LogWriter(LogBuffer);

    impl Write for LogWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                 .0
                .lock()
                .expect("log buffer lock")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for LogBuffer {
        type Writer = LogWriter;

        fn make_writer(&'a self) -> Self::Writer {
            LogWriter(self.clone())
        }
    }

    fn test_process_alert(pid: Option<&str>, image: Option<&str>) -> Alert {
        Alert {
            severity: AlertSeverity::Low,
            rule_name: "Test process rule".to_string(),
            rule_description: None,
            rule_id: None,
            engine: DetectionEngine::Sigma,
            tags: Vec::new(),
            event: NormalizedEvent {
                timestamp: "2026-02-03T00:00:00Z".to_string(),
                source_seq: None,
                ingest_seq: 0,
                platform: Platform::Linux,
                provider: "test".to_string(),
                category: EventCategory::Process,
                event_id: 1,
                event_id_string: "1".to_string(),
                opcode: 1,
                fields: EventFields::ProcessCreation(ProcessCreationFields {
                    image: image.map(str::to_string),
                    image_source: None,
                    image_truncated: None,
                    process_id: pid.map(str::to_string),
                    process_start_time: None,
                    command_line: None,
                    original_file_name: None,
                    product: None,
                    description: None,
                    company: None,
                    file_version: None,
                    target_image: None,
                    parent_process_id: None,
                    parent_image: None,
                    parent_command_line: None,
                    current_directory: None,
                    integrity_level: None,
                    user: None,
                }),
                provenance: Default::default(),
                process_context: None,
            },
            match_details: None,
        }
    }

    #[test]
    fn test_parse_pid_decimal() {
        assert_eq!(parse_pid(Some("1234")), Some(1234));
    }

    #[test]
    fn test_parse_pid_hex() {
        assert_eq!(parse_pid(Some("0x4D2")), Some(1234));
    }

    #[test]
    fn test_allowlist_image_basename() {
        let allowlist_images = vec!["cmd.exe".to_string()];
        let allowlist_paths = vec![];
        assert!(is_allowlisted(
            "C:\\Windows\\System32\\cmd.exe",
            &normalize_allowlist_images(&allowlist_images),
            &normalize_allowlist_paths(&allowlist_paths),
        ));
    }

    #[test]
    fn test_allowlist_path_prefix() {
        #[cfg(windows)]
        {
            let allowlist_paths = vec!["C:\\Windows\\".to_string()];
            let allowlist_images = vec![];
            assert!(is_allowlisted(
                "C:\\Windows\\System32\\svchost.exe",
                &normalize_allowlist_images(&allowlist_images),
                &normalize_allowlist_paths(&allowlist_paths),
            ));
        }
        #[cfg(not(windows))]
        {
            let allowlist_paths = vec!["/usr/bin/".to_string()];
            let allowlist_images = vec![];
            assert!(is_allowlisted(
                "/usr/bin/bash",
                &normalize_allowlist_images(&allowlist_images),
                &normalize_allowlist_paths(&allowlist_paths),
            ));
        }
    }

    #[test]
    fn handle_alert_logs_allowlisted_decision() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        let logs = LogBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(logs.clone())
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            rt.block_on(async {
                let cfg = std::sync::Arc::new(arc_swap::ArcSwap::from(std::sync::Arc::new(
                    ResponseConfig {
                        enabled: true,
                        prevention_enabled: true,
                        min_severity: "low".to_string(),
                        channel_capacity: 4,
                        allowlist_images: vec![],
                        allowlist_paths: vec!["/usr/bin/".to_string()],
                        ..ResponseConfig::default()
                    },
                )));
                let (engine, worker) = ResponseEngine::new(cfg);

                engine.handle_alert(&test_process_alert(Some("4242"), Some("/usr/bin/sleep")));
                drop(engine);
                worker.await.expect("response worker");
            });
        });

        let output =
            String::from_utf8(logs.0.lock().expect("log buffer lock").clone()).expect("UTF-8 logs");
        assert!(
            output.contains("Active response skipped: allowlisted"),
            "expected allowlist decision in logs, got: {output}"
        );
        assert!(output.contains("pid=4242"));
        assert!(output.contains("image=/usr/bin/sleep"));
    }

    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    fn validate_process_identity_accepts_current_process() {
        let pid = std::process::id();
        let identity = crate::utils::query_process_identity(pid).expect("current process identity");
        assert!(validate_process_identity(&identity).is_ok());
    }

    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    fn validate_process_identity_rejects_image_mismatch() {
        let pid = std::process::id();
        let mut identity =
            crate::utils::query_process_identity(pid).expect("current process identity");
        identity.image = if cfg!(windows) {
            r"C:\definitely-not-rustinel.exe".to_string()
        } else {
            "/definitely/not/rustinel".to_string()
        };

        assert!(validate_process_identity(&identity).is_err());
    }

    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    fn validate_process_identity_rejects_start_time_mismatch_when_available() {
        let pid = std::process::id();
        let mut identity =
            crate::utils::query_process_identity(pid).expect("current process identity");
        let Some(start_time) = identity.start_time else {
            return;
        };
        identity.start_time = Some(start_time.saturating_add(1));

        assert!(validate_process_identity(&identity).is_err());
    }

    #[test]
    fn test_extract_process_info() {
        let alert = test_process_alert(Some("4242"), Some("C:\\Temp\\evil.exe"));

        let (pid, image) = extract_process_info(&alert);
        assert_eq!(pid, Some(4242));
        assert_eq!(image, Some("C:\\Temp\\evil.exe".to_string()));
    }
}
