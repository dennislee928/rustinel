//! Response policy integration tests.
//!
//! These drive the whole engine — policy matching, identity revalidation, the
//! safety gate, the executor, and the audit record — through a mock executor.
//! They assert on what *would* be done to a machine without doing anything to
//! this one: the target is a real, harmless child process, so the identity
//! revalidation the engine performs before acting is exercised honestly, while
//! the executor only records.
//!
//! ```sh
//! cargo test --test response_policy
//! ```

use rustinel::{
    alerts::AlertSink,
    config::{ActionToggle, ResponseActionsConfig, ResponseConfig, ResponseRule},
    models::{
        Alert, AlertSeverity, DetectionEngine, EventCategory, EventFields, NormalizedEvent,
        ProcessCreationFields,
    },
    response::{
        action::ActionKind,
        executor::{ActionExecutor, Capabilities, MockExecutor},
        ResponseDecision, ResponseEngine,
    },
    sensor::Platform,
    utils::{query_process_identity, ProcessIdentity},
};
use serde_json::Value;
use std::process::Stdio;
use std::sync::Arc;

/// A real child process to aim the engine at.
///
/// The engine revalidates a target's identity immediately before acting, so a
/// made-up PID would be rejected before any action ran and these tests would
/// pass for the wrong reason. This spawns something harmless and long-lived,
/// reads back the identity the engine will see, and kills it on drop.
struct Target {
    child: std::process::Child,
    identity: ProcessIdentity,
}

impl Target {
    fn spawn() -> Self {
        let mut command = if cfg!(windows) {
            let mut command = std::process::Command::new("ping");
            command.args(["-n", "30", "127.0.0.1"]);
            command
        } else {
            let mut command = std::process::Command::new("sleep");
            command.arg("30");
            command
        };

        let mut child = command
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn target process");

        // The image path becomes readable a moment after spawn.
        for _ in 0..50 {
            if let Some(identity) = query_process_identity(child.id()) {
                return Self { child, identity };
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }

        // Reap before failing; `Drop` never runs on this path.
        let _ = child.kill();
        let _ = child.wait();
        panic!("could not read the identity of the spawned target process");
    }

    fn pid(&self) -> u32 {
        self.identity.pid
    }

    fn image(&self) -> &str {
        &self.identity.image
    }

    fn basename(&self) -> String {
        self.image()
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(self.image())
            .to_string()
    }
}

impl Drop for Target {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn alert_for(
    target: &Target,
    severity: AlertSeverity,
    engine: DetectionEngine,
    tags: &[&str],
) -> Alert {
    Alert {
        severity,
        rule_name: "Suspicious LSASS Access".to_string(),
        rule_description: None,
        rule_id: Some("sigma::abc-123".to_string()),
        engine,
        tags: tags.iter().map(|tag| tag.to_string()).collect(),
        event: NormalizedEvent {
            timestamp: "2026-09-10T00:00:00Z".to_string(),
            source_seq: None,
            ingest_seq: 0,
            platform: Platform::current(),
            provider: "test".to_string(),
            category: EventCategory::Process,
            event_id: 1,
            event_id_string: "1".to_string(),
            opcode: 1,
            fields: EventFields::ProcessCreation(ProcessCreationFields {
                image: Some(target.image().to_string()),
                image_source: None,
                image_truncated: None,
                process_id: Some(target.pid().to_string()),
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

fn critical_sigma_alert(target: &Target, tags: &[&str]) -> Alert {
    alert_for(
        target,
        AlertSeverity::Critical,
        DetectionEngine::Sigma,
        tags,
    )
}

fn rule(actions: &[&str]) -> ResponseRule {
    ResponseRule {
        actions: actions.iter().map(|a| a.to_string()).collect(),
        ..ResponseRule::default()
    }
}

fn shared(cfg: ResponseConfig) -> Arc<arc_swap::ArcSwap<ResponseConfig>> {
    Arc::new(arc_swap::ArcSwap::from(Arc::new(cfg)))
}

/// Feed one alert through a full engine and return the decision plus what the
/// executor was actually asked to do.
///
/// Dropping the engine closes the queue, so awaiting the worker drains every
/// pending task before returning: no sleeping, no flake.
fn run(cfg: ResponseConfig, alert: &Alert) -> (ResponseDecision, Vec<ActionKind>) {
    run_with(cfg, alert, MockExecutor::new(), None)
}

fn run_with(
    cfg: ResponseConfig,
    alert: &Alert,
    mock: MockExecutor,
    audit: Option<AlertSink>,
) -> (ResponseDecision, Vec<ActionKind>) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    runtime.block_on(async {
        // Keep a typed handle to the mock so the recorded calls can be read
        // back once the worker has finished with it.
        let mock = Arc::new(mock);
        let executor: Arc<dyn ActionExecutor> = Arc::clone(&mock) as Arc<dyn ActionExecutor>;

        let (engine, worker) = ResponseEngine::with_options(shared(cfg), executor, audit);
        let decision = engine.decision_for_alert(alert);
        engine.handle_alert(alert);
        drop(engine);
        worker.await.expect("response worker");

        (decision, mock.call_kinds())
    })
}

/// Read the audit records a run produced.
fn audit_lines(output: &std::path::Path) -> Vec<Value> {
    std::fs::read_to_string(output)
        .expect("read audit output")
        .lines()
        .map(|line| serde_json::from_str(line).expect("valid JSON audit line"))
        .collect()
}

#[test]
fn a_configuration_without_rules_behaves_as_it_did_before_policy_existed() {
    let target = Target::spawn();
    let cfg = ResponseConfig {
        enabled: true,
        prevention_enabled: true,
        min_severity: "critical".to_string(),
        ..ResponseConfig::default()
    };

    let (decision, performed) = run(cfg.clone(), &critical_sigma_alert(&target, &[]));
    assert!(
        matches!(decision, ResponseDecision::Execute { ref actions, .. }
            if actions == &[ActionKind::TerminateProcess]),
        "legacy mode must still select exactly one termination, got {decision:?}"
    );
    assert_eq!(performed, vec![ActionKind::TerminateProcess]);

    let (decision, performed) = run(
        cfg,
        &alert_for(&target, AlertSeverity::High, DetectionEngine::Sigma, &[]),
    );
    assert!(matches!(decision, ResponseDecision::BelowSeverity { .. }));
    assert!(
        performed.is_empty(),
        "an alert below min_severity must not reach the executor"
    );
}

#[test]
fn a_rule_selects_actions_by_technique_tag() {
    let target = Target::spawn();
    let cfg = ResponseConfig {
        enabled: true,
        prevention_enabled: true,
        actions: ResponseActionsConfig {
            suspend_process: ActionToggle::on(),
            ..Default::default()
        },
        rules: vec![ResponseRule {
            name: Some("credential-access".to_string()),
            tags: vec!["attack.t1003*".to_string()],
            ..rule(&["suspend_process"])
        }],
        ..ResponseConfig::default()
    };

    let (decision, performed) = run(
        cfg.clone(),
        &critical_sigma_alert(&target, &["attack.t1003.001"]),
    );
    assert!(
        matches!(decision, ResponseDecision::Execute { ref policy_rule, .. }
            if policy_rule == "credential-access"),
        "got {decision:?}"
    );
    assert_eq!(performed, vec![ActionKind::SuspendProcess]);

    let (decision, performed) = run(cfg, &critical_sigma_alert(&target, &["attack.t1055"]));
    assert!(
        matches!(decision, ResponseDecision::NoPolicyMatch { .. }),
        "an unmatched tag must fall through, got {decision:?}"
    );
    assert!(performed.is_empty());
}

#[test]
fn suspension_is_ordered_before_termination() {
    let target = Target::spawn();
    let cfg = ResponseConfig {
        enabled: true,
        prevention_enabled: true,
        actions: ResponseActionsConfig {
            suspend_process: ActionToggle::on(),
            ..Default::default()
        },
        // Deliberately the wrong way round: the engine must reorder so the
        // process is still alive when it is frozen.
        rules: vec![rule(&["terminate_process", "suspend_process"])],
        ..ResponseConfig::default()
    };

    let (_, performed) = run(cfg, &critical_sigma_alert(&target, &[]));
    assert_eq!(
        performed,
        vec![ActionKind::SuspendProcess, ActionKind::TerminateProcess]
    );
}

#[test]
fn prevention_disabled_selects_actions_but_performs_none() {
    let target = Target::spawn();
    let cfg = ResponseConfig {
        enabled: true,
        prevention_enabled: false,
        rules: vec![rule(&["terminate_process"])],
        ..ResponseConfig::default()
    };

    let (decision, performed) = run(cfg, &critical_sigma_alert(&target, &[]));
    assert!(
        matches!(decision, ResponseDecision::DryRun { ref actions, .. }
            if actions == &[ActionKind::TerminateProcess]),
        "got {decision:?}"
    );
    assert!(
        performed.is_empty(),
        "a dry run must never reach the executor"
    );
}

#[test]
fn a_rule_can_tighten_to_a_dry_run_but_never_loosen_to_prevention() {
    let target = Target::spawn();
    let tightened = ResponseConfig {
        enabled: true,
        prevention_enabled: true,
        rules: vec![ResponseRule {
            dry_run: true,
            ..rule(&["terminate_process"])
        }],
        ..ResponseConfig::default()
    };

    let (decision, performed) = run(tightened, &critical_sigma_alert(&target, &[]));
    assert!(matches!(decision, ResponseDecision::DryRun { .. }));
    assert!(performed.is_empty());

    // The reverse is not expressible: with prevention off, dry_run = false
    // still yields a dry run.
    let loosened = ResponseConfig {
        enabled: true,
        prevention_enabled: false,
        rules: vec![ResponseRule {
            dry_run: false,
            ..rule(&["terminate_process"])
        }],
        ..ResponseConfig::default()
    };

    let (decision, performed) = run(loosened, &critical_sigma_alert(&target, &[]));
    assert!(matches!(decision, ResponseDecision::DryRun { .. }));
    assert!(performed.is_empty());
}

#[test]
fn an_action_switched_off_in_configuration_is_never_selected() {
    let target = Target::spawn();
    let cfg = ResponseConfig {
        enabled: true,
        prevention_enabled: true,
        actions: ResponseActionsConfig {
            terminate_process: ActionToggle::off(),
            ..Default::default()
        },
        rules: vec![rule(&["terminate_process"])],
        ..ResponseConfig::default()
    };

    let (decision, performed) = run(cfg, &critical_sigma_alert(&target, &[]));
    assert!(
        matches!(decision, ResponseDecision::NoEnabledAction { .. }),
        "got {decision:?}"
    );
    assert!(performed.is_empty());
}

#[test]
fn an_action_the_executor_cannot_perform_is_never_selected() {
    let target = Target::spawn();
    let cfg = ResponseConfig {
        enabled: true,
        prevention_enabled: true,
        rules: vec![rule(&["terminate_process"])],
        ..ResponseConfig::default()
    };

    let (decision, performed) = run_with(
        cfg,
        &critical_sigma_alert(&target, &[]),
        MockExecutor::with_capabilities(Capabilities::none("kernel driver is not installed")),
        None,
    );

    assert!(
        matches!(decision, ResponseDecision::NoEnabledAction { .. }),
        "an unsupported action must not be promised, got {decision:?}"
    );
    assert!(performed.is_empty());
}

#[test]
fn the_allowlist_still_wins_over_a_matching_rule() {
    let target = Target::spawn();
    let cfg = ResponseConfig {
        enabled: true,
        prevention_enabled: true,
        allowlist_images: vec![target.basename()],
        rules: vec![rule(&["terminate_process"])],
        ..ResponseConfig::default()
    };

    let (decision, performed) = run(cfg, &critical_sigma_alert(&target, &[]));
    assert!(
        matches!(decision, ResponseDecision::Allowlisted { .. }),
        "got {decision:?}"
    );
    assert!(performed.is_empty());
}

#[test]
fn every_attempted_action_is_written_to_the_audit_stream() {
    let target = Target::spawn();
    let tempdir = tempfile::tempdir().expect("tempdir");
    let output = tempdir.path().join("alerts.ndjson");
    let file = std::fs::File::create(&output).expect("create audit file");
    let (writer, guard) = tracing_appender::non_blocking(file);

    let cfg = ResponseConfig {
        enabled: true,
        prevention_enabled: true,
        rules: vec![ResponseRule {
            name: Some("catch-all".to_string()),
            ..rule(&["terminate_process"])
        }],
        ..ResponseConfig::default()
    };

    let (_, performed) = run_with(
        cfg,
        &critical_sigma_alert(&target, &["attack.t1003"]),
        MockExecutor::new(),
        Some(AlertSink::new(writer)),
    );
    assert_eq!(performed, vec![ActionKind::TerminateProcess]);

    drop(guard);

    let lines = audit_lines(&output);
    assert_eq!(lines.len(), 1, "expected exactly one audit line");

    let json = &lines[0];
    assert_eq!(json["event.kind"], "event");
    assert_eq!(json["event.dataset"], "rustinel.response");
    assert_eq!(json["event.action"], "rustinel.response.terminate_process");
    assert_eq!(json["event.outcome"], "success");
    assert_eq!(json["edr.response.decision"], "performed");
    assert_eq!(json["edr.response.mode"], "prevention");
    assert_eq!(json["edr.response.policy_rule"], "catch-all");
    assert_eq!(json["edr.response.enforcement"], "post_hoc");
    assert_eq!(json["rule.name"], "Suspicious LSASS Access");
    assert_eq!(json["process.pid"], target.pid());
}

#[test]
fn a_failed_action_is_audited_as_a_failure_not_a_success() {
    let target = Target::spawn();
    let tempdir = tempfile::tempdir().expect("tempdir");
    let output = tempdir.path().join("alerts.ndjson");
    let file = std::fs::File::create(&output).expect("create audit file");
    let (writer, guard) = tracing_appender::non_blocking(file);

    let cfg = ResponseConfig {
        enabled: true,
        prevention_enabled: true,
        rules: vec![rule(&["terminate_process"])],
        ..ResponseConfig::default()
    };

    run_with(
        cfg,
        &critical_sigma_alert(&target, &[]),
        MockExecutor::failing("Access is denied"),
        Some(AlertSink::new(writer)),
    );

    drop(guard);

    let lines = audit_lines(&output);
    let json = lines.first().expect("one audit line");

    assert_eq!(json["event.outcome"], "failure");
    assert_eq!(json["edr.response.decision"], "failed");
    assert_eq!(
        json["edr.response.reason"],
        "terminate_process failed: Access is denied"
    );
}

#[test]
fn a_dry_run_is_audited_so_tuning_can_happen_before_prevention() {
    let target = Target::spawn();
    let tempdir = tempfile::tempdir().expect("tempdir");
    let output = tempdir.path().join("alerts.ndjson");
    let file = std::fs::File::create(&output).expect("create audit file");
    let (writer, guard) = tracing_appender::non_blocking(file);

    let cfg = ResponseConfig {
        enabled: true,
        prevention_enabled: false,
        rules: vec![rule(&["terminate_process"])],
        ..ResponseConfig::default()
    };

    run_with(
        cfg,
        &critical_sigma_alert(&target, &[]),
        MockExecutor::new(),
        Some(AlertSink::new(writer)),
    );

    drop(guard);

    let lines = audit_lines(&output);
    let json = lines.first().expect("one audit line");

    assert_eq!(json["edr.response.decision"], "dry_run");
    assert_eq!(json["edr.response.mode"], "dry_run");
    assert_eq!(json["event.outcome"], "unknown");
}
