//! ECS mapping for response audit records.
//!
//! Response records share the alert file rather than getting one of their own,
//! so an operator tailing `alerts.json` sees what was detected and what was
//! done about it in one ordered stream. They are distinguished by
//! `event.dataset: rustinel.response` and by `event.kind: event` (a record of
//! something Rustinel did) as against `alert` (something it saw).

use super::event::{alert_severity_to_event_severity, host_os_family, host_os_type};
use super::ECS_VERSION;
use crate::models::ecs::EVENT_MODULE;
use crate::response::audit::ResponseAuditRecord;
use crate::sensor::Platform;
use serde::Serialize;

/// ECS document for one attempted response action.
#[derive(Debug, Clone, Serialize)]
pub struct EcsResponse {
    #[serde(rename = "@timestamp")]
    pub timestamp: String,

    #[serde(rename = "ecs.version")]
    pub ecs_version: String,

    #[serde(rename = "event.kind")]
    pub event_kind: String,

    #[serde(rename = "event.category")]
    pub event_category: Vec<String>,

    #[serde(rename = "event.type")]
    pub event_type: Vec<String>,

    /// `rustinel.response.<action>`, e.g. `rustinel.response.terminate_process`.
    #[serde(rename = "event.action")]
    pub event_action: String,

    #[serde(rename = "event.outcome")]
    pub event_outcome: String,

    #[serde(rename = "event.dataset")]
    pub event_dataset: String,

    #[serde(rename = "event.module")]
    pub event_module: String,

    #[serde(rename = "event.severity")]
    pub event_severity: u8,

    #[serde(rename = "host.os.type")]
    pub host_os_type: String,

    #[serde(rename = "host.os.family")]
    pub host_os_family: String,

    #[serde(rename = "rule.name")]
    pub rule_name: String,

    #[serde(rename = "rule.id", skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,

    #[serde(rename = "edr.rule.severity")]
    pub edr_rule_severity: String,

    #[serde(rename = "edr.rule.engine")]
    pub edr_rule_engine: String,

    /// Action kind, in its configuration spelling.
    #[serde(rename = "edr.response.action")]
    pub edr_response_action: String,

    /// `prevention` or `dry_run`: what the engine was configured to do.
    #[serde(rename = "edr.response.mode")]
    pub edr_response_mode: String,

    /// `performed`, `dry_run`, `suppressed`, or `failed`.
    #[serde(rename = "edr.response.decision")]
    pub edr_response_decision: String,

    /// Why, for anything that did not simply succeed.
    #[serde(rename = "edr.response.reason", skip_serializing_if = "Option::is_none")]
    pub edr_response_reason: Option<String>,

    /// Executor that handled it.
    #[serde(
        rename = "edr.response.executor",
        skip_serializing_if = "Option::is_none"
    )]
    pub edr_response_executor: Option<String>,

    /// `inline` if the operation itself was denied, `post_hoc` if cleaned up after.
    #[serde(
        rename = "edr.response.enforcement",
        skip_serializing_if = "Option::is_none"
    )]
    pub edr_response_enforcement: Option<String>,

    /// What the action acted on.
    #[serde(rename = "edr.response.target")]
    pub edr_response_target: String,

    /// Policy rule that selected the action.
    #[serde(rename = "edr.response.policy_rule")]
    pub edr_response_policy_rule: String,

    #[serde(rename = "process.pid", skip_serializing_if = "Option::is_none")]
    pub process_pid: Option<u32>,

    #[serde(rename = "process.executable", skip_serializing_if = "Option::is_none")]
    pub process_executable: Option<String>,
}

impl EcsResponse {
    /// Map a record, tagging it with the platform the agent runs on.
    pub fn from_record(record: &ResponseAuditRecord, platform: Platform) -> Self {
        Self {
            timestamp: record.timestamp.clone(),
            ecs_version: ECS_VERSION.to_string(),
            event_kind: "event".to_string(),
            event_category: vec!["intrusion_detection".to_string()],
            event_type: vec![event_type(record)],
            event_action: format!("rustinel.response.{}", record.action),
            event_outcome: record.outcome.event_outcome().to_string(),
            event_dataset: "rustinel.response".to_string(),
            event_module: EVENT_MODULE.to_string(),
            event_severity: alert_severity_to_event_severity(record.severity),
            host_os_type: host_os_type(platform),
            host_os_family: host_os_family(platform),
            rule_name: record.rule_name.clone(),
            rule_id: record.rule_id.clone(),
            edr_rule_severity: format!("{:?}", record.severity),
            edr_rule_engine: format!("{:?}", record.engine),
            edr_response_action: record.action.to_string(),
            edr_response_mode: record.mode().to_string(),
            edr_response_decision: record.outcome.decision().to_string(),
            edr_response_reason: record.outcome.reason(),
            edr_response_executor: record.outcome.executor().map(str::to_string),
            edr_response_enforcement: record
                .outcome
                .enforcement()
                .map(|enforcement| enforcement.to_string()),
            edr_response_target: record.target.clone(),
            edr_response_policy_rule: record.policy_rule.clone(),
            process_pid: record.pid,
            process_executable: record.image.clone(),
        }
    }
}

/// ECS `event.type`: `denied` when something was actually stopped.
fn event_type(record: &ResponseAuditRecord) -> String {
    match &record.outcome {
        crate::response::audit::ActionOutcome::Performed { .. } => "denied".to_string(),
        _ => "info".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AlertSeverity, DetectionEngine};
    use crate::response::action::{ActionKind, Enforcement};
    use crate::response::audit::ActionOutcome;
    use crate::response::safety::SuppressionReason;

    fn record(outcome: ActionOutcome) -> ResponseAuditRecord {
        ResponseAuditRecord {
            timestamp: "2026-09-10T00:00:00Z".to_string(),
            action: ActionKind::TerminateProcess,
            outcome,
            target: "4242:C:\\tmp\\evil.exe".to_string(),
            policy_rule: "credential-access".to_string(),
            rule_name: "Suspicious LSASS Access".to_string(),
            rule_id: Some("sigma::abc-123".to_string()),
            severity: AlertSeverity::Critical,
            engine: DetectionEngine::Sigma,
            pid: Some(4242),
            image: Some("C:\\tmp\\evil.exe".to_string()),
            prevention_enabled: true,
        }
    }

    fn json(record: &ResponseAuditRecord) -> serde_json::Value {
        serde_json::to_value(EcsResponse::from_record(record, Platform::Windows))
            .expect("serialize")
    }

    #[test]
    fn a_performed_action_is_a_denial_event() {
        let value = json(&record(ActionOutcome::Performed {
            executor: "ring3",
            enforcement: Enforcement::PostHoc,
            detail: None,
        }));

        assert_eq!(value["event.kind"], "event");
        assert_eq!(value["event.dataset"], "rustinel.response");
        assert_eq!(value["event.action"], "rustinel.response.terminate_process");
        assert_eq!(value["event.outcome"], "success");
        assert_eq!(value["event.type"][0], "denied");
        assert_eq!(value["edr.response.decision"], "performed");
        assert_eq!(value["edr.response.mode"], "prevention");
        assert_eq!(value["edr.response.executor"], "ring3");
        assert_eq!(value["edr.response.enforcement"], "post_hoc");
        assert_eq!(value["edr.response.policy_rule"], "credential-access");
        assert_eq!(value["process.pid"], 4242);
        assert_eq!(value["rule.id"], "sigma::abc-123");
        assert!(value.get("edr.response.reason").is_none());
    }

    #[test]
    fn a_dry_run_reports_the_action_it_would_have_taken() {
        let mut base = record(ActionOutcome::DryRun);
        base.prevention_enabled = false;
        let value = json(&base);

        assert_eq!(value["event.outcome"], "unknown");
        assert_eq!(value["event.type"][0], "info");
        assert_eq!(value["edr.response.decision"], "dry_run");
        assert_eq!(value["edr.response.mode"], "dry_run");
        assert_eq!(value["edr.response.action"], "terminate_process");
    }

    #[test]
    fn a_suppression_records_why() {
        let value = json(&record(ActionOutcome::Suppressed {
            reason: SuppressionReason::ProtectedProcessLight,
        }));

        assert_eq!(value["edr.response.decision"], "suppressed");
        assert_eq!(value["edr.response.reason"], "protected_process_light");
        assert!(value.get("edr.response.executor").is_none());
    }

    #[test]
    fn a_failure_records_the_operating_system_error() {
        let value = json(&record(ActionOutcome::Failed {
            executor: "ring3",
            error: "OpenProcess failed: Access is denied".to_string(),
        }));

        assert_eq!(value["event.outcome"], "failure");
        assert_eq!(value["edr.response.decision"], "failed");
        assert_eq!(
            value["edr.response.reason"],
            "OpenProcess failed: Access is denied"
        );
    }
}
