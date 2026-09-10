//! Alert fixtures for the response unit tests.
//!
//! Building a `NormalizedEvent` by hand is verbose enough that tests written
//! around it end up asserting on their own scaffolding. [`AlertShape`] names
//! only the fields a response test actually varies and fills in the rest.

use crate::models::{
    Alert, AlertSeverity, DetectionEngine, EventCategory, EventFields, NormalizedEvent,
    ProcessCreationFields,
};
use crate::sensor::Platform;

/// The parts of an alert a response test cares about.
pub(crate) struct AlertShape {
    pub severity: AlertSeverity,
    pub engine: DetectionEngine,
    pub rule_name: String,
    pub rule_id: Option<String>,
    pub tags: Vec<String>,
    pub pid: Option<String>,
    pub image: Option<String>,
}

impl Default for AlertShape {
    fn default() -> Self {
        Self {
            severity: AlertSeverity::Critical,
            engine: DetectionEngine::Sigma,
            rule_name: "Test Rule".to_string(),
            rule_id: None,
            tags: Vec::new(),
            pid: Some("4242".to_string()),
            image: Some("/tmp/target".to_string()),
        }
    }
}

/// Build a process-creation alert with the given shape.
pub(crate) fn alert_with(shape: AlertShape) -> Alert {
    Alert {
        severity: shape.severity,
        rule_name: shape.rule_name,
        rule_description: None,
        rule_id: shape.rule_id,
        engine: shape.engine,
        tags: shape.tags,
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
                image: shape.image,
                image_source: None,
                image_truncated: None,
                process_id: shape.pid,
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
