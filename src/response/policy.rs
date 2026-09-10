//! Which alerts get which actions.
//!
//! Policy lives in operator configuration rather than in rule content on
//! purpose. Detection rules are installed from a catalog and replaced wholesale
//! by `rustinel rules install`, so a rule author who could name an action would
//! be deciding what runs on someone else's machine. `[[response.rules]]` keeps
//! that decision with the person who owns the endpoint, and uses the rule's own
//! metadata — id, name, tags, severity, logsource category, engine — only to
//! select.
//!
//! Rules are evaluated in file order and the first match wins. When no rules
//! are configured at all the engine synthesizes the pre-policy behaviour:
//! terminate at or above `response.min_severity`.

use super::action::ActionKind;
use crate::config::{ResponseConfig, ResponseRule};
use crate::engine::Engine;
use crate::models::{Alert, AlertSeverity, DetectionEngine};
use std::sync::Arc;
use tracing::warn;

const TARGET_RESPONSE: &str = "response";

/// A rule with its patterns parsed and validated once, at load time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedRule {
    /// Operator label, or a positional fallback.
    pub name: String,
    rule_ids: Vec<String>,
    rule_names: Vec<GlobPattern>,
    tags: Vec<GlobPattern>,
    categories: Vec<String>,
    engines: Vec<DetectionEngine>,
    min_severity: Option<AlertSeverity>,
    /// Actions to take, in order, deduplicated.
    pub actions: Vec<ActionKind>,
    /// Whether this rule reports without acting.
    pub dry_run: bool,
}

impl PreparedRule {
    /// Parse one configured rule, dropping and reporting what cannot be used.
    fn from_config(index: usize, rule: &ResponseRule) -> Self {
        let name = rule
            .name
            .clone()
            .unwrap_or_else(|| format!("response.rules[{index}]"));

        let mut actions = Vec::new();
        for action in &rule.actions {
            match ActionKind::parse(action) {
                Some(kind) if !actions.contains(&kind) => actions.push(kind),
                Some(_) => {}
                None => warn!(
                    target: TARGET_RESPONSE,
                    rule = %name,
                    action = %action,
                    "Unknown response action in policy rule; ignoring it"
                ),
            }
        }

        if actions.is_empty() {
            warn!(
                target: TARGET_RESPONSE,
                rule = %name,
                "Policy rule selects no usable action; it can never do anything"
            );
        }

        let engines = rule
            .engines
            .iter()
            .filter_map(|engine| match engine.trim().to_ascii_lowercase().as_str() {
                "sigma" => Some(DetectionEngine::Sigma),
                "yara" => Some(DetectionEngine::Yara),
                "ioc" => Some(DetectionEngine::Ioc),
                other => {
                    warn!(
                        target: TARGET_RESPONSE,
                        rule = %name,
                        engine = %other,
                        "Unknown detection engine in policy rule; ignoring it"
                    );
                    None
                }
            })
            .collect();

        Self {
            name,
            rule_ids: rule
                .rule_ids
                .iter()
                .map(|id| id.trim().to_string())
                .collect(),
            rule_names: rule
                .rule_names
                .iter()
                .map(|p| GlobPattern::new(p))
                .collect(),
            tags: rule.tags.iter().map(|p| GlobPattern::new(p)).collect(),
            categories: rule
                .categories
                .iter()
                .map(|c| c.trim().to_ascii_lowercase())
                .collect(),
            engines,
            min_severity: rule.min_severity.as_deref().map(parse_severity),
            actions,
            dry_run: rule.dry_run,
        }
    }

    /// The synthesized rule used when no policy rules are configured: the
    /// behaviour the engine had before policy existed.
    fn legacy(min_severity: AlertSeverity) -> Self {
        Self {
            name: "response.min_severity".to_string(),
            rule_ids: Vec::new(),
            rule_names: Vec::new(),
            tags: Vec::new(),
            categories: Vec::new(),
            engines: Vec::new(),
            min_severity: Some(min_severity),
            actions: vec![ActionKind::TerminateProcess],
            dry_run: false,
        }
    }

    /// Whether this rule covers the alert. Every populated field must match.
    fn matches(&self, ctx: &AlertContext<'_>) -> bool {
        if let Some(min_severity) = self.min_severity {
            if ctx.severity < min_severity {
                return false;
            }
        }

        if !self.engines.is_empty() && !self.engines.contains(&ctx.engine) {
            return false;
        }

        if !self.rule_ids.is_empty()
            && !self
                .rule_ids
                .iter()
                .any(|id| Some(id.as_str()) == ctx.rule_id)
        {
            return false;
        }

        if !self.rule_names.is_empty()
            && !self
                .rule_names
                .iter()
                .any(|pattern| pattern.matches(ctx.rule_name))
        {
            return false;
        }

        if !self.tags.is_empty()
            && !self
                .tags
                .iter()
                .any(|pattern| ctx.tags.iter().any(|tag| pattern.matches(tag)))
        {
            return false;
        }

        if !self.categories.is_empty()
            && !self
                .categories
                .iter()
                .any(|category| ctx.categories.iter().any(|actual| actual == category))
        {
            return false;
        }

        true
    }
}

/// The compiled policy: rules plus the settings the worker consults per action.
///
/// Rebuilt only when the underlying `Arc<ResponseConfig>` pointer changes, so
/// a hot reload pays the parse cost once rather than once per alert.
#[derive(Debug, Clone)]
pub struct PreparedPolicy {
    source: Arc<ResponseConfig>,
    /// Whether response is on at all.
    pub enabled: bool,
    /// Whether actions are performed rather than only reported.
    pub prevention_enabled: bool,
    /// Whether the rule list was synthesized from `min_severity`.
    pub legacy_mode: bool,
    /// Severity floor in legacy mode.
    pub min_severity: AlertSeverity,
    rules: Vec<PreparedRule>,
    /// Images that are never acted on.
    pub allowlist_images: Vec<String>,
    /// Path prefixes that are never acted on.
    pub allowlist_paths: Vec<String>,
    /// Images protected from action even when not allowlisted.
    pub protected_images: Vec<String>,
    /// Ceiling on actions of one kind per minute.
    pub max_actions_per_minute: u32,
    /// Minimum gap between identical actions on the same target.
    pub cooldown_secs: u64,
    /// Whether attempted actions are written to the alert stream.
    pub audit_to_alerts: bool,
    enabled_actions: [bool; ActionKind::COUNT],
}

impl PreparedPolicy {
    /// Compile a configuration snapshot.
    pub fn from_raw(raw: &Arc<ResponseConfig>) -> Self {
        let min_severity = parse_severity(&raw.min_severity);
        let legacy_mode = raw.rules.is_empty();
        let rules = if legacy_mode {
            vec![PreparedRule::legacy(min_severity)]
        } else {
            raw.rules
                .iter()
                .enumerate()
                .map(|(index, rule)| PreparedRule::from_config(index, rule))
                .collect()
        };

        let actions = &raw.actions;
        let mut enabled_actions = [false; ActionKind::COUNT];
        enabled_actions[ActionKind::TerminateProcess.index()] = actions.terminate_process.enabled;
        enabled_actions[ActionKind::SuspendProcess.index()] = actions.suspend_process.enabled;
        enabled_actions[ActionKind::IsolateHost.index()] = actions.isolate_host.enabled;
        enabled_actions[ActionKind::BlockProcessNetwork.index()] =
            actions.block_process_network.enabled;
        enabled_actions[ActionKind::QuarantineFile.index()] = actions.quarantine_file.enabled;
        enabled_actions[ActionKind::RevertRegistry.index()] = actions.revert_registry.enabled;
        enabled_actions[ActionKind::DisableService.index()] = actions.disable_service.enabled;
        enabled_actions[ActionKind::DisableScheduledTask.index()] =
            actions.disable_scheduled_task.enabled;

        Self {
            source: Arc::clone(raw),
            enabled: raw.enabled,
            prevention_enabled: raw.prevention_enabled,
            legacy_mode,
            min_severity,
            rules,
            allowlist_images: super::normalize_allowlist_images(&raw.allowlist_images),
            allowlist_paths: super::normalize_allowlist_paths(&raw.allowlist_paths),
            protected_images: super::normalize_allowlist_images(&raw.protected_images),
            max_actions_per_minute: raw.max_actions_per_minute,
            cooldown_secs: raw.cooldown_secs,
            audit_to_alerts: raw.audit_to_alerts,
            enabled_actions,
        }
    }

    /// Recompile only if the configuration pointer changed.
    pub fn refresh_if_changed(&mut self, current: &Arc<ResponseConfig>) {
        if !self.matches_source(current) {
            *self = Self::from_raw(current);
        }
    }

    /// Whether this policy was compiled from `current`.
    pub fn matches_source(&self, current: &Arc<ResponseConfig>) -> bool {
        Arc::ptr_eq(&self.source, current)
    }

    /// Whether an action kind is switched on in configuration.
    pub fn action_enabled(&self, kind: ActionKind) -> bool {
        self.enabled_actions[kind.index()]
    }

    /// First rule covering this alert.
    pub fn match_alert(&self, alert: &Alert) -> Option<&PreparedRule> {
        let ctx = AlertContext::new(alert);
        self.rules.iter().find(|rule| rule.matches(&ctx))
    }

    /// Rules in evaluation order.
    pub fn rules(&self) -> &[PreparedRule] {
        &self.rules
    }
}

/// The parts of an alert a policy rule can select on, gathered once.
struct AlertContext<'a> {
    severity: AlertSeverity,
    engine: DetectionEngine,
    rule_id: Option<&'a str>,
    rule_name: &'a str,
    tags: &'a [String],
    categories: Vec<String>,
}

impl<'a> AlertContext<'a> {
    fn new(alert: &'a Alert) -> Self {
        Self {
            severity: super::effective_alert_severity(alert),
            engine: alert.engine,
            rule_id: alert.rule_id.as_deref(),
            rule_name: &alert.rule_name,
            tags: &alert.tags,
            categories: Engine::concrete_logsource_aliases_for_event(&alert.event)
                .into_iter()
                .filter_map(|alias| alias.category)
                .map(|category| category.to_ascii_lowercase())
                .collect(),
        }
    }
}

/// A case-insensitive pattern with `*` wildcards, compiled once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobPattern {
    /// Literal segments between the wildcards, lowercased.
    segments: Vec<String>,
    anchored_start: bool,
    anchored_end: bool,
}

impl GlobPattern {
    /// Compile a pattern. `*` matches any run of characters, including none.
    pub fn new(pattern: &str) -> Self {
        let pattern = pattern.trim().to_ascii_lowercase();
        let anchored_start = !pattern.starts_with('*');
        let anchored_end = !pattern.ends_with('*');
        let segments = pattern
            .split('*')
            .filter(|segment| !segment.is_empty())
            .map(|segment| segment.to_string())
            .collect();

        Self {
            segments,
            anchored_start,
            anchored_end,
        }
    }

    /// Whether `value` matches, ignoring case.
    pub fn matches(&self, value: &str) -> bool {
        let value = value.trim().to_ascii_lowercase();

        // A pattern of only wildcards, or an empty pattern, matches anything.
        if self.segments.is_empty() {
            return true;
        }

        let last_index = self.segments.len() - 1;
        let mut cursor = 0usize;

        for (index, segment) in self.segments.iter().enumerate() {
            let anchor_start = index == 0 && self.anchored_start;
            let anchor_end = index == last_index && self.anchored_end;

            let at = match (anchor_start, anchor_end) {
                // No wildcards at all: the value must be exactly the pattern.
                (true, true) => {
                    if value.len() != segment.len() || value != *segment {
                        return false;
                    }
                    0
                }
                (true, false) => {
                    if !value.starts_with(segment.as_str()) {
                        return false;
                    }
                    0
                }
                // The final segment must sit flush against the end, which the
                // left-to-right search above would not guarantee on its own.
                (false, true) => {
                    let Some(start) = value.len().checked_sub(segment.len()) else {
                        return false;
                    };
                    if start < cursor
                        || !value.is_char_boundary(start)
                        || &value[start..] != segment.as_str()
                    {
                        return false;
                    }
                    start
                }
                (false, false) => {
                    let Some(offset) = value[cursor..].find(segment.as_str()) else {
                        return false;
                    };
                    cursor + offset
                }
            };

            cursor = at + segment.len();
        }

        true
    }
}

/// Parse a configured severity, defaulting to the strictest on nonsense input.
pub fn parse_severity(value: &str) -> AlertSeverity {
    match value.trim().to_ascii_lowercase().as_str() {
        "critical" => AlertSeverity::Critical,
        "high" => AlertSeverity::High,
        "medium" => AlertSeverity::Medium,
        "low" => AlertSeverity::Low,
        other => {
            warn!(
                target: TARGET_RESPONSE,
                min_severity = %other,
                "Unknown response severity; defaulting to critical"
            );
            AlertSeverity::Critical
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ResponseConfig;
    use crate::response::tests_support::{alert_with, AlertShape};

    fn prepared(rules: Vec<ResponseRule>) -> PreparedPolicy {
        PreparedPolicy::from_raw(&Arc::new(ResponseConfig {
            enabled: true,
            prevention_enabled: true,
            rules,
            ..ResponseConfig::default()
        }))
    }

    fn rule(actions: &[&str]) -> ResponseRule {
        ResponseRule {
            actions: actions.iter().map(|a| a.to_string()).collect(),
            ..ResponseRule::default()
        }
    }

    #[test]
    fn glob_matches_prefix_suffix_and_middle() {
        assert!(GlobPattern::new("attack.t1003*").matches("attack.t1003.001"));
        assert!(GlobPattern::new("attack.t1003*").matches("attack.t1003"));
        assert!(!GlobPattern::new("attack.t1003*").matches("attack.t1055"));

        assert!(GlobPattern::new("*credential*").matches("Suspicious Credential Access"));
        assert!(!GlobPattern::new("*credential*").matches("Suspicious Access"));

        assert!(GlobPattern::new("*.exe").matches("C:\\tmp\\evil.exe"));
        assert!(!GlobPattern::new("*.exe").matches("C:\\tmp\\evil.exe.bak"));

        assert!(GlobPattern::new("exact").matches("EXACT"));
        assert!(!GlobPattern::new("exact").matches("exactly"));

        assert!(GlobPattern::new("*").matches("anything at all"));
    }

    #[test]
    fn glob_requires_segments_in_order() {
        let pattern = GlobPattern::new("a*b*c");
        assert!(pattern.matches("a-b-c"));
        assert!(pattern.matches("abc"));
        assert!(!pattern.matches("a-c-b"));
        assert!(!pattern.matches("cba"));
    }

    #[test]
    fn empty_rule_list_reproduces_the_pre_policy_behaviour() {
        let policy = PreparedPolicy::from_raw(&Arc::new(ResponseConfig {
            enabled: true,
            min_severity: "high".to_string(),
            ..ResponseConfig::default()
        }));

        assert!(policy.legacy_mode);
        assert_eq!(policy.rules().len(), 1);
        assert_eq!(
            policy.rules()[0].actions,
            vec![ActionKind::TerminateProcess]
        );

        let high = alert_with(AlertShape {
            severity: AlertSeverity::High,
            ..AlertShape::default()
        });
        let medium = alert_with(AlertShape {
            severity: AlertSeverity::Medium,
            ..AlertShape::default()
        });

        assert!(policy.match_alert(&high).is_some());
        assert!(policy.match_alert(&medium).is_none());
    }

    #[test]
    fn first_matching_rule_wins() {
        let policy = prepared(vec![
            ResponseRule {
                name: Some("first".to_string()),
                tags: vec!["attack.t1003*".to_string()],
                ..rule(&["suspend_process"])
            },
            ResponseRule {
                name: Some("second".to_string()),
                ..rule(&["terminate_process"])
            },
        ]);

        let tagged = alert_with(AlertShape {
            tags: vec!["attack.t1003.001".to_string()],
            ..AlertShape::default()
        });
        let untagged = alert_with(AlertShape::default());

        assert_eq!(policy.match_alert(&tagged).expect("match").name, "first");
        assert_eq!(policy.match_alert(&untagged).expect("match").name, "second");
    }

    #[test]
    fn every_populated_field_must_match() {
        let policy = prepared(vec![ResponseRule {
            tags: vec!["attack.t1003*".to_string()],
            min_severity: Some("critical".to_string()),
            engines: vec!["sigma".to_string()],
            ..rule(&["terminate_process"])
        }]);

        let matching = alert_with(AlertShape {
            severity: AlertSeverity::Critical,
            engine: DetectionEngine::Sigma,
            tags: vec!["attack.t1003".to_string()],
            ..AlertShape::default()
        });
        assert!(policy.match_alert(&matching).is_some());

        // Right tag and engine, severity too low.
        let low_severity = alert_with(AlertShape {
            severity: AlertSeverity::High,
            engine: DetectionEngine::Sigma,
            tags: vec!["attack.t1003".to_string()],
            ..AlertShape::default()
        });
        assert!(policy.match_alert(&low_severity).is_none());

        // Right severity and tag, wrong engine.
        let wrong_engine = alert_with(AlertShape {
            severity: AlertSeverity::Critical,
            engine: DetectionEngine::Ioc,
            tags: vec!["attack.t1003".to_string()],
            ..AlertShape::default()
        });
        assert!(policy.match_alert(&wrong_engine).is_none());

        // Right severity and engine, no tag at all.
        let no_tags = alert_with(AlertShape {
            severity: AlertSeverity::Critical,
            engine: DetectionEngine::Sigma,
            ..AlertShape::default()
        });
        assert!(policy.match_alert(&no_tags).is_none());
    }

    #[test]
    fn rule_id_and_name_select_individual_rules() {
        let policy = prepared(vec![
            ResponseRule {
                name: Some("by-id".to_string()),
                rule_ids: vec!["sigma::abc-123".to_string()],
                ..rule(&["terminate_process"])
            },
            ResponseRule {
                name: Some("by-name".to_string()),
                rule_names: vec!["*lsass*".to_string()],
                ..rule(&["suspend_process"])
            },
        ]);

        let by_id = alert_with(AlertShape {
            rule_id: Some("sigma::abc-123".to_string()),
            ..AlertShape::default()
        });
        let by_name = alert_with(AlertShape {
            rule_name: "Suspicious LSASS Access".to_string(),
            ..AlertShape::default()
        });
        let neither = alert_with(AlertShape::default());

        assert_eq!(policy.match_alert(&by_id).expect("match").name, "by-id");
        assert_eq!(policy.match_alert(&by_name).expect("match").name, "by-name");
        assert!(policy.match_alert(&neither).is_none());
    }

    #[test]
    fn category_matches_the_events_sigma_logsource() {
        let policy = prepared(vec![ResponseRule {
            categories: vec!["process_creation".to_string()],
            ..rule(&["terminate_process"])
        }]);

        assert!(policy
            .match_alert(&alert_with(AlertShape::default()))
            .is_some());

        let other = prepared(vec![ResponseRule {
            categories: vec!["registry_set".to_string()],
            ..rule(&["terminate_process"])
        }]);
        assert!(other
            .match_alert(&alert_with(AlertShape::default()))
            .is_none());
    }

    #[test]
    fn unknown_actions_and_engines_are_dropped_not_fatal() {
        let policy = prepared(vec![ResponseRule {
            engines: vec!["sigma".to_string(), "telepathy".to_string()],
            ..rule(&["terminate_process", "format_the_disk", "terminate_process"])
        }]);

        let prepared = &policy.rules()[0];
        assert_eq!(prepared.actions, vec![ActionKind::TerminateProcess]);
        assert_eq!(prepared.engines, vec![DetectionEngine::Sigma]);
    }

    #[test]
    fn action_switches_are_read_from_configuration() {
        let policy = PreparedPolicy::from_raw(&Arc::new(ResponseConfig::default()));
        assert!(policy.action_enabled(ActionKind::TerminateProcess));
        assert!(!policy.action_enabled(ActionKind::SuspendProcess));
        assert!(!policy.action_enabled(ActionKind::IsolateHost));
    }

    #[test]
    fn recompiles_only_when_the_configuration_pointer_changes() {
        let first = Arc::new(ResponseConfig::default());
        let mut policy = PreparedPolicy::from_raw(&first);
        policy.refresh_if_changed(&first);
        assert!(policy.legacy_mode);

        let second = Arc::new(ResponseConfig {
            rules: vec![rule(&["suspend_process"])],
            ..ResponseConfig::default()
        });
        policy.refresh_if_changed(&second);
        assert!(!policy.legacy_mode);
        assert_eq!(policy.rules()[0].actions, vec![ActionKind::SuspendProcess]);
    }
}
