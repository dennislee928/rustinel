use super::{MatchDetails, NormalizedEvent};
use serde::{Deserialize, Serialize};

/// Alert structure for detection hits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// Alert severity
    pub severity: AlertSeverity,
    /// Rule name that triggered
    pub rule_name: String,
    /// Optional rule description / context (e.g., IOC comment)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_description: Option<String>,
    /// Rule ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// Detection engine type
    pub engine: DetectionEngine,
    /// Rule tags, as written in the Sigma rule (`attack.t1003.001`).
    ///
    /// Carried on the alert so the response policy can select on technique
    /// without reaching back into the detector store, which YARA and IOC
    /// alerts have no entry in. Empty for those two engines.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Associated event data
    pub event: NormalizedEvent,
    /// Optional debug match details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_details: Option<MatchDetails>,
}

/// Alert severity levels
///
/// The variants are ordered from least to most severe, so the derived `Ord`
/// ranks severities directly (`Low < Medium < High < Critical`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Detection engine type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionEngine {
    Sigma,
    Yara,
    Ioc,
}
