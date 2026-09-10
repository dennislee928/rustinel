//! Last checks before an action runs.
//!
//! The policy decides what *should* happen; this module decides what is safe
//! to actually do. A false positive that kills a process is worse than a missed
//! detection, and some targets are worse than others: terminating a Windows
//! critical process bugchecks the machine, and a protected-process-light target
//! will refuse the handle anyway. Both are better recognised and reported than
//! attempted.
//!
//! The two rate controls exist for a different failure: a rule that matches far
//! more often than its author expected. A per-kind ceiling bounds the damage
//! per minute, and a per-target cooldown stops the same action being retried
//! against the same thing in a tight loop.

use super::action::{ActionKind, ResponseAction};
use super::executor::ActionExecutor;
use super::policy::PreparedPolicy;
use crate::utils::path_allowlist;
use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

/// Cooldown entries retained before the map is trimmed.
const MAX_COOLDOWN_ENTRIES: usize = 4096;

/// Why an action the policy selected did not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuppressionReason {
    /// Switched off under `[response.actions]`.
    ActionDisabled,
    /// The executor cannot perform this kind of action.
    Unsupported(&'static str),
    /// This kind of action has hit its per-minute ceiling.
    RateLimited,
    /// The same action ran against the same target too recently.
    Cooldown,
    /// The image is on the protected list.
    ProtectedImage,
    /// Windows would bugcheck if this process died.
    CriticalProcess,
    /// The target runs as a protected process; the handle would be refused.
    ProtectedProcessLight,
}

impl SuppressionReason {
    /// Audit spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            SuppressionReason::ActionDisabled => "action_disabled",
            SuppressionReason::Unsupported(_) => "unsupported",
            SuppressionReason::RateLimited => "rate_limited",
            SuppressionReason::Cooldown => "cooldown",
            SuppressionReason::ProtectedImage => "protected_image",
            SuppressionReason::CriticalProcess => "critical_process",
            SuppressionReason::ProtectedProcessLight => "protected_process_light",
        }
    }

    /// Human-readable detail, where there is any.
    pub const fn detail(self) -> Option<&'static str> {
        match self {
            SuppressionReason::Unsupported(reason) => Some(reason),
            _ => None,
        }
    }
}

impl fmt::Display for SuppressionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Per-kind budget and per-target cooldown, owned by the response worker.
///
/// Single-threaded by construction: only the worker touches it, so no locking
/// is needed on the hot path.
#[derive(Debug)]
pub struct SafetyGate {
    buckets: [Bucket; ActionKind::COUNT],
    cooldowns: HashMap<(ActionKind, String), Instant>,
}

impl Default for SafetyGate {
    fn default() -> Self {
        Self::new()
    }
}

impl SafetyGate {
    /// A gate with no history.
    pub fn new() -> Self {
        Self {
            buckets: [Bucket::new(); ActionKind::COUNT],
            cooldowns: HashMap::new(),
        }
    }

    /// Whether the action may run, without recording anything.
    ///
    /// Read-only so a dry run reports the same suppression a real run would
    /// hit, without consuming the budget that a real run would.
    pub fn check(
        &self,
        action: &ResponseAction,
        policy: &PreparedPolicy,
        executor: &dyn ActionExecutor,
        now: Instant,
    ) -> Result<(), SuppressionReason> {
        let kind = action.kind();

        if !policy.action_enabled(kind) {
            return Err(SuppressionReason::ActionDisabled);
        }

        if let super::executor::ActionSupport::Unsupported(reason) =
            executor.capabilities().support(kind)
        {
            return Err(SuppressionReason::Unsupported(reason));
        }

        if let Some(target) = action.process_target() {
            if is_protected_image(&target.image, &policy.protected_images) {
                return Err(SuppressionReason::ProtectedImage);
            }
            if platform::is_critical_process(target.pid) {
                return Err(SuppressionReason::CriticalProcess);
            }
            if platform::is_protected_process(target.pid) {
                return Err(SuppressionReason::ProtectedProcessLight);
            }
        }

        if self.buckets[kind.index()].would_exceed(policy.max_actions_per_minute, now) {
            return Err(SuppressionReason::RateLimited);
        }

        let cooldown = Duration::from_secs(policy.cooldown_secs);
        if !cooldown.is_zero() {
            let key = (kind, action.target_key());
            if let Some(last) = self.cooldowns.get(&key) {
                if now.duration_since(*last) < cooldown {
                    return Err(SuppressionReason::Cooldown);
                }
            }
        }

        Ok(())
    }

    /// Record that the action ran, consuming budget and starting its cooldown.
    ///
    /// Called only when the action was actually performed, so a dry run never
    /// starves the budget of the real run that follows it.
    pub fn commit(&mut self, action: &ResponseAction, now: Instant) {
        let kind = action.kind();
        self.buckets[kind.index()].record(now);

        if self.cooldowns.len() >= MAX_COOLDOWN_ENTRIES {
            self.trim_cooldowns(now);
        }
        self.cooldowns.insert((kind, action.target_key()), now);
    }

    /// Drop cooldown entries that can no longer suppress anything.
    fn trim_cooldowns(&mut self, now: Instant) {
        let horizon = Duration::from_secs(3600);
        self.cooldowns
            .retain(|_, last| now.duration_since(*last) < horizon);

        if self.cooldowns.len() < MAX_COOLDOWN_ENTRIES {
            return;
        }

        // Still full of live entries: evict the oldest half rather than let
        // the map grow without bound.
        let keep = MAX_COOLDOWN_ENTRIES / 2;
        let mut entries: Vec<((ActionKind, String), Instant)> = self
            .cooldowns
            .iter()
            .map(|(key, last)| (key.clone(), *last))
            .collect();
        entries.sort_by_key(|(_, last)| *last);

        let drop_count = entries.len().saturating_sub(keep);
        for (key, _) in entries.into_iter().take(drop_count) {
            self.cooldowns.remove(&key);
        }
    }
}

/// A sliding one-minute count of actions of one kind.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    window_start: Option<Instant>,
    count: u32,
}

impl Bucket {
    const WINDOW: Duration = Duration::from_secs(60);

    const fn new() -> Self {
        Self {
            window_start: None,
            count: 0,
        }
    }

    /// Whether one more action would break the ceiling.
    fn would_exceed(&self, max_per_minute: u32, now: Instant) -> bool {
        if max_per_minute == 0 {
            return false;
        }
        match self.window_start {
            Some(start) if now.duration_since(start) < Self::WINDOW => self.count >= max_per_minute,
            _ => false,
        }
    }

    /// Count an action, rolling the window if it has expired.
    fn record(&mut self, now: Instant) {
        match self.window_start {
            Some(start) if now.duration_since(start) < Self::WINDOW => self.count += 1,
            _ => {
                self.window_start = Some(now);
                self.count = 1;
            }
        }
    }
}

/// Processes this platform must never have killed out from under it.
///
/// These are the ones whose death takes the session or the machine with them.
/// Operators add to the list through `response.protected_images`; nothing
/// removes an entry from it.
pub fn builtin_protected_images() -> &'static [&'static str] {
    #[cfg(windows)]
    {
        &[
            "smss.exe",
            "csrss.exe",
            "wininit.exe",
            "winlogon.exe",
            "services.exe",
            "lsass.exe",
            "system",
            "registry",
            "memory compression",
        ]
    }
    #[cfg(target_os = "linux")]
    {
        &[
            "systemd",
            "init",
            "systemd-journald",
            "systemd-logind",
            "systemd-udevd",
            "dbus-daemon",
            "sshd",
        ]
    }
    #[cfg(target_os = "macos")]
    {
        &[
            "launchd",
            "kernel_task",
            "windowserver",
            "loginwindow",
            "securityd",
        ]
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        &[]
    }
}

/// Whether an image is protected, by built-in list or operator configuration.
///
/// Configured entries containing a separator are compared as full paths;
/// everything else is compared against the file name, so `lsass.exe` protects
/// the process wherever it lives.
pub fn is_protected_image(image: &str, configured: &[String]) -> bool {
    let normalized = crate::utils::normalize_path_for_comparison(image);
    let basename = super::image_basename(&normalized);

    if builtin_protected_images()
        .iter()
        .any(|protected| basename == *protected)
    {
        return true;
    }

    if path_allowlist::matches_normalized(&normalized, configured) {
        return true;
    }

    configured.iter().any(|entry| {
        if entry.contains('\\') || entry.contains('/') {
            normalized == *entry
        } else {
            basename == entry
        }
    })
}

#[cfg(windows)]
mod platform {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        GetProcessInformation, IsProcessCritical, OpenProcess, ProcessProtectionLevelInfo,
        PROCESS_PROTECTION_LEVEL_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
        PROTECTION_LEVEL_NONE,
    };

    /// Whether the kernel would bugcheck if this process exited.
    ///
    /// A failure to ask is treated as "not critical": the process may simply
    /// have exited, and refusing every action because a probe failed would
    /// make response unreliable in exactly the noisy conditions it is for.
    pub(super) fn is_critical_process(pid: u32) -> bool {
        with_query_handle(pid, |handle| {
            let mut critical = windows::core::BOOL(0);
            unsafe { IsProcessCritical(handle, &mut critical) }
                .is_ok()
                .then(|| critical.as_bool())
                .unwrap_or(false)
        })
        .unwrap_or(false)
    }

    /// Whether the target runs as a protected process (PPL or full PP).
    ///
    /// `OpenProcess` for termination fails on these regardless, so reporting
    /// the reason beats reporting an opaque access-denied.
    pub(super) fn is_protected_process(pid: u32) -> bool {
        with_query_handle(pid, |handle| {
            let mut info = PROCESS_PROTECTION_LEVEL_INFORMATION::default();
            let ok = unsafe {
                GetProcessInformation(
                    handle,
                    ProcessProtectionLevelInfo,
                    std::ptr::from_mut(&mut info).cast(),
                    u32::try_from(std::mem::size_of::<PROCESS_PROTECTION_LEVEL_INFORMATION>())
                        .unwrap_or(0),
                )
            }
            .is_ok();

            ok && info.ProtectionLevel != PROTECTION_LEVEL_NONE
        })
        .unwrap_or(false)
    }

    /// Run `probe` against a limited-information handle to `pid`.
    fn with_query_handle<T>(pid: u32, probe: impl FnOnce(windows::Win32::Foundation::HANDLE) -> T) -> Option<T> {
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
        let result = probe(handle);
        unsafe {
            let _ = CloseHandle(handle);
        }
        Some(result)
    }
}

#[cfg(not(windows))]
mod platform {
    /// Unix has no equivalent of a kernel-critical user process.
    pub(super) fn is_critical_process(_pid: u32) -> bool {
        false
    }

    /// Unix has no equivalent of a protected process.
    pub(super) fn is_protected_process(_pid: u32) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ResponseConfig;
    use crate::response::executor::{Capabilities, MockExecutor};
    use crate::utils::ProcessIdentity;
    use std::sync::Arc;

    fn prepared(cfg: ResponseConfig) -> PreparedPolicy {
        PreparedPolicy::from_raw(&Arc::new(cfg))
    }

    fn action(pid: u32) -> ResponseAction {
        ResponseAction::TerminateProcess {
            target: ProcessIdentity {
                pid,
                image: format!("/tmp/target{pid}"),
                start_time: None,
                command_line_hash: None,
            },
        }
    }

    #[test]
    fn disabled_actions_are_suppressed() {
        let gate = SafetyGate::new();
        let executor = MockExecutor::new();
        let policy = prepared(ResponseConfig {
            actions: crate::config::ResponseActionsConfig {
                terminate_process: crate::config::ActionToggle::off(),
                ..Default::default()
            },
            ..ResponseConfig::default()
        });

        assert_eq!(
            gate.check(&action(4242), &policy, &executor, Instant::now()),
            Err(SuppressionReason::ActionDisabled)
        );
    }

    #[test]
    fn actions_the_executor_cannot_perform_are_suppressed() {
        let gate = SafetyGate::new();
        let executor = MockExecutor::with_capabilities(Capabilities::none("no driver"));

        assert_eq!(
            gate.check(
                &action(4242),
                &prepared(ResponseConfig::default()),
                &executor,
                Instant::now()
            ),
            Err(SuppressionReason::Unsupported("no driver"))
        );
    }

    #[test]
    fn rate_limit_applies_per_kind_and_resets_with_the_window() {
        let mut gate = SafetyGate::new();
        let executor = MockExecutor::new();
        let policy = prepared(ResponseConfig {
            max_actions_per_minute: 2,
            cooldown_secs: 0,
            ..ResponseConfig::default()
        });

        let start = Instant::now();
        assert!(gate.check(&action(1), &policy, &executor, start).is_ok());
        gate.commit(&action(1), start);
        assert!(gate.check(&action(2), &policy, &executor, start).is_ok());
        gate.commit(&action(2), start);

        assert_eq!(
            gate.check(&action(3), &policy, &executor, start),
            Err(SuppressionReason::RateLimited)
        );

        let later = start + Duration::from_secs(61);
        assert!(gate.check(&action(3), &policy, &executor, later).is_ok());
    }

    #[test]
    fn zero_rate_limit_means_no_ceiling() {
        let mut gate = SafetyGate::new();
        let executor = MockExecutor::new();
        let policy = prepared(ResponseConfig {
            max_actions_per_minute: 0,
            cooldown_secs: 0,
            ..ResponseConfig::default()
        });

        let now = Instant::now();
        for pid in 0..50 {
            assert!(gate.check(&action(pid), &policy, &executor, now).is_ok());
            gate.commit(&action(pid), now);
        }
    }

    #[test]
    fn cooldown_is_per_target_not_global() {
        let mut gate = SafetyGate::new();
        let executor = MockExecutor::new();
        let policy = prepared(ResponseConfig {
            cooldown_secs: 60,
            ..ResponseConfig::default()
        });

        let start = Instant::now();
        gate.commit(&action(1), start);

        assert_eq!(
            gate.check(&action(1), &policy, &executor, start + Duration::from_secs(10)),
            Err(SuppressionReason::Cooldown)
        );
        assert!(gate
            .check(&action(2), &policy, &executor, start + Duration::from_secs(10))
            .is_ok());
        assert!(gate
            .check(&action(1), &policy, &executor, start + Duration::from_secs(61))
            .is_ok());
    }

    #[test]
    fn a_dry_run_check_does_not_consume_budget() {
        let gate = SafetyGate::new();
        let executor = MockExecutor::new();
        let policy = prepared(ResponseConfig {
            max_actions_per_minute: 1,
            ..ResponseConfig::default()
        });

        let now = Instant::now();
        assert!(gate.check(&action(1), &policy, &executor, now).is_ok());
        assert!(
            gate.check(&action(1), &policy, &executor, now).is_ok(),
            "check must not record anything on its own"
        );
    }

    #[test]
    fn builtin_protected_images_cover_this_platform() {
        let configured: Vec<String> = Vec::new();

        #[cfg(windows)]
        {
            assert!(is_protected_image("C:\\Windows\\System32\\lsass.exe", &configured));
            assert!(is_protected_image("c:\\windows\\system32\\CSRSS.EXE", &configured));
            assert!(!is_protected_image("C:\\tmp\\evil.exe", &configured));
        }
        #[cfg(target_os = "linux")]
        {
            assert!(is_protected_image("/usr/lib/systemd/systemd", &configured));
            assert!(!is_protected_image("/tmp/evil", &configured));
        }
        #[cfg(target_os = "macos")]
        {
            assert!(is_protected_image("/sbin/launchd", &configured));
            assert!(!is_protected_image("/tmp/evil", &configured));
        }
    }

    #[test]
    fn configured_protected_images_match_by_name_or_full_path() {
        let by_name = vec!["backup-agent".to_string()];
        assert!(is_protected_image("/opt/backup/backup-agent", &by_name));
        assert!(!is_protected_image("/opt/backup/other", &by_name));

        let by_path = vec![crate::utils::normalize_path_for_comparison(
            "/opt/backup/backup-agent",
        )];
        assert!(is_protected_image("/opt/backup/backup-agent", &by_path));
        assert!(!is_protected_image("/usr/bin/backup-agent", &by_path));
    }

    #[test]
    fn protected_images_are_suppressed_before_any_probe() {
        let gate = SafetyGate::new();
        let executor = MockExecutor::new();
        let policy = prepared(ResponseConfig {
            protected_images: vec!["target4242".to_string()],
            ..ResponseConfig::default()
        });

        assert_eq!(
            gate.check(&action(4242), &policy, &executor, Instant::now()),
            Err(SuppressionReason::ProtectedImage)
        );
    }
}
