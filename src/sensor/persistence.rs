//! Classifying a macOS file write as a persistence install.
//!
//! The macOS sensor already sees every create, rename, and unlink. What it
//! could not say was *what* a write meant: a plist landing in
//! `~/Library/LaunchAgents` and one landing in `~/Downloads` arrived as the
//! same kind of event, so a rule had to carry the path list itself and every
//! rule had to carry it again.
//!
//! This names the location instead. A rule can then ask for
//! `PersistenceMechanism: launch_agent` and be right about every user on the
//! machine, including ones whose home directory is not under `/Users`.
//!
//! # Where the list comes from
//!
//! Phil Stokes, *A Guide to macOS Threat Hunting and Incident Response*
//! (SentinelOne, 2020), chapter 1, which enumerates how macOS malware actually
//! persists. Two of its judgements shaped what is here:
//!
//! - The LaunchAgent is "by far the most common way malware persists on
//!   macOS", and a *user* LaunchAgent needs no privileges at all. So the
//!   per-user directory matters at least as much as the system one.
//! - `/System/Library` is protected by SIP, so the guide points monitoring at
//!   `/Library/LaunchDaemons` and the per-user folders instead. A write under
//!   `/System` is still classified here — SIP being bypassed is worth an alert
//!   of its own — but it is not what the common case looks like.
//!
//! Mechanisms the guide lists that are *not* classified here are noted at the
//! bottom of this file, with why.

/// What a path's location says the write is for.
///
/// The string is what a Sigma rule matches on, so these spellings are a
/// detection contract rather than labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PersistenceMechanism {
    /// `LaunchAgents`: runs at user login. The common case.
    LaunchAgent,
    /// `LaunchDaemons`: runs at boot, before any user logs in.
    LaunchDaemon,
    /// Configuration profile.
    Profile,
    /// A cron table.
    Cron,
    /// A periodic maintenance script, or its configuration.
    Periodic,
    /// A kernel extension.
    KernelExtension,
    /// The background task manager's login-item store.
    LoginItem,
    /// A Mail rule, which can run AppleScript on a crafted message.
    MailRule,
    /// A login or logout hook.
    LoginHook,
    /// A one-shot `at` job.
    AtJob,
    /// An `emond` client rule.
    Emond,
}

impl PersistenceMechanism {
    /// The value written to the event, and matched by rules.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::LaunchAgent => "launch_agent",
            Self::LaunchDaemon => "launch_daemon",
            Self::Profile => "profile",
            Self::Cron => "cron",
            Self::Periodic => "periodic",
            Self::KernelExtension => "kernel_extension",
            Self::LoginItem => "login_item",
            Self::MailRule => "mail_rule",
            Self::LoginHook => "login_hook",
            Self::AtJob => "at_job",
            Self::Emond => "emond",
        }
    }
}

/// Classify a path, or `None` when it is not a persistence location.
///
/// Matching is on path *segments*, not substrings: `/LaunchAgents/` has to be
/// a directory on the way to the file. A substring match would classify
/// `/tmp/LaunchAgents-notes.txt`, and an attacker who wanted to be noisy could
/// bury the agent's alerting in files named after the thing it watches for.
///
/// Case is folded because macOS filesystems are case-insensitive by default:
/// `/library/launchagents/x.plist` is the same file as the canonical spelling,
/// and a classifier that missed it would be trivially evaded.
pub(crate) fn classify(path: &str) -> Option<PersistenceMechanism> {
    if path.is_empty() {
        return None;
    }

    let lowered = path.to_ascii_lowercase();
    let segments: Vec<&str> = lowered
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    if segments.is_empty() {
        return None;
    }

    // A directory anywhere on the path is enough: these live under `/`,
    // `/System/`, and every user's home, and hard-coding `/Users/<name>`
    // would miss a home directory somewhere else, which is a supported and
    // unremarkable macOS configuration.
    let has_segment = |name: &str| segments.contains(&name);

    if has_segment("launchagents") {
        return Some(PersistenceMechanism::LaunchAgent);
    }
    if has_segment("launchdaemons") {
        return Some(PersistenceMechanism::LaunchDaemon);
    }
    if has_segment("configurationprofiles") || has_segment("managed preferences") {
        return Some(PersistenceMechanism::Profile);
    }
    // `/usr/lib/cron/tabs/<user>` is where crontab actually writes; `/etc/
    // crontab` and `/etc/cron.d` are the file-based forms.
    if has_segment("tabs") && has_segment("cron") {
        return Some(PersistenceMechanism::Cron);
    }
    if segments.last() == Some(&"crontab") || has_segment("cron.d") {
        return Some(PersistenceMechanism::Cron);
    }
    if has_segment("periodic")
        || segments.last() == Some(&"periodic.conf")
        || has_segment("periodic.conf")
    {
        return Some(PersistenceMechanism::Periodic);
    }
    if has_segment("extensions") && has_segment("library") {
        return Some(PersistenceMechanism::KernelExtension);
    }
    if has_segment("com.apple.backgroundtaskmanagementagent") {
        return Some(PersistenceMechanism::LoginItem);
    }
    if let Some(name) = segments.last() {
        if name.ends_with("syncedrules.plist") {
            return Some(PersistenceMechanism::MailRule);
        }
    }
    if has_segment("com.apple.loginwindow.plist") {
        return Some(PersistenceMechanism::LoginHook);
    }
    if has_segment("jobs") && has_segment("at") {
        return Some(PersistenceMechanism::AtJob);
    }
    if has_segment("emondclients") {
        return Some(PersistenceMechanism::Emond);
    }

    None
}

// Deliberately not classified, though the guide lists them:
//
// **Folder Actions and AppleScript.** The persistence is a script attached to
// a folder, not a file in a known place, so there is no path to recognise. The
// guide's own advice is to watch for `osascript` and `ScriptMonitor` in
// process command lines, which is process telemetry the sensor already
// produces and a rule can match directly.
//
// **StartupItems, rc.common, launchd.conf.** The guide records that these no
// longer work on any supported macOS. Classifying them would produce a field
// no rule should be written against.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_common_case_is_a_user_launch_agent() {
        // No privileges needed, which is why the guide calls it the most
        // common persistence on macOS.
        assert_eq!(
            classify("/Users/alice/Library/LaunchAgents/com.evil.plist"),
            Some(PersistenceMechanism::LaunchAgent)
        );
    }

    #[test]
    fn a_home_directory_outside_users_is_still_classified() {
        // Matching on segments rather than a `/Users/` prefix is what makes
        // this work; a home directory elsewhere is an ordinary macOS setup.
        assert_eq!(
            classify("/export/home/bob/Library/LaunchAgents/x.plist"),
            Some(PersistenceMechanism::LaunchAgent)
        );
    }

    #[test]
    fn system_and_library_daemons_are_both_classified() {
        assert_eq!(
            classify("/Library/LaunchDaemons/com.evil.plist"),
            Some(PersistenceMechanism::LaunchDaemon)
        );
        // SIP should stop this one; if it happens anyway it is worth knowing.
        assert_eq!(
            classify("/System/Library/LaunchDaemons/com.apple.real.plist"),
            Some(PersistenceMechanism::LaunchDaemon)
        );
    }

    /// macOS filesystems are case-insensitive by default, so a classifier that
    /// only matched the canonical spelling could be evaded by typing it
    /// differently.
    #[test]
    fn case_is_folded_because_the_filesystem_folds_it() {
        assert_eq!(
            classify("/library/launchagents/com.evil.plist"),
            Some(PersistenceMechanism::LaunchAgent)
        );
        assert_eq!(
            classify("/LIBRARY/LAUNCHDAEMONS/com.evil.plist"),
            Some(PersistenceMechanism::LaunchDaemon)
        );
    }

    /// The reason this matches segments and not substrings.
    ///
    /// A substring match would classify any file whose *name* mentions the
    /// directory, which lets anyone who can write to `/tmp` bury real
    /// persistence alerts under noise of their own making.
    #[test]
    fn a_filename_that_merely_mentions_the_directory_is_not_persistence() {
        assert_eq!(classify("/tmp/LaunchAgents-notes.txt"), None);
        assert_eq!(classify("/Users/alice/Downloads/LaunchDaemons.zip"), None);
    }

    #[test]
    fn the_quieter_mechanisms_are_recognised() {
        assert_eq!(
            classify("/usr/lib/cron/tabs/alice"),
            Some(PersistenceMechanism::Cron)
        );
        assert_eq!(classify("/etc/crontab"), Some(PersistenceMechanism::Cron));
        assert_eq!(
            classify("/etc/periodic/daily/999.uptime"),
            Some(PersistenceMechanism::Periodic)
        );
        assert_eq!(
            classify("/etc/periodic.conf"),
            Some(PersistenceMechanism::Periodic)
        );
        assert_eq!(
            classify("/Library/Extensions/evil.kext/Contents/Info.plist"),
            Some(PersistenceMechanism::KernelExtension)
        );
        assert_eq!(
            classify(
                "/Users/alice/Library/Application Support/\
                 com.apple.backgroundtaskmanagementagent/backgrounditems.btm"
            ),
            Some(PersistenceMechanism::LoginItem)
        );
        assert_eq!(
            classify("/Users/alice/Library/Mail/V6/MailData/SyncedRules.plist"),
            Some(PersistenceMechanism::MailRule)
        );
        // The iCloud form the guide names alongside the local one.
        assert_eq!(
            classify("/Users/alice/Library/Mail/V6/MailData/ubiquitous_SyncedRules.plist"),
            Some(PersistenceMechanism::MailRule)
        );
        assert_eq!(
            classify("/var/at/jobs/a0001"),
            Some(PersistenceMechanism::AtJob)
        );
        assert_eq!(
            classify("/private/var/db/emondClients/com.evil"),
            Some(PersistenceMechanism::Emond)
        );
    }

    #[test]
    fn ordinary_paths_are_left_alone() {
        assert_eq!(classify("/Users/alice/Documents/notes.txt"), None);
        assert_eq!(classify("/usr/bin/curl"), None);
        assert_eq!(classify(""), None);
        assert_eq!(classify("/"), None);
    }

    /// The spellings are what rules match on, so they are pinned.
    #[test]
    fn the_reported_names_are_stable() {
        assert_eq!(PersistenceMechanism::LaunchAgent.as_str(), "launch_agent");
        assert_eq!(PersistenceMechanism::LaunchDaemon.as_str(), "launch_daemon");
        assert_eq!(PersistenceMechanism::LoginItem.as_str(), "login_item");
        assert_eq!(PersistenceMechanism::Emond.as_str(), "emond");
    }
}
