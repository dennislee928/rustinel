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

/// Classify a path for the platform it came from.
///
/// Platform-scoped rather than one combined list: `/etc/cron.d` and
/// `/Library/LaunchDaemons` cannot both exist meaningfully on one host, and a
/// combined matcher would answer for paths its host could not have produced.
pub(crate) fn classify_for(
    platform: crate::sensor::Platform,
    path: &str,
) -> Option<PersistenceMechanism> {
    match platform {
        crate::sensor::Platform::MacOS => classify(path),
        crate::sensor::Platform::Linux => classify_linux(path),
        // Windows persistence is registry Run keys, services, and scheduled
        // tasks, which arrive as their own event categories rather than as
        // file writes, so there is nothing for a path classifier to add.
        crate::sensor::Platform::Windows => None,
    }
}

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
    /// A systemd unit, system-wide or per-user.
    SystemdUnit,
    /// A System V init script.
    InitScript,
    /// A shell profile or rc file that runs on login.
    ShellProfile,
    /// `/etc/ld.so.preload`, which injects a library into every process.
    LdPreload,
    /// A udev rule, which can run a program on device events.
    UdevRule,
    /// An SSH `authorized_keys` file.
    AuthorizedKeys,
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
            Self::SystemdUnit => "systemd_unit",
            Self::InitScript => "init_script",
            Self::ShellProfile => "shell_profile",
            Self::LdPreload => "ld_preload",
            Self::UdevRule => "udev_rule",
            Self::AuthorizedKeys => "authorized_keys",
        }
    }
}

/// Classify a Linux path, or `None` when it is not a persistence location.
///
/// Case is *not* folded here, unlike macOS: Linux filesystems are
/// case-sensitive, so `/etc/CRON.D` is a different path from `/etc/cron.d` and
/// treating them as the same would classify a file that has nothing to do with
/// cron.
pub(crate) fn classify_linux(path: &str) -> Option<PersistenceMechanism> {
    if path.is_empty() {
        return None;
    }

    let segments: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    if segments.is_empty() {
        return None;
    }
    let has = |name: &str| segments.contains(&name);
    let last = segments.last().copied().unwrap_or_default();

    // Every process on the host loads what this names, so it is the single
    // most valuable write on the list.
    if path == "/etc/ld.so.preload" {
        return Some(PersistenceMechanism::LdPreload);
    }
    if has("systemd") && (has("system") || has("user")) {
        return Some(PersistenceMechanism::SystemdUnit);
    }
    if last.ends_with(".service") || last.ends_with(".timer") {
        return Some(PersistenceMechanism::SystemdUnit);
    }
    if has("cron.d")
        || has("cron.daily")
        || has("cron.hourly")
        || has("cron.weekly")
        || has("cron.monthly")
        || last == "crontab"
        || (has("spool") && has("cron"))
    {
        return Some(PersistenceMechanism::Cron);
    }
    if has("init.d") || last == "rc.local" {
        return Some(PersistenceMechanism::InitScript);
    }
    if has("udev") && has("rules.d") {
        return Some(PersistenceMechanism::UdevRule);
    }
    if last == "authorized_keys" || last == "authorized_keys2" {
        return Some(PersistenceMechanism::AuthorizedKeys);
    }
    // Login shells run these, so a line appended to one persists for that user.
    if matches!(
        last,
        ".bashrc"
            | ".bash_profile"
            | ".bash_login"
            | ".bash_logout"
            | ".profile"
            | ".zshrc"
            | ".zshenv"
            | ".zprofile"
            | ".zlogin"
    ) {
        return Some(PersistenceMechanism::ShellProfile);
    }
    if (has("profile.d") && has("etc")) || path == "/etc/profile" || path == "/etc/bash.bashrc" {
        return Some(PersistenceMechanism::ShellProfile);
    }

    None
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

    /// Every process on the host loads what this file names, which makes it
    /// the single most valuable write on the Linux list.
    #[test]
    fn ld_so_preload_is_recognised() {
        assert_eq!(
            classify_linux("/etc/ld.so.preload"),
            Some(PersistenceMechanism::LdPreload)
        );
    }

    #[test]
    fn the_linux_mechanisms_are_recognised() {
        for (path, expected) in [
            (
                "/etc/systemd/system/evil.service",
                PersistenceMechanism::SystemdUnit,
            ),
            (
                "/home/alice/.config/systemd/user/evil.service",
                PersistenceMechanism::SystemdUnit,
            ),
            ("/etc/cron.d/evil", PersistenceMechanism::Cron),
            ("/var/spool/cron/crontabs/alice", PersistenceMechanism::Cron),
            ("/etc/init.d/evil", PersistenceMechanism::InitScript),
            ("/etc/rc.local", PersistenceMechanism::InitScript),
            (
                "/etc/udev/rules.d/99-evil.rules",
                PersistenceMechanism::UdevRule,
            ),
            (
                "/home/alice/.ssh/authorized_keys",
                PersistenceMechanism::AuthorizedKeys,
            ),
            ("/home/alice/.bashrc", PersistenceMechanism::ShellProfile),
            ("/etc/profile.d/evil.sh", PersistenceMechanism::ShellProfile),
        ] {
            assert_eq!(classify_linux(path), Some(expected), "for {path}");
        }
    }

    /// Linux filesystems are case-sensitive, so folding case here would
    /// classify a path that is genuinely a different file. This is the
    /// opposite of the macOS rule, and deliberately so.
    #[test]
    fn linux_case_is_not_folded_because_the_filesystem_does_not_fold_it() {
        assert_eq!(classify_linux("/etc/CRON.D/evil"), None);
        assert_eq!(
            classify_linux("/etc/cron.d/evil"),
            Some(PersistenceMechanism::Cron)
        );
    }

    #[test]
    fn ordinary_linux_paths_are_left_alone() {
        assert_eq!(classify_linux("/home/alice/notes.txt"), None);
        assert_eq!(classify_linux("/usr/bin/curl"), None);
        assert_eq!(classify_linux("/tmp/ld.so.preload"), None);
    }

    /// A host only produces paths its own platform has, so asking the wrong
    /// matcher would answer for a file that could not exist there.
    #[test]
    fn each_platform_is_classified_by_its_own_list() {
        use crate::sensor::Platform;

        assert_eq!(
            classify_for(Platform::MacOS, "/Library/LaunchDaemons/x.plist"),
            Some(PersistenceMechanism::LaunchDaemon)
        );
        assert_eq!(
            classify_for(Platform::Linux, "/etc/systemd/system/x.service"),
            Some(PersistenceMechanism::SystemdUnit)
        );
        // Windows persistence arrives as registry and service events, not as
        // file writes, so there is nothing here to add.
        assert_eq!(
            classify_for(Platform::Windows, r"C:\Windows\System32\evil.exe"),
            None
        );
    }

    /// The spellings are what rules match on, so they are pinned.
    #[test]
    fn the_reported_names_are_stable() {
        assert_eq!(PersistenceMechanism::LaunchAgent.as_str(), "launch_agent");
        assert_eq!(PersistenceMechanism::LaunchDaemon.as_str(), "launch_daemon");
        assert_eq!(PersistenceMechanism::LoginItem.as_str(), "login_item");
        assert_eq!(PersistenceMechanism::Emond.as_str(), "emond");
        assert_eq!(PersistenceMechanism::SystemdUnit.as_str(), "systemd_unit");
        assert_eq!(PersistenceMechanism::LdPreload.as_str(), "ld_preload");
        assert_eq!(
            PersistenceMechanism::AuthorizedKeys.as_str(),
            "authorized_keys"
        );
    }
}
