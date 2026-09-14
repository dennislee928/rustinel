//! Whether the response engine can actually do what it is configured to do.
//!
//! Response is the part of the agent that fails silently when it is
//! misconfigured. A detection that cannot fire is visible as a rule that never
//! matches; an action that cannot run is visible only at the moment it is
//! needed, which is the worst possible time to discover it.
//!
//! These checks answer three questions ahead of that moment: can the filtering
//! engine be reached, is the quarantine directory usable, and is anything
//! currently contained that the operator may not know about.

use super::inspect::DiagnosticResult;
use crate::config::ResponseConfig;
use crate::response::executor::{driver, wfp};
use std::path::Path;

/// Report on whether the configured response actions can run.
pub fn response_results(response: &ResponseConfig) -> Vec<DiagnosticResult> {
    let mut results = Vec::new();

    results.extend(isolation_results(response));
    results.extend(quarantine_results(response));
    results.extend(driver_results());

    // Anything currently contained is worth saying out loud, whether or not
    // response is enabled now: filters installed by an earlier run outlive the
    // configuration that installed them.
    match crate::response::executor::installed_containment_count() {
        Ok(0) => {}
        Ok(count) => results.push(
            DiagnosticResult::warn(
                "response_containment_active",
                format!("This host has {count} Rustinel network filters installed"),
                "Network access is restricted by a previous isolation. Filters marked \
                 persistent survive a reboot and outlive the agent.",
            )
            .with_fix("Lift it with rustinel response unisolate"),
        ),
        Err(error) => {
            // Only worth reporting when a network action could actually run.
            if response.enabled && network_actions_enabled(response) {
                results.push(DiagnosticResult::warn(
                    "response_containment_active",
                    "Could not read the filtering engine",
                    error,
                ));
            }
        }
    }

    results
}

/// What the kernel driver is actually enforcing, if one is loaded.
///
/// Silent when no driver is present, which is the normal case: the driver is
/// optional and not shipped, so reporting its absence on every machine would
/// be noise rather than a finding.
///
/// When one *is* loaded, the interesting failure is a partial registration. A
/// driver whose image was not linked `/INTEGRITYCHECK` loads and runs, and
/// `ObRegisterCallbacks` alone refuses it, so the machine ends up policing
/// registry writes and file operations while leaving handle opens against
/// `lsass` untouched. That looks identical to a working driver from the
/// outside, which is exactly the kind of thing this report exists to catch.
fn driver_results() -> Vec<DiagnosticResult> {
    let executor = driver::KernelDriverExecutor::new();
    if !executor.driver_present() {
        return Vec::new();
    }

    let state = match executor.query_state() {
        Ok(state) => state,
        Err(error) => {
            return vec![DiagnosticResult::warn(
                "response_driver_state",
                "The kernel driver is loaded but did not answer",
                error,
            )];
        }
    };

    if state.version != driver::POLICY_VERSION {
        return vec![DiagnosticResult::warn(
            "response_driver_state",
            format!(
                "The kernel driver speaks policy version {}, the agent speaks {}",
                state.version,
                driver::POLICY_VERSION
            ),
            "The driver refuses a policy whose version it does not recognise, so nothing \
             is being denied in kernel mode.",
        )
        .with_fix("Install the driver built from this release")];
    }

    let inactive: Vec<&str> = [
        (state.object_callbacks_active, "handle opens"),
        (state.registry_callback_active, "registry writes"),
        (state.minifilter_active, "file operations"),
    ]
    .iter()
    .filter(|(active, _)| !active)
    .map(|(_, what)| *what)
    .collect();

    if !inactive.is_empty() {
        return vec![DiagnosticResult::warn(
            "response_driver_state",
            format!(
                "The kernel driver is loaded but is not policing {}",
                inactive.join(", ")
            ),
            "A callback that failed to register denies nothing, and the driver keeps \
             running. Object callbacks in particular refuse an image that was not linked \
             with /INTEGRITYCHECK.",
        )
        .with_fix("See driver/README.md for the signing and linker requirements")];
    }

    vec![DiagnosticResult::pass(
        "response_driver_state",
        format!(
            "The kernel driver is policing handle opens, registry writes, and file \
             operations ({} stripped, {} denied, {} registry writes denied, {} file \
             operations denied since load)",
            state.handles_stripped,
            state.handles_denied,
            state.registry_writes_denied,
            state.file_operations_denied
        ),
    )]
}

/// Whether any action needing the filtering engine is switched on.
fn network_actions_enabled(response: &ResponseConfig) -> bool {
    response.actions.isolate_host.enabled || response.actions.block_process_network.enabled
}

/// Checks for the two network actions.
fn isolation_results(response: &ResponseConfig) -> Vec<DiagnosticResult> {
    let mut results = Vec::new();

    if !network_actions_enabled(response) {
        return results;
    }

    let isolation = &response.actions.isolate_host;
    let policy = wfp::IsolationPolicy {
        allow_cidrs: isolation.allow_cidrs.clone(),
        allow_dns: isolation.allow_dns,
        allow_dhcp: isolation.allow_dhcp,
    };

    // The refusal that matters most, caught here rather than at the moment
    // somebody needs to isolate a machine.
    if isolation.enabled && policy.is_empty() {
        results.push(
            DiagnosticResult::fail(
                "response_isolation_exceptions",
                "Host isolation is enabled with no exceptions",
                "Isolation will refuse to run: cutting off a host reachable only over the \
                 network it just lost is an outage the agent cannot undo remotely.",
            )
            .with_fix(
                "Set allow_cidrs, allow_dns, or allow_dhcp under \
                 [response.actions.isolate_host]",
            ),
        );
    } else if isolation.enabled {
        let rejected = policy.rejected_cidrs();
        if rejected.is_empty() {
            let mut kept: Vec<String> = policy
                .parsed_networks()
                .iter()
                .map(|network| network.to_string())
                .collect();
            if isolation.allow_dns {
                kept.push("DNS".to_string());
            }
            if isolation.allow_dhcp {
                kept.push("DHCP".to_string());
            }
            kept.push("loopback".to_string());

            results.push(DiagnosticResult::pass(
                "response_isolation_exceptions",
                format!("Host isolation would keep {} reachable", kept.join(", ")),
            ));
        } else {
            results.push(
                DiagnosticResult::fail(
                    "response_isolation_exceptions",
                    "Some isolation exceptions are not addresses or networks",
                    format!("Ignored: {}", rejected.join(", ")),
                )
                .with_fix(
                    "Correct them under [response.actions.isolate_host].allow_cidrs; an \
                     exception that does not parse is one the operator believes is in force",
                ),
            );
        }
    }

    // The engine itself. Every filtering operation goes through it, and it
    // needs both the Base Filtering Engine service and administrator rights.
    match crate::response::executor::installed_containment_count() {
        Ok(_) => results.push(DiagnosticResult::pass(
            "response_filtering_engine",
            "The Windows Filtering Platform is reachable",
        )),
        Err(error) => results.push(
            DiagnosticResult::fail(
                "response_filtering_engine",
                "The Windows Filtering Platform is not reachable",
                error,
            )
            .with_fix(
                "Run as Administrator or LocalSystem, and confirm the Base Filtering Engine \
                 (BFE) service is running",
            ),
        ),
    }

    results
}

/// Checks for the quarantine directory.
fn quarantine_results(response: &ResponseConfig) -> Vec<DiagnosticResult> {
    let mut results = Vec::new();

    if !response.actions.quarantine_file.enabled {
        return results;
    }

    let directory = &response.quarantine_directory;

    match probe_directory(directory) {
        Ok(()) => results.push(DiagnosticResult::pass(
            "response_quarantine_directory",
            format!("Quarantine directory is writable: {}", directory.display()),
        )),
        Err(error) => results.push(
            DiagnosticResult::fail(
                "response_quarantine_directory",
                "Quarantine directory is not writable",
                format!("{}: {error}", directory.display()),
            )
            .with_fix(
                "Create it, or point response.quarantine_directory somewhere the agent can \
                 write",
            ),
        ),
    }

    results
}

/// Whether a directory exists and accepts a write.
///
/// Creating and removing a probe file is the only reliable answer on Windows,
/// where a directory can be listable and still refuse writes.
fn probe_directory(directory: &Path) -> Result<(), String> {
    std::fs::create_dir_all(directory).map_err(|err| err.to_string())?;

    let probe = directory.join(".rustinel-write-probe");
    std::fs::write(&probe, b"probe").map_err(|err| err.to_string())?;
    let _ = std::fs::remove_file(&probe);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ActionToggle, IsolationConfig, ResponseActionsConfig, ResponseConfig};
    use crate::doctor::inspect::DiagnosticStatus;

    fn find<'a>(results: &'a [DiagnosticResult], id: &str) -> Option<&'a DiagnosticResult> {
        results.iter().find(|result| result.id == id)
    }

    /// A config with isolation on and these exceptions.
    fn isolating(allow_cidrs: &[&str]) -> ResponseConfig {
        ResponseConfig {
            actions: ResponseActionsConfig {
                isolate_host: IsolationConfig {
                    enabled: true,
                    allow_cidrs: allow_cidrs.iter().map(|c| c.to_string()).collect(),
                    allow_dns: false,
                    allow_dhcp: false,
                    ..IsolationConfig::default()
                },
                ..Default::default()
            },
            ..ResponseConfig::default()
        }
    }

    #[test]
    fn nothing_is_checked_when_no_network_action_is_enabled() {
        let results = response_results(&ResponseConfig::default());

        assert!(find(&results, "response_isolation_exceptions").is_none());
        assert!(find(&results, "response_filtering_engine").is_none());
    }

    #[test]
    fn isolation_without_exceptions_fails_the_report() {
        // A failure rather than a warning: the action is switched on and
        // cannot run, which the operator would otherwise discover at the
        // moment they need it.
        let results = response_results(&isolating(&[]));

        let check = find(&results, "response_isolation_exceptions").expect("checked");
        assert_eq!(check.status, DiagnosticStatus::Fail);
        assert!(check.fix.is_some());
    }

    #[test]
    fn an_unparseable_exception_fails_rather_than_being_ignored() {
        let results = response_results(&isolating(&["10.0.0.0/8", "typo-here"]));

        let check = find(&results, "response_isolation_exceptions").expect("checked");
        assert_eq!(check.status, DiagnosticStatus::Fail);
        assert!(
            check
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("typo-here")),
            "the operator has to be told which entry did not take"
        );
    }

    #[test]
    fn valid_exceptions_pass_and_say_how_many() {
        let results = response_results(&isolating(&["10.0.0.0/8", "192.168.1.5"]));

        let check = find(&results, "response_isolation_exceptions").expect("checked");
        assert_eq!(check.status, DiagnosticStatus::Pass);
        assert!(check.message.contains("10.0.0.0/8"), "{}", check.message);
        assert!(
            check.message.contains("192.168.1.5/32"),
            "{}",
            check.message
        );
        assert!(
            check.message.contains("loopback"),
            "an operator needs to see that loopback survives: {}",
            check.message
        );
    }

    #[test]
    fn a_writable_quarantine_directory_passes() {
        let temp = tempfile::tempdir().expect("tempdir");
        let results = response_results(&ResponseConfig {
            quarantine_directory: temp.path().join("quarantine"),
            actions: ResponseActionsConfig {
                quarantine_file: ActionToggle::on(),
                ..Default::default()
            },
            ..ResponseConfig::default()
        });

        let check = find(&results, "response_quarantine_directory").expect("checked");
        assert_eq!(check.status, DiagnosticStatus::Pass);
    }

    #[test]
    fn the_quarantine_directory_is_only_checked_when_the_action_is_on() {
        let results = response_results(&ResponseConfig::default());
        assert!(find(&results, "response_quarantine_directory").is_none());
    }
}
