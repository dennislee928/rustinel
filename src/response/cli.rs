//! `rustinel response`: operating the containment the engine installs.
//!
//! Two of the engine's actions leave state behind that outlives the process
//! that created it. WFP filters sit in the kernel until something removes them,
//! and a quarantined file sits on disk until something restores it. Both need a
//! way to be inspected and undone by hand, because the situations where they
//! matter most are the ones where the agent is not running: a host isolated by
//! a rule that turned out to be wrong, or a file quarantined before a reboot.
//!
//! Everything here runs in a separate process from the service and reaches the
//! same state the service does, which is why isolation is found by enumerating
//! the kernel rather than by reading a file the service owns.

use crate::config::AppConfig;
use crate::response::executor::{quarantine::QuarantineStore, wfp};
use anyhow::Result;

/// What the operator asked for.
#[derive(clap::Subcommand, Clone)]
pub enum ResponseAction {
    /// Show what containment is currently in force
    Status,
    /// Cut this host off the network, keeping the configured exceptions
    Isolate {
        /// Apply without the confirmation prompt
        #[arg(long)]
        yes: bool,
    },
    /// Remove every network filter Rustinel installed
    Unisolate,
    /// List quarantined files
    Quarantine,
    /// Restore a quarantined file by its id
    Restore {
        /// Quarantine id, as shown by `rustinel response quarantine`
        #[arg(value_name = "ID")]
        id: String,
        /// Restore here instead of the original location
        #[arg(long, value_name = "PATH")]
        to: Option<std::path::PathBuf>,
    },
}

/// Run one response command.
pub fn run_cli(action: ResponseAction, config: &AppConfig) -> Result<i32> {
    let store = QuarantineStore::new(config.response.quarantine_directory.clone());

    match action {
        ResponseAction::Status => status(config, &store),
        ResponseAction::Isolate { yes } => isolate(config, yes),
        ResponseAction::Unisolate => unisolate(),
        ResponseAction::Quarantine => list_quarantine(&store),
        ResponseAction::Restore { id, to } => restore(&store, &id, to.as_deref()),
    }
}

fn status(config: &AppConfig, store: &QuarantineStore) -> Result<i32> {
    let response = &config.response;

    println!("Response");
    println!(
        "  mode:        {}",
        match (response.enabled, response.prevention_enabled) {
            (false, _) => "disabled",
            (true, false) => "dry run",
            (true, true) => "prevention",
        }
    );
    println!(
        "  policy:      {}",
        if response.rules.is_empty() {
            format!("severity floor at {}", response.min_severity)
        } else {
            format!("{} rule(s)", response.rules.len())
        }
    );

    println!("\nNetwork containment");
    match wfp::installed_filter_count() {
        Ok(0) => println!("  filters:     none installed"),
        Ok(count) => println!("  filters:     {count} installed; this host is contained"),
        Err(error) => println!("  filters:     unavailable ({error})"),
    }

    let isolation = &response.actions.isolate_host;
    if isolation.enabled && isolation.allow_cidrs.is_empty() && !isolation.allow_dns && !isolation.allow_dhcp {
        println!(
            "  WARNING:     isolate_host is enabled with no exceptions, so it will refuse to run"
        );
    }

    println!("\nQuarantine");
    let entries = store.list();
    if entries.is_empty() {
        println!("  files:       none");
    } else {
        println!("  files:       {}", entries.len());
        println!("  directory:   {}", store.root().display());
    }

    Ok(0)
}

fn isolate(config: &AppConfig, yes: bool) -> Result<i32> {
    let isolation = &config.response.actions.isolate_host;
    let policy = wfp::IsolationPolicy {
        allow_cidrs: isolation.allow_cidrs.clone(),
        allow_dns: isolation.allow_dns,
        allow_dhcp: isolation.allow_dhcp,
    };

    if policy.is_empty() {
        eprintln!(
            "Refusing to isolate: [response.actions.isolate_host] names no exception.\n\
             Cutting off a host reachable only over the network it just lost is an outage\n\
             this command cannot undo remotely. Set allow_cidrs, allow_dns, or allow_dhcp."
        );
        return Ok(2);
    }

    if !yes {
        println!("This will cut the host off the network, keeping only:");
        for cidr in &policy.allow_cidrs {
            println!("  - {cidr}");
        }
        if policy.allow_dns {
            println!("  - DNS");
        }
        if policy.allow_dhcp {
            println!("  - DHCP");
        }
        println!("\nRe-run with --yes to proceed.");
        return Ok(1);
    }

    let executor = wfp::WfpExecutor::new(policy, isolation.persistent);
    match executor.isolate_now() {
        Ok(count) => {
            println!("Isolated: {count} filters installed.");
            println!("Lift with: rustinel response unisolate");
            Ok(0)
        }
        Err(error) => {
            eprintln!("Isolation failed: {error}");
            Ok(1)
        }
    }
}

fn unisolate() -> Result<i32> {
    match wfp::unisolate() {
        Ok(0) => {
            println!("Nothing to remove; this host is not contained by Rustinel.");
            Ok(0)
        }
        Ok(count) => {
            println!("Removed {count} filters. Network access is restored.");
            Ok(0)
        }
        Err(error) => {
            eprintln!("Could not remove filters: {error}");
            Ok(1)
        }
    }
}

fn list_quarantine(store: &QuarantineStore) -> Result<i32> {
    let entries = store.list();

    if entries.is_empty() {
        println!("No quarantined files in {}.", store.root().display());
        return Ok(0);
    }

    println!("{:<20}  {:>10}  {}", "ID", "SIZE", "ORIGINAL PATH");
    for entry in entries {
        // The id is a SHA-256; the leading 16 characters identify it uniquely
        // enough to type, and `restore` accepts a prefix.
        println!(
            "{:<20}  {:>10}  {}",
            &entry.id[..entry.id.len().min(16)],
            entry.size,
            entry.original_path.display()
        );
    }

    Ok(0)
}

fn restore(
    store: &QuarantineStore,
    id: &str,
    to: Option<&std::path::Path>,
) -> Result<i32> {
    let full_id = match store.resolve_id(id) {
        Ok(id) => id,
        Err(error) => {
            eprintln!("{error}");
            return Ok(1);
        }
    };

    match store.restore(&full_id, to) {
        Ok(path) => {
            println!("Restored to {}.", path.display());
            Ok(0)
        }
        Err(error) => {
            eprintln!("Restore failed: {error}");
            Ok(1)
        }
    }
}
