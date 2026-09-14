//! Network containment on Linux and macOS.
//!
//! The counterpart to [`super::wfp`], which does the same job through the
//! Windows Filtering Platform. Linux goes through nftables and macOS through
//! `pf`; both are kernel packet filters, so like WFP these are the only
//! actions in the engine the kernel enforces rather than cleans up after.
//!
//! # The ruleset is built separately from being applied
//!
//! Everything that decides *what* to block is a pure function from an
//! [`IsolationPolicy`] to a ruleset string, and is unit-tested. Only the thin
//! part that hands that string to `nft` or `pfctl` touches the system.
//!
//! That split is deliberate. An isolation is the one action that can strand a
//! machine nobody can reach any more, and the way it strands one is a wrong
//! rule — an exception that did not make it into the ruleset, or a permit that
//! landed after the block. Those are exactly the mistakes a test can catch,
//! and they are worth catching somewhere other than on the host.
//!
//! # Why the default policy is drop rather than a drop rule
//!
//! Both backends set the chain policy to drop and then add accepts, instead of
//! adding a catch-all drop rule at the end. A rule can be shadowed by an
//! earlier one; a chain policy cannot. It is also what happens when the
//! ruleset is truncated or partially applied, which is the failure direction
//! containment should take.

use super::{ActionExecutor, Capabilities};
use crate::response::action::{
    ActionError, ActionKind, ActionReceipt, Enforcement, ResponseAction,
};
use crate::response::executor::wfp::{permitted_networks, IsolationPolicy};

/// Name of the nftables table and the `pf` anchor Rustinel owns.
///
/// Everything is installed under it and removed by it, so `unisolate` works
/// after a reboot or a lost state file, exactly as the WFP provider GUID does
/// on Windows.
pub const CONTAINER_NAME: &str = "rustinel";

/// Build the nftables ruleset for an isolation.
///
/// One `inet` table so a single ruleset covers IPv4 and IPv6: leaving IPv6
/// unfiltered is the classic way an "isolated" host stays reachable.
///
/// The table is flushed at the top of its own ruleset, which is what makes
/// applying it idempotent: isolating twice converges on the same state instead
/// of stacking a second copy of every rule.
// Built and tested on every platform, applied only where a backend exists:
// the ruleset logic is what carries the risk, so it is not hidden behind a
// target gate where only one CI runner would ever compile it.
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
pub(crate) fn nftables_ruleset(policy: &IsolationPolicy) -> String {
    let mut out = String::new();
    out.push_str(&format!("table inet {CONTAINER_NAME} {{\n"));

    for (chain, hook, direction) in [
        ("input", "input", Direction::Inbound),
        ("output", "output", Direction::Outbound),
    ] {
        out.push_str(&format!("  chain {chain} {{\n"));
        // Priority 0 and policy drop: the policy is the block, so a truncated
        // ruleset fails closed.
        out.push_str(&format!(
            "    type filter hook {hook} priority 0; policy drop;\n"
        ));
        // Established flows first: without this, an accepted outbound
        // connection's replies are dropped by the inbound chain and every
        // exception is one-way.
        out.push_str("    ct state established,related accept\n");
        out.push_str("    iif lo accept\n");
        out.push_str("    oif lo accept\n");

        for network in permitted_networks(policy) {
            let family = if network.is_ipv4() { "ip" } else { "ip6" };
            let field = match direction {
                Direction::Inbound => "saddr",
                Direction::Outbound => "daddr",
            };
            out.push_str(&format!("    {family} {field} {network} accept\n"));
        }

        if policy.allow_dns {
            out.push_str("    udp dport 53 accept\n");
            out.push_str("    tcp dport 53 accept\n");
        }
        if policy.allow_dhcp {
            out.push_str("    udp dport 67 accept\n");
            out.push_str("    udp dport 68 accept\n");
        }

        out.push_str("  }\n");
    }

    out.push_str("}\n");
    out
}

/// Build the `pf` anchor ruleset for an isolation.
///
/// `pf` takes the *last* matching rule unless one says `quick`, which is the
/// opposite of nftables and of most people's expectations. Every rule here is
/// `quick` so the order written is the order applied, and the block comes
/// first so a later accept cannot be lost.
// Built and tested on every platform, applied only where a backend exists:
// the ruleset logic is what carries the risk, so it is not hidden behind a
// target gate where only one CI runner would ever compile it.
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
pub(crate) fn pf_ruleset(policy: &IsolationPolicy) -> String {
    let mut out = String::new();

    // Loopback before anything else: a host that cannot reach itself loses
    // local IPC and breaks software unrelated to the incident.
    out.push_str("set skip on lo0\n");
    out.push_str("block drop all\n");

    for network in permitted_networks(policy) {
        out.push_str(&format!("pass quick from {network} to any\n"));
        out.push_str(&format!("pass quick from any to {network}\n"));
    }

    if policy.allow_dns {
        out.push_str("pass quick proto udp to any port 53\n");
        out.push_str("pass quick proto tcp to any port 53\n");
    }
    if policy.allow_dhcp {
        out.push_str("pass quick proto udp to any port 67\n");
        out.push_str("pass quick proto udp to any port 68\n");
    }

    // Replies to flows the host opened. `pf` keeps state on `pass` by default,
    // so this is about flows established before isolation began.
    out.push_str("pass quick proto tcp flags A/A\n");
    out
}

/// Which side of a connection a rule matches on.
#[derive(Debug, Clone, Copy)]
// Built and tested on every platform, applied only where a backend exists:
// the ruleset logic is what carries the risk, so it is not hidden behind a
// target gate where only one CI runner would ever compile it.
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
enum Direction {
    Inbound,
    Outbound,
}

/// Executor for network containment on Linux and macOS.
#[derive(Debug)]
pub struct HostFirewallExecutor {
    policy: IsolationPolicy,
    capabilities: Capabilities,
}

impl HostFirewallExecutor {
    /// Build the executor.
    pub fn new(policy: IsolationPolicy) -> Self {
        Self {
            policy,
            // Only isolation. Blocking one image's traffic needs a per-process
            // match that neither nftables nor `pf` offers the way WFP's
            // `ALE_APP_ID` does: nftables can match a cgroup and `pf` a user,
            // neither of which is "this executable". Claiming it here would
            // route the action away from an executor that could do it.
            capabilities: Capabilities::none("handled by another executor")
                .supporting(ActionKind::IsolateHost, Enforcement::Inline),
        }
    }

    /// The isolation exceptions this executor was built with.
    pub fn policy(&self) -> &IsolationPolicy {
        &self.policy
    }

    /// Isolate now, bypassing the action plumbing.
    ///
    /// The refusal on an empty exception list is a property of isolation, not
    /// of how it was asked for, so it applies here exactly as in
    /// [`super::wfp::WfpExecutor::isolate_now`].
    pub fn isolate_now(&self) -> Result<usize, String> {
        if self.policy.is_empty() {
            return Err(
                "isolation needs at least one exception; refusing to strand this host".to_string(),
            );
        }
        platform::isolate(&self.policy)
    }
}

impl ActionExecutor for HostFirewallExecutor {
    fn name(&self) -> &'static str {
        "host_firewall"
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    fn execute(&self, action: &ResponseAction) -> Result<ActionReceipt, ActionError> {
        let enforcement = self.reject_unsupported(action)?;
        let kind = action.kind();

        match action {
            ResponseAction::IsolateHost => {
                if self.policy.is_empty() {
                    return Err(ActionError::Failed {
                        kind,
                        reason: "isolation needs at least one exception under \
                                 [response.actions.isolate_host]; refusing to \
                                 strand this host"
                            .to_string(),
                    });
                }

                let rules = platform::isolate(&self.policy)
                    .map_err(|reason| ActionError::Failed { kind, reason })?;

                Ok(
                    ActionReceipt::new(kind, enforcement, "host_firewall", action.target_key())
                        .with_detail(format!("{rules} filter rules installed")),
                )
            }
            other => Err(ActionError::Unsupported {
                kind: other.kind(),
                reason: "not a network action",
            }),
        }
    }

    fn rollback(&self, receipt: &ActionReceipt) -> Result<(), ActionError> {
        platform::remove_all()
            .map(|_| ())
            .map_err(|reason| ActionError::Failed {
                kind: receipt.kind,
                reason,
            })
    }
}

/// Lift every rule Rustinel installed.
pub fn unisolate() -> Result<usize, String> {
    platform::remove_all()
}

/// How many rules Rustinel currently has installed.
pub fn installed_rule_count() -> Result<usize, String> {
    platform::count()
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{nftables_ruleset, IsolationPolicy, CONTAINER_NAME};
    use std::io::Write;
    use std::process::{Command, Stdio};

    /// Feed a ruleset to `nft -f -`.
    ///
    /// Through stdin rather than a temporary file: a ruleset naming the
    /// management networks that keep a host reachable should not be left on
    /// disk for something else to read, and a file would have to be cleaned up
    /// on a path where the machine may be about to lose the network.
    fn nft(ruleset: &str) -> Result<(), String> {
        let mut child = Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| format!("cannot run nft: {err}"))?;

        child
            .stdin
            .take()
            .ok_or("nft stdin unavailable")?
            .write_all(ruleset.as_bytes())
            .map_err(|err| format!("cannot write ruleset to nft: {err}"))?;

        let output = child
            .wait_with_output()
            .map_err(|err| format!("nft did not finish: {err}"))?;
        if !output.status.success() {
            return Err(format!(
                "nft rejected the ruleset: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        Ok(())
    }

    pub(super) fn isolate(policy: &IsolationPolicy) -> Result<usize, String> {
        let ruleset = nftables_ruleset(policy);

        // Delete first so isolating twice converges rather than stacking. A
        // missing table is the normal first-run case, so its failure is
        // ignored rather than reported.
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", CONTAINER_NAME])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        nft(&ruleset)?;
        count()
    }

    pub(super) fn remove_all() -> Result<usize, String> {
        let installed = count().unwrap_or(0);
        let status = Command::new("nft")
            .args(["delete", "table", "inet", CONTAINER_NAME])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|err| format!("cannot run nft: {err}"))?;

        // A table that is not there is the state the caller asked for.
        if !status.success() && installed > 0 {
            return Err("nft could not delete the rustinel table".to_string());
        }
        Ok(installed)
    }

    pub(super) fn count() -> Result<usize, String> {
        let output = Command::new("nft")
            .args(["list", "table", "inet", CONTAINER_NAME])
            .output()
            .map_err(|err| format!("cannot run nft: {err}"))?;

        if !output.status.success() {
            // No table means nothing installed, which is an answer rather than
            // a failure.
            return Ok(0);
        }
        Ok(super::count_rule_lines(&String::from_utf8_lossy(
            &output.stdout,
        )))
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::{pf_ruleset, IsolationPolicy, CONTAINER_NAME};
    use std::io::Write;
    use std::process::{Command, Stdio};

    /// Load the anchor's ruleset from stdin.
    ///
    /// An anchor keeps Rustinel's rules separate from whatever else the host
    /// has in `pf`, so removing them cannot take someone else's rules with
    /// them.
    fn pfctl_load(ruleset: &str) -> Result<(), String> {
        let mut child = Command::new("pfctl")
            .args(["-a", CONTAINER_NAME, "-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| format!("cannot run pfctl: {err}"))?;

        child
            .stdin
            .take()
            .ok_or("pfctl stdin unavailable")?
            .write_all(ruleset.as_bytes())
            .map_err(|err| format!("cannot write ruleset to pfctl: {err}"))?;

        let output = child
            .wait_with_output()
            .map_err(|err| format!("pfctl did not finish: {err}"))?;
        if !output.status.success() {
            return Err(format!(
                "pfctl rejected the ruleset: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        Ok(())
    }

    pub(super) fn isolate(policy: &IsolationPolicy) -> Result<usize, String> {
        // Loading an anchor replaces its contents, so this is already
        // convergent: isolating twice ends with one copy of the ruleset.
        pfctl_load(&pf_ruleset(policy))?;

        // `pf` is off by default on macOS. Enabling an already-enabled `pf`
        // reports an error that means "already done", so its status is not
        // treated as a failure.
        let _ = Command::new("pfctl")
            .arg("-e")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        count()
    }

    pub(super) fn remove_all() -> Result<usize, String> {
        let installed = count().unwrap_or(0);
        let status = Command::new("pfctl")
            .args(["-a", CONTAINER_NAME, "-F", "rules"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|err| format!("cannot run pfctl: {err}"))?;

        if !status.success() && installed > 0 {
            return Err("pfctl could not flush the rustinel anchor".to_string());
        }
        Ok(installed)
    }

    pub(super) fn count() -> Result<usize, String> {
        let output = Command::new("pfctl")
            .args(["-a", CONTAINER_NAME, "-s", "rules"])
            .output()
            .map_err(|err| format!("cannot run pfctl: {err}"))?;

        if !output.status.success() {
            return Ok(0);
        }
        Ok(super::count_rule_lines(&String::from_utf8_lossy(
            &output.stdout,
        )))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod platform {
    use super::IsolationPolicy;

    /// Windows contains through the filtering platform instead.
    pub(super) fn isolate(_policy: &IsolationPolicy) -> Result<usize, String> {
        Err("host firewall containment is Linux and macOS only".to_string())
    }

    pub(super) fn remove_all() -> Result<usize, String> {
        Ok(0)
    }

    pub(super) fn count() -> Result<usize, String> {
        Ok(0)
    }
}

/// Count the rule lines in a backend's own listing.
///
/// Blank lines and the block headers both backends print are not rules, and
/// counting them would report containment on a host that has none.
// Built and tested on every platform, applied only where a backend exists:
// the ruleset logic is what carries the risk, so it is not hidden behind a
// target gate where only one CI runner would ever compile it.
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
pub(crate) fn count_rule_lines(listing: &str) -> usize {
    listing
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && !line.ends_with('{')
                && !line.starts_with('}')
                && !line.starts_with("table ")
                && !line.starts_with("chain ")
                && !line.starts_with("type filter")
        })
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(cidrs: &[&str], dns: bool, dhcp: bool) -> IsolationPolicy {
        IsolationPolicy {
            allow_cidrs: cidrs.iter().map(|entry| entry.to_string()).collect(),
            allow_dns: dns,
            allow_dhcp: dhcp,
        }
    }

    /// The chain policy is the block, not a trailing rule.
    ///
    /// A drop *rule* can be shadowed by an earlier accept; a chain policy
    /// cannot, and a ruleset that is truncated part-way through still fails
    /// closed.
    #[test]
    fn nftables_blocks_by_chain_policy_in_both_directions() {
        let ruleset = nftables_ruleset(&policy(&["10.0.0.0/8"], false, false));

        assert_eq!(ruleset.matches("policy drop;").count(), 2);
        assert!(ruleset.contains("hook input priority 0"));
        assert!(ruleset.contains("hook output priority 0"));
    }

    /// Leaving IPv6 unfiltered is how an "isolated" host stays reachable.
    #[test]
    fn nftables_uses_one_inet_table_so_ipv6_is_covered() {
        let ruleset = nftables_ruleset(&policy(&["10.0.0.0/8"], false, false));
        assert!(ruleset.contains("table inet rustinel"));
    }

    /// Without this every exception is one-way: the outbound packet is
    /// accepted and the reply is dropped on the way back in.
    #[test]
    fn nftables_accepts_established_flows() {
        let ruleset = nftables_ruleset(&policy(&["10.0.0.0/8"], false, false));
        assert_eq!(
            ruleset
                .matches("ct state established,related accept")
                .count(),
            2
        );
    }

    /// Loopback is not optional: a host that cannot reach itself loses local
    /// IPC and breaks software unrelated to the incident.
    #[test]
    fn loopback_survives_isolation_on_both_backends() {
        let empty_ish = policy(&[], true, false);

        let nft = nftables_ruleset(&empty_ish);
        assert!(nft.contains("iif lo accept"));
        assert!(nft.contains("oif lo accept"));
        // `permitted_networks` appends loopback whatever the operator wrote.
        assert!(nft.contains("127.0.0.0/8"));
        assert!(nft.contains("::1/128"));

        assert!(pf_ruleset(&empty_ish).contains("set skip on lo0"));
    }

    /// An exception carries its prefix length.
    ///
    /// Dropping it would turn `10.0.0.0/8` into a permit for exactly one host
    /// and strand an operator who believed their management range was still
    /// reachable.
    #[test]
    fn an_exception_keeps_its_prefix_length() {
        let ruleset = nftables_ruleset(&policy(&["10.0.0.0/8", "192.168.1.5"], false, false));

        assert!(ruleset.contains("ip saddr 10.0.0.0/8 accept"));
        assert!(ruleset.contains("ip daddr 10.0.0.0/8 accept"));
        // A bare address becomes a host route rather than a whole network.
        assert!(ruleset.contains("192.168.1.5/32"));
    }

    #[test]
    fn ipv6_exceptions_are_written_as_ip6_rules() {
        let ruleset = nftables_ruleset(&policy(&["fd00::/8"], false, false));
        assert!(ruleset.contains("ip6 saddr fd00::/8 accept"));
        assert!(ruleset.contains("ip6 daddr fd00::/8 accept"));
    }

    #[test]
    fn dns_and_dhcp_are_only_opened_when_asked_for() {
        let without = nftables_ruleset(&policy(&["10.0.0.0/8"], false, false));
        assert!(!without.contains("dport 53"));
        assert!(!without.contains("dport 67"));

        let with = nftables_ruleset(&policy(&["10.0.0.0/8"], true, true));
        assert!(with.contains("udp dport 53 accept"));
        assert!(with.contains("tcp dport 53 accept"));
        assert!(with.contains("udp dport 67 accept"));
        assert!(with.contains("udp dport 68 accept"));
    }

    /// `pf` takes the last matching rule unless one says `quick`, which is the
    /// opposite of nftables. Every pass here must be `quick` or the block
    /// above it wins and the exceptions do nothing.
    #[test]
    fn every_pf_exception_is_quick_and_follows_the_block() {
        let ruleset = pf_ruleset(&policy(&["10.0.0.0/8"], true, false));

        let block_at = ruleset.find("block drop all").expect("a block");
        let pass_at = ruleset.find("pass quick").expect("a pass");
        assert!(block_at < pass_at, "the block must come before the passes");

        for line in ruleset.lines().filter(|line| line.starts_with("pass")) {
            assert!(line.starts_with("pass quick"), "not quick: {line}");
        }
    }

    #[test]
    fn an_empty_policy_is_refused_rather_than_stranding_the_host() {
        let executor = HostFirewallExecutor::new(IsolationPolicy::default());

        assert!(executor.isolate_now().is_err());

        let error = executor
            .execute(&ResponseAction::IsolateHost)
            .expect_err("an empty policy must be refused");
        match error {
            ActionError::Failed { reason, .. } => {
                assert!(reason.contains("at least one exception"))
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn only_isolation_is_claimed() {
        let executor = HostFirewallExecutor::new(policy(&["10.0.0.0/8"], false, false));
        let kinds = executor.capabilities().supported_kinds();

        assert!(kinds.contains(&ActionKind::IsolateHost));
        // Neither backend can match "this executable" the way WFP's ALE_APP_ID
        // does, so claiming it would strand the action here.
        assert!(!kinds.contains(&ActionKind::BlockProcessNetwork));
    }

    #[test]
    fn headers_and_blank_lines_are_not_counted_as_rules() {
        let listing = "table inet rustinel {\n  chain input {\n    \
                       type filter hook input priority 0; policy drop;\n    \
                       iif lo accept\n    ip saddr 10.0.0.0/8 accept\n  }\n}\n";
        assert_eq!(count_rule_lines(listing), 2);
    }
}
