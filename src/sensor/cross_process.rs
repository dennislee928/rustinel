//! Assembling cross-process events from FFI-free fields.
//!
//! One process reaching into another is the shape of both credential theft and
//! code injection, so it is the telemetry a rule about either needs. Windows
//! produces it from ETW; this is the equivalent for macOS, where the same
//! meaning arrives as Endpoint Security events with entirely different names.
//!
//! # Why this is not in `sensor::macos`
//!
//! The same reason `integrity_level` and `persistence` are not: everything
//! here is plain data assembly, and putting it behind a `target_os` gate would
//! mean it only ever compiled on one CI runner. The Endpoint Security types
//! stay in `sensor::macos::esf`, which extracts them and calls in here.
//!
//! # The macOS primitives, and why they are named rather than masked
//!
//! Windows answers "what access was obtained" with a mask, and Sysmon writes
//! it as `GrantedAccess`. macOS has no mask; it has several distinct calls,
//! and which one was used is the interesting part:
//!
//! - `task_for_pid` hands over the task *control* port: full read and write of
//!   another process's memory, and the ability to create threads in it. It is
//!   how credential theft and injection both start.
//! - A task *read* port grants memory reads without writes. Enough to steal
//!   secrets, not enough to inject.
//! - `ptrace` attaches a debugger, which on macOS is separately restricted and
//!   is a different signal from either.
//!
//! Collapsing those into one event would lose the distinction, so the method
//! is recorded and `GrantedAccess` is left empty rather than filled with a
//! Windows-shaped number that does not mean anything here.

use crate::models::{ProcessAccessFields, RemoteThreadFields};
use crate::sensor::{
    Platform, ProcessStartKey, SensorAction, SensorEvent, SensorNormalization, SensorPayload,
};
use std::time::SystemTime;

/// Sysmon's event ID for a remote thread creation.
///
/// Matched to Sysmon so a stock SigmaHQ rule selecting on `EventID: 8` rather
/// than on logsource still fires, exactly as the Windows sensor does.
pub(crate) const EVENT_ID_REMOTE_THREAD: u16 = 8;

/// Sysmon's event ID for process access.
pub(crate) const EVENT_ID_PROCESS_ACCESS: u16 = 10;

/// How one process reached another.
///
/// The spelling is what a rule matches on, so these are a detection contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AccessMethod {
    /// `ptrace`: debugger attach. The one primitive both platforms have.
    Ptrace,
    /// `task_for_pid`: the task control port. Read, write, and thread creation.
    TaskForPid,
    /// A task read port: memory reads without writes.
    TaskRead,
}

impl AccessMethod {
    /// The value written to the event.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Ptrace => "ptrace",
            Self::TaskForPid => "task_for_pid",
            Self::TaskRead => "task_read_port",
        }
    }
}

/// One process reaching into another, with the FFI already peeled off.
#[derive(Debug, Clone)]
pub(crate) struct RawCrossProcess {
    /// Which sensor produced it.
    pub platform: Platform,
    /// The sensor's own name, recorded on the event.
    pub provider: &'static str,
    /// The process doing the reaching.
    pub source_pid: u32,
    /// Its executable, when known.
    pub source_image: Option<String>,
    /// The process being reached into.
    pub target_pid: u32,
    /// Its executable, when known.
    pub target_image: Option<String>,
    /// Real UID of the acting process.
    pub user: Option<String>,
    /// When it happened.
    pub event_time: SystemTime,
    /// Native ordering token, when the source has one.
    pub source_seq: Option<u64>,
    /// Start key of the acting process, for PID-reuse safety.
    pub process_start_key: Option<ProcessStartKey>,
}

/// Build a process-access event.
///
/// `pid` is the *source*: the actor is what the pipeline keys enrichment and
/// response on, and responding to a credential dump means acting on the
/// process doing the reading, not on `lsass`.
pub(crate) fn process_access_event(raw: RawCrossProcess, method: AccessMethod) -> SensorEvent {
    SensorEvent {
        platform: raw.platform,
        provider: raw.provider,
        action: SensorAction::Access,
        normalization: SensorNormalization {
            event_id: EVENT_ID_PROCESS_ACCESS,
            action_code: 1,
        },
        pid: Some(raw.source_pid),
        timestamp: raw.event_time,
        source_seq: raw.source_seq,
        process_start_key: raw.process_start_key,
        parent_process_start_key: None,
        payload: SensorPayload::ProcessAccess(ProcessAccessFields {
            source_process_id: Some(raw.source_pid.to_string()),
            source_image: raw.source_image,
            target_process_id: Some(raw.target_pid.to_string()),
            target_image: raw.target_image,
            // No mask exists on macOS; the method is the answer instead.
            granted_access: None,
            access_method: Some(method.as_str().to_string()),
            target_thread_id: None,
            user: raw.user,
        }),
    }
}

/// Build a remote-thread event.
///
/// macOS reports the thread's entry point only for `thread_create_running`,
/// and even then as register state rather than a resolved symbol, so
/// `StartAddress`, `StartModule`, and `StartFunction` are left empty. A rule
/// that matches on them will not fire here, which is the honest outcome: the
/// alternative is inventing a value it would match against.
pub(crate) fn remote_thread_event(raw: RawCrossProcess) -> SensorEvent {
    SensorEvent {
        platform: raw.platform,
        provider: raw.provider,
        action: SensorAction::Start,
        normalization: SensorNormalization {
            event_id: EVENT_ID_REMOTE_THREAD,
            action_code: 1,
        },
        pid: Some(raw.source_pid),
        timestamp: raw.event_time,
        source_seq: raw.source_seq,
        process_start_key: raw.process_start_key,
        parent_process_start_key: None,
        payload: SensorPayload::RemoteThread(RemoteThreadFields {
            source_process_id: Some(raw.source_pid.to_string()),
            source_image: raw.source_image,
            target_process_id: Some(raw.target_pid.to_string()),
            target_image: raw.target_image,
            start_address: None,
            start_module: None,
            start_function: None,
            user: raw.user,
        }),
    }
}

/// Whether a cross-process event is worth reporting at all.
///
/// A process reaching into *itself* is ordinary: a debugger inspecting its own
/// state, a runtime remapping its own memory, a thread starting in the process
/// that asked for it. Reporting those would bury the cross-process case that
/// matters under the one that never does, which is the same filter the Windows
/// sensor applies to thread starts.
pub(crate) fn is_cross_process(source_pid: u32, target_pid: u32) -> bool {
    source_pid != target_pid
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw() -> RawCrossProcess {
        RawCrossProcess {
            platform: Platform::MacOS,
            provider: "esf",
            source_pid: 501,
            source_image: Some("/tmp/dumper".to_string()),
            target_pid: 88,
            target_image: Some("/usr/sbin/securityd".to_string()),
            user: Some("501".to_string()),
            event_time: SystemTime::UNIX_EPOCH,
            source_seq: Some(9),
            process_start_key: Some(ProcessStartKey {
                pid: 501,
                start_time: 1_700_000_000,
            }),
        }
    }

    /// A stock SigmaHQ rule may select on `EventID: 10` rather than on
    /// logsource, so the id has to be Sysmon's.
    #[test]
    fn process_access_carries_sysmons_event_id() {
        let event = process_access_event(raw(), AccessMethod::TaskForPid);

        assert_eq!(event.normalization.event_id, EVENT_ID_PROCESS_ACCESS);
        assert_eq!(event.action, SensorAction::Access);
        assert_eq!(event.platform, Platform::MacOS);
        assert_eq!(event.provider, "esf");
    }

    #[test]
    fn remote_thread_carries_sysmons_event_id() {
        let event = remote_thread_event(raw());

        assert_eq!(event.normalization.event_id, EVENT_ID_REMOTE_THREAD);
        assert_eq!(event.action, SensorAction::Start);
    }

    /// The actor is what response acts on: answering a credential dump means
    /// killing the reader, not the process being read.
    #[test]
    fn the_event_is_keyed_on_the_process_doing_the_reaching() {
        let event = process_access_event(raw(), AccessMethod::TaskForPid);

        assert_eq!(event.pid, Some(501));
        match event.payload {
            SensorPayload::ProcessAccess(fields) => {
                assert_eq!(fields.source_process_id.as_deref(), Some("501"));
                assert_eq!(fields.target_process_id.as_deref(), Some("88"));
                assert_eq!(fields.source_image.as_deref(), Some("/tmp/dumper"));
                assert_eq!(fields.target_image.as_deref(), Some("/usr/sbin/securityd"));
            }
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    /// The three primitives permit materially different things, so a rule has
    /// to be able to tell them apart.
    #[test]
    fn each_primitive_is_named_rather_than_masked() {
        for (method, expected) in [
            (AccessMethod::Ptrace, "ptrace"),
            (AccessMethod::TaskForPid, "task_for_pid"),
            (AccessMethod::TaskRead, "task_read_port"),
        ] {
            let event = process_access_event(raw(), method);
            match event.payload {
                SensorPayload::ProcessAccess(fields) => {
                    assert_eq!(fields.access_method.as_deref(), Some(expected));
                    // macOS has no access mask; inventing one would give rules
                    // a number to match that means nothing on this platform.
                    assert!(fields.granted_access.is_none());
                }
                other => panic!("unexpected payload: {other:?}"),
            }
        }
    }

    /// Entry points are not resolvable from what macOS reports, and guessing
    /// one would make a rule match something that was never observed.
    #[test]
    fn a_remote_thread_reports_no_entry_point_it_cannot_know() {
        let event = remote_thread_event(raw());

        match event.payload {
            SensorPayload::RemoteThread(fields) => {
                assert!(fields.start_address.is_none());
                assert!(fields.start_module.is_none());
                assert!(fields.start_function.is_none());
                assert_eq!(fields.target_image.as_deref(), Some("/usr/sbin/securityd"));
            }
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    /// The same assembly serves both sensors, so a rule written against one
    /// platform's cross-process events reads the other's identically.
    #[test]
    fn the_linux_sensor_produces_the_same_shape() {
        let raw = RawCrossProcess {
            platform: Platform::Linux,
            provider: "ebpf",
            ..raw()
        };
        let event = process_access_event(raw, AccessMethod::Ptrace);

        assert_eq!(event.platform, Platform::Linux);
        assert_eq!(event.provider, "ebpf");
        assert_eq!(event.normalization.event_id, EVENT_ID_PROCESS_ACCESS);
        match event.payload {
            SensorPayload::ProcessAccess(fields) => {
                assert_eq!(fields.access_method.as_deref(), Some("ptrace"));
            }
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    /// Self-access is the overwhelming majority of these events and carries no
    /// signal; letting it through would bury the case that does.
    #[test]
    fn a_process_reaching_into_itself_is_not_reported() {
        assert!(!is_cross_process(501, 501));
        assert!(is_cross_process(501, 88));
    }
}
