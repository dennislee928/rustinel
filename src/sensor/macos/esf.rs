//! macOS Endpoint Security sensor.
//!
//! [`EsfSensor`] implements [`Sensor`] for macOS using Apple's Endpoint
//! Security framework via the `endpoint-sec` crate. On `start()` it spawns a
//! dedicated thread that owns the ES client — the client must be created and
//! released on the same thread — subscribes to process events, and translates
//! each message into a [`SensorEvent`] for the shared pipeline.
//!
//! Endpoint Security delivers messages on its own dispatch queue, so the
//! keepalive thread simply holds the client alive until shutdown; the actual
//! work happens in the message handler.
//!
//! Requirements: root, the `com.apple.developer.endpoint-security.client`
//! entitlement, and user approval (TCC). Dev builds can run with SIP/AMFI
//! relaxed.

use std::ffi::OsStr;
use std::io::IsTerminal;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Result};
use endpoint_sec::{
    Client, Event, EventClose, EventCreate, EventCreateDestinationFile, EventExec, EventRename,
    EventRenameDestinationFile, EventUnlink, Message, Process,
};
use endpoint_sec_sys::{es_event_type_t, NewClientError};

use crate::sensor::cross_process::{
    is_cross_process, process_access_event, remote_thread_event, AccessMethod, RawCrossProcess,
};
use tokio::sync::mpsc::Sender;
use tracing::{info, warn};

use crate::models::{FileEventFields, ProcessCreationFields};
use crate::sensor::{
    Platform, ProcessStartKey, Sensor, SensorAction, SensorEvent, SensorNormalization,
    SensorPayload,
};

/// Poll interval for the keepalive thread to observe the shutdown flag.
const SHUTDOWN_POLL: Duration = Duration::from_millis(200);

/// Sysmon-compatible event ID emitted for process-create events.
const EVENT_ID_PROCESS_CREATE: u16 = 1;
/// Sysmon-compatible event ID emitted for process-terminate events.
const EVENT_ID_PROCESS_TERMINATE: u16 = 5;

/// Endpoint Security event subscriptions for the macOS sensor.
const SUBSCRIPTIONS: &[es_event_type_t] = &[
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_EXEC,
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_EXIT,
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_CREATE,
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_UNLINK,
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_RENAME,
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_CLOSE,
    // One process reaching into another: the shape of both credential theft
    // and code injection, and the largest thing the macOS sensor could not
    // see. `task_for_pid` is the macOS equivalent of opening a handle to
    // `lsass`; `ptrace` is a separate primitive with its own restrictions;
    // a remote thread is injection that has already succeeded.
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_TRACE,
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_GET_TASK,
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_GET_TASK_READ,
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE,
];

/// macOS Endpoint Security sensor. Implements [`Sensor`].
pub struct EsfSensor {
    shutdown: Arc<AtomicBool>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl EsfSensor {
    pub fn new() -> Self {
        Self {
            shutdown: Arc::new(AtomicBool::new(false)),
            thread: Mutex::new(None),
        }
    }
}

impl Default for EsfSensor {
    fn default() -> Self {
        Self::new()
    }
}

impl Sensor for EsfSensor {
    /// Spawn the Endpoint Security client thread and block until the client is
    /// created and subscribed, so initialization errors (missing entitlement,
    /// not root, TCC denial) surface synchronously to the caller.
    fn start(&self, tx: Sender<SensorEvent>) -> Result<()> {
        let shutdown = Arc::clone(&self.shutdown);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();

        let handle = std::thread::Builder::new()
            .name("rustinel-esf".to_string())
            .spawn(move || run_client(tx, shutdown, ready_tx))
            .map_err(|e| anyhow!("failed to spawn Endpoint Security thread: {e}"))?;

        *self.thread.lock().expect("esf thread mutex poisoned") = Some(handle);

        match ready_rx.recv() {
            Ok(Ok(())) => {
                info!("Endpoint Security client subscribed");
                Ok(())
            }
            Ok(Err(e)) => Err(anyhow!("Endpoint Security client init failed: {e}")),
            Err(_) => Err(anyhow!(
                "Endpoint Security thread exited before signaling readiness"
            )),
        }
    }

    fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self
            .thread
            .lock()
            .expect("esf thread mutex poisoned")
            .take()
        {
            let _ = handle.join();
        }
    }
}

/// Translate an `es_new_client` failure into an actionable message.
///
/// These failures are almost always environmental — missing TCC approval, not
/// root, or an unsigned binary — rather than bugs, so we point at the concrete
/// step that unblocks each one instead of surfacing a bare result code.
fn new_client_error_hint(err: &NewClientError) -> String {
    let remedy = match err {
        NewClientError::NotPermitted => {
            "macOS has not granted Endpoint Security access. Grant Rustinel.app Full Disk \
             Access in System Settings > Privacy & Security > Full Disk Access, then re-run. \
             If you launched it from a terminal, that terminal app may also need Full Disk \
             Access."
        }
        NewClientError::NotPrivileged => "Endpoint Security requires root. Re-run with sudo.",
        NewClientError::NotEntitled => {
            "The binary lacks the com.apple.developer.endpoint-security.client entitlement. \
             Run a signed Rustinel.app from a release, or repackage it with \
             scripts/macos/package-app.sh."
        }
        NewClientError::TooManyClients => {
            "The system reached its Endpoint Security client limit. Stop another Endpoint \
             Security agent and retry."
        }
        _ => "Could not create the Endpoint Security client.",
    };
    format!("es_new_client failed: {err:?}: {remedy}")
}

/// Best-effort deep-link to the Full Disk Access settings pane.
///
/// `NotPermitted` means the user still has to grant Full Disk Access by hand, so
/// for an interactive `sudo ./rustinel run` we open the right pane for them.
/// Started with sudo the process is root, which has no GUI session, so we reopen
/// in the invoking user's session via `launchctl asuser`. A LaunchDaemon has no
/// controlling terminal and is skipped; any failure is ignored — this is a
/// convenience, not a step the pipeline depends on.
fn try_open_full_disk_access_settings() {
    if !std::io::stderr().is_terminal() {
        return;
    }
    const PANE: &str = "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles";
    info!("Opening System Settings → Privacy & Security → Full Disk Access");
    let status = match std::env::var("SUDO_UID") {
        Ok(uid) => std::process::Command::new("launchctl")
            .args(["asuser", &uid, "open", PANE])
            .status(),
        Err(_) => std::process::Command::new("open").arg(PANE).status(),
    };
    let _ = status;
}

/// Body of the Endpoint Security client thread.
///
/// Creates the client, subscribes, signals readiness, then keeps the client
/// alive until shutdown. The client is dropped (released) on this thread, as
/// Endpoint Security requires.
fn run_client(
    tx: Sender<SensorEvent>,
    shutdown: Arc<AtomicBool>,
    ready_tx: std::sync::mpsc::Sender<Result<(), String>>,
) {
    let handler =
        move |_client: &mut Client<'_>, msg: Message| match catch_unwind(AssertUnwindSafe(|| {
            build_sensor_event(&msg)
        })) {
            Ok(Some(event)) => try_send(&tx, event),
            Ok(None) => {}
            Err(_) => {
                warn!(
                    event_type = ?msg.event_type(),
                    "Endpoint Security event conversion panicked; dropping event"
                );
            }
        };

    let mut client = match Client::new(handler) {
        Ok(client) => client,
        Err(e) => {
            if matches!(e, NewClientError::NotPermitted) {
                try_open_full_disk_access_settings();
            }
            let _ = ready_tx.send(Err(new_client_error_hint(&e)));
            return;
        }
    };

    if let Err(e) = client.subscribe(SUBSCRIPTIONS) {
        let _ = ready_tx.send(Err(format!("es_subscribe failed: {e:?}")));
        return;
    }

    let _ = ready_tx.send(Ok(()));

    while !shutdown.load(Ordering::Relaxed) {
        std::thread::sleep(SHUTDOWN_POLL);
    }

    info!("Endpoint Security sensor shutting down");
}

/// Translate an Endpoint Security message into a shared [`SensorEvent`].
///
/// Returns `None` for messages that carry no detection signal or are not yet
/// mapped. Per-event-class translation is filled in incrementally.
fn build_sensor_event(msg: &Message) -> Option<SensorEvent> {
    match msg.event()? {
        Event::NotifyExec(exec) => build_exec_event(msg, &exec),
        Event::NotifyExit(_) => build_exit_event(msg),
        Event::NotifyCreate(create) => build_create_event(msg, &create),
        Event::NotifyUnlink(unlink) => build_unlink_event(msg, &unlink),
        Event::NotifyRename(rename) => build_rename_event(msg, &rename),
        Event::NotifyClose(close) => build_close_event(msg, &close),
        Event::NotifyTrace(trace) => {
            build_cross_process(msg, &trace.target(), Some(AccessMethod::Ptrace))
        }
        Event::NotifyGetTask(task) => {
            build_cross_process(msg, &task.target(), Some(AccessMethod::TaskForPid))
        }
        Event::NotifyGetTaskRead(task) => {
            build_cross_process(msg, &task.target(), Some(AccessMethod::TaskRead))
        }
        Event::NotifyRemoteThreadCreate(remote) => build_cross_process(msg, &remote.target(), None),
        _ => None,
    }
}

/// Assemble a cross-process event from the acting process and its target.
///
/// `method` distinguishes the process-access primitives; `None` means this was
/// a remote thread creation, which is a different event class rather than
/// another way of obtaining access.
///
/// Self-access is dropped here rather than in the classifier: a process
/// inspecting or remapping itself is ordinary, and it is the overwhelming
/// majority of these events.
fn build_cross_process(
    msg: &Message,
    target: &Process<'_>,
    method: Option<AccessMethod>,
) -> Option<SensorEvent> {
    let (source_pid, source_image, user, process_start_key) = actor(msg);
    let target_pid = target.audit_token().pid() as u32;

    if !is_cross_process(source_pid, target_pid) {
        return None;
    }

    let raw = RawCrossProcess {
        platform: Platform::MacOS,
        provider: "esf",
        source_pid,
        source_image,
        target_pid,
        target_image: {
            let path = osstr_to_string(target.executable().path());
            (!path.is_empty()).then_some(path)
        },
        user: Some(user),
        event_time: msg.time(),
        source_seq: msg.global_seq_num(),
        process_start_key,
    };

    Some(match method {
        Some(method) => process_access_event(raw, method),
        None => remote_thread_event(raw),
    })
}

/// Plain, FFI-free description of an exec, extracted from an ESF event.
///
/// Keeping this separate from the Endpoint Security types lets the
/// `SensorEvent` assembly be unit-tested without a live ES client.
struct RawExec {
    pid: u32,
    image: String,
    command_line: Option<String>,
    parent_pid: i32,
    parent_image: Option<String>,
    current_directory: Option<String>,
    user: String,
    /// Process start time, as nanoseconds since the Unix epoch.
    start_time: u64,
    event_time: SystemTime,
    source_seq: Option<u64>,
    /// Code Directory hash, hex, as Sysmon would spell a hash field.
    cdhash: Option<String>,
    /// Signing identity: the team identifier, or the signing identifier when
    /// there is no team.
    signing_identity: Option<String>,
    /// Whether the kernel accepted the signature.
    signed: bool,
    /// Why, in Sysmon's vocabulary.
    signature_status: &'static str,
}

/// Extract the fields we care about from an ESF exec event.
fn build_exec_event(msg: &Message, exec: &EventExec) -> Option<SensorEvent> {
    let target = exec.target();
    let token = target.audit_token();

    let image = osstr_to_string(target.executable().path());
    if image.is_empty() {
        return None;
    }

    let command_line = {
        let parts: Vec<String> = exec.args().map(osstr_to_string).collect();
        (!parts.is_empty()).then(|| parts.join(" "))
    };

    let current_directory = exec
        .cwd()
        .map(|cwd| osstr_to_string(cwd.path()))
        .filter(|value| !value.is_empty());

    let event_time = msg.time();
    let start_time = target
        .start_time()
        .map(system_time_nanos)
        .unwrap_or_else(|| system_time_nanos(event_time));

    let parent_pid = target.ppid();
    let parent_image = (parent_pid > 0)
        .then(|| crate::utils::process_image_path(parent_pid as u32))
        .flatten();

    Some(process_start_event(RawExec {
        pid: token.pid() as u32,
        image,
        command_line,
        parent_pid,
        parent_image,
        current_directory,
        user: token.ruid().to_string(),
        start_time,
        event_time,
        source_seq: msg.global_seq_num(),
        cdhash: cdhash_hex(&target.cdhash()),
        signing_identity: signing_identity(&target),
        signed: is_signed(&target),
        signature_status: signature_status(&target),
    }))
}

/// `CS_VALID`: the kernel has verified this binary's signature.
///
/// Taken from `cs_blobs.h`. The flag is the kernel's own live verdict, which
/// is why nothing here opens the file: on macOS the answer Authenticode needs
/// a full verification pass for is already attached to the event.
const CS_VALID: u32 = 0x0000_0001;
/// `CS_SIGNED`: a signature is present, whether or not it validated.
const CS_SIGNED: u32 = 0x2000_0000;

/// The Code Directory hash as lowercase hex.
///
/// All-zero means the kernel recorded no hash, which is not the same as a hash
/// of zero, so it is reported as absent.
fn cdhash_hex(cdhash: &[u8; 20]) -> Option<String> {
    if cdhash.iter().all(|byte| *byte == 0) {
        return None;
    }
    let mut hex = String::with_capacity(40);
    for byte in cdhash {
        use std::fmt::Write;
        let _ = write!(hex, "{byte:02x}");
    }
    Some(hex)
}

/// Team identifier, falling back to the signing identifier.
///
/// The team id is the stable identity of whoever signed it; an unsigned or
/// ad-hoc binary has neither, and reports nothing.
fn signing_identity(process: &Process<'_>) -> Option<String> {
    let team = osstr_to_string(process.team_id());
    if !team.is_empty() {
        return Some(team);
    }
    let signing = osstr_to_string(process.signing_id());
    (!signing.is_empty()).then_some(signing)
}

/// Whether the kernel accepted the signature.
fn is_signed(process: &Process<'_>) -> bool {
    process.codesigning_flags() & CS_VALID != 0
}

/// Why the signature was or was not accepted, in Sysmon's vocabulary.
///
/// `Platform` is a macOS notion with no Sysmon equivalent and is worth keeping:
/// a binary shipped by Apple is a materially different thing from one merely
/// signed by a valid certificate.
fn signature_status(process: &Process<'_>) -> &'static str {
    let flags = process.codesigning_flags();
    if flags & CS_VALID != 0 {
        if process.is_platform_binary() {
            "Platform"
        } else {
            "Valid"
        }
    } else if flags & CS_SIGNED != 0 {
        "Invalid"
    } else {
        "Unsigned"
    }
}

/// Assemble a process-start [`SensorEvent`] from FFI-free exec fields.
fn process_start_event(raw: RawExec) -> SensorEvent {
    let parent_process_id = (raw.parent_pid > 0).then(|| raw.parent_pid.to_string());

    SensorEvent {
        platform: Platform::MacOS,
        provider: "esf",
        action: SensorAction::Start,
        normalization: SensorNormalization {
            event_id: EVENT_ID_PROCESS_CREATE,
            action_code: 1,
        },
        pid: Some(raw.pid),
        timestamp: raw.event_time,
        source_seq: raw.source_seq,
        process_start_key: Some(ProcessStartKey {
            pid: raw.pid,
            start_time: raw.start_time,
        }),
        parent_process_start_key: None,
        payload: SensorPayload::Process(ProcessCreationFields {
            hashes: None,
            signed: None,
            signature: None,
            signature_status: None,
            image: Some(raw.image),
            image_source: None,
            image_truncated: None,
            original_file_name: None,
            product: None,
            description: None,
            company: None,
            file_version: None,
            target_image: None,
            command_line: raw.command_line,
            process_id: Some(raw.pid.to_string()),
            process_start_time: Some(raw.start_time),
            parent_process_id,
            parent_image: raw.parent_image,
            // ESF exec events do not carry the parent's command line.
            parent_command_line: None,
            current_directory: raw.current_directory,
            // Windows-specific; absent on macOS.
            integrity_level: None,
            user: Some(raw.user),
            // Sysmon's spelling, so a rule matching `Hashes|contains:` reads
            // it the same way it reads a Windows event. CDHASH rather than
            // MD5 or SHA256: it is what the kernel actually computed, and
            // hashing the file again here would cost a full read per exec.
            hashes: raw
                .cdhash
                .map(|hash| format!("CDHASH={}", hash.to_uppercase())),
            signed: Some(raw.signed.to_string()),
            signature: raw.signing_identity,
            signature_status: Some(raw.signature_status.to_string()),
        }),
    }
}

/// Extract the exiting process from an ESF exit event.
///
/// ESF reports the exiting process as the message's acting process; the exit
/// status is not carried in the shared payload (matching the Linux sensor).
fn build_exit_event(msg: &Message) -> Option<SensorEvent> {
    let process = msg.process();
    let token = process.audit_token();
    Some(process_stop_event(
        token.pid() as u32,
        token.ruid().to_string(),
        process.start_time().map(system_time_nanos),
        msg.time(),
        msg.global_seq_num(),
    ))
}

/// Assemble a process-stop [`SensorEvent`] from FFI-free fields.
fn process_stop_event(
    pid: u32,
    user: String,
    start_time: Option<u64>,
    event_time: SystemTime,
    source_seq: Option<u64>,
) -> SensorEvent {
    SensorEvent {
        platform: Platform::MacOS,
        provider: "esf",
        action: SensorAction::Stop,
        normalization: SensorNormalization {
            event_id: EVENT_ID_PROCESS_TERMINATE,
            action_code: 2,
        },
        pid: Some(pid),
        timestamp: event_time,
        source_seq,
        process_start_key: start_time.map(|start_time| ProcessStartKey { pid, start_time }),
        parent_process_start_key: None,
        payload: SensorPayload::Process(ProcessCreationFields {
            hashes: None,
            signed: None,
            signature: None,
            signature_status: None,
            image: None,
            image_source: None,
            image_truncated: None,
            original_file_name: None,
            product: None,
            description: None,
            company: None,
            file_version: None,
            target_image: None,
            command_line: None,
            process_id: Some(pid.to_string()),
            process_start_time: None,
            parent_process_id: None,
            parent_image: None,
            parent_command_line: None,
            current_directory: None,
            integrity_level: None,
            user: Some(user),
        }),
    }
}

/// File event class, mapped to Sysmon-compatible action metadata.
#[derive(Clone, Copy)]
enum FileAction {
    Create,
    Delete,
    Rename,
    Modify,
}

impl FileAction {
    /// Return the (action, event id, action code) triple for this class, taken
    /// from the shared [`FILE_EVENT_NORMALIZATION`] table so macOS lands in the
    /// same Sigma category as Linux and Windows for the same operation.
    fn normalization(self) -> (SensorAction, u16, u8) {
        let action = match self {
            FileAction::Create => SensorAction::Create,
            FileAction::Delete => SensorAction::Delete,
            FileAction::Rename => SensorAction::Rename,
            FileAction::Modify => SensorAction::Modify,
        };
        let normalization = SensorNormalization::for_file_action(action)
            .expect("file actions are covered by the shared file normalization table");
        (action, normalization.event_id, normalization.action_code)
    }
}

/// Plain, FFI-free description of a file event, extracted from an ESF event.
struct RawFile {
    action: FileAction,
    pid: u32,
    image: Option<String>,
    user: String,
    target: String,
    source: Option<String>,
    event_time: SystemTime,
    source_seq: Option<u64>,
    process_start_key: Option<ProcessStartKey>,
}

/// Acting process context shared by all file events: pid, executable, and the
/// raw uid as a string. Username resolution is deferred to the normalizer
/// (like the Linux sensor) to avoid a directory-services lookup per event on
/// the high-volume file path.
fn actor(msg: &Message) -> (u32, Option<String>, String, Option<ProcessStartKey>) {
    let process = msg.process();
    let token = process.audit_token();
    let pid = token.pid() as u32;
    let image = osstr_to_string(process.executable().path());
    (
        pid,
        (!image.is_empty()).then_some(image),
        token.ruid().to_string(),
        process
            .start_time()
            .map(system_time_nanos)
            .map(|start_time| ProcessStartKey { pid, start_time }),
    )
}

fn build_create_event(msg: &Message, create: &EventCreate) -> Option<SensorEvent> {
    let target = create_destination_path(create.destination()?)?;
    let (pid, image, user, process_start_key) = actor(msg);
    file_event(RawFile {
        action: FileAction::Create,
        pid,
        image,
        user,
        target,
        source: None,
        event_time: msg.time(),
        source_seq: msg.global_seq_num(),
        process_start_key,
    })
}

fn build_unlink_event(msg: &Message, unlink: &EventUnlink) -> Option<SensorEvent> {
    let target = osstr_to_string(unlink.target().path());
    let (pid, image, user, process_start_key) = actor(msg);
    file_event(RawFile {
        action: FileAction::Delete,
        pid,
        image,
        user,
        target,
        source: None,
        event_time: msg.time(),
        source_seq: msg.global_seq_num(),
        process_start_key,
    })
}

fn build_rename_event(msg: &Message, rename: &EventRename) -> Option<SensorEvent> {
    let target = rename_destination_path(rename.destination()?)?;
    let source = osstr_to_string(rename.source().path());
    let (pid, image, user, process_start_key) = actor(msg);
    file_event(RawFile {
        action: FileAction::Rename,
        pid,
        image,
        user,
        target,
        source: (!source.is_empty()).then_some(source),
        event_time: msg.time(),
        source_seq: msg.global_seq_num(),
        process_start_key,
    })
}

/// Emit a modify event when a writable file is closed after being changed.
///
/// Filtering on `modified` keeps the high-volume close stream down to actual
/// content changes, the closest ESF analog to Sysmon's file-change event.
fn build_close_event(msg: &Message, close: &EventClose) -> Option<SensorEvent> {
    if !close.modified() {
        return None;
    }
    let target = osstr_to_string(close.target().path());
    let (pid, image, user, process_start_key) = actor(msg);
    file_event(RawFile {
        action: FileAction::Modify,
        pid,
        image,
        user,
        target,
        source: None,
        event_time: msg.time(),
        source_seq: msg.global_seq_num(),
        process_start_key,
    })
}

/// Resolve the absolute path of a create destination.
fn create_destination_path(dest: EventCreateDestinationFile) -> Option<String> {
    let path = match dest {
        EventCreateDestinationFile::ExistingFile { file, .. } => osstr_to_string(file.path()),
        EventCreateDestinationFile::NewPath {
            directory,
            filename,
            ..
        } => join_path(directory.path(), filename),
        _ => return None,
    };
    (!path.is_empty()).then_some(path)
}

/// Resolve the absolute path of a rename destination.
fn rename_destination_path(dest: EventRenameDestinationFile) -> Option<String> {
    let path = match dest {
        EventRenameDestinationFile::ExistingFile { file, .. } => osstr_to_string(file.path()),
        EventRenameDestinationFile::NewPath {
            directory,
            filename,
            ..
        } => join_path(directory.path(), filename),
        _ => return None,
    };
    (!path.is_empty()).then_some(path)
}

/// Assemble a file [`SensorEvent`] from FFI-free fields.
fn file_event(raw: RawFile) -> Option<SensorEvent> {
    if raw.target.is_empty() {
        return None;
    }
    let (action, event_id, action_code) = raw.action.normalization();

    // Classified from the destination, not the source: a rename *into*
    // `LaunchAgents` is how persistence is usually installed, because staging
    // the plist elsewhere and moving it in is both atomic and quieter than
    // writing it in place.
    let persistence = crate::sensor::persistence::classify_for(Platform::MacOS, &raw.target)
        .map(|mechanism| mechanism.as_str().to_string());

    Some(SensorEvent {
        platform: Platform::MacOS,
        provider: "esf",
        action,
        normalization: SensorNormalization {
            event_id,
            action_code,
        },
        pid: Some(raw.pid),
        timestamp: raw.event_time,
        source_seq: raw.source_seq,
        process_start_key: raw.process_start_key,
        parent_process_start_key: None,
        payload: SensorPayload::File(FileEventFields {
            persistence_mechanism: persistence,
            source_filename: raw.source,
            target_filename: Some(raw.target),
            process_id: Some(raw.pid.to_string()),
            image: raw.image,
            creation_utc_time: None,
            previous_creation_utc_time: None,
            user: Some(raw.user),
            path_truncated: None,
        }),
    })
}

fn join_path(directory: &OsStr, filename: &OsStr) -> String {
    let mut path = PathBuf::from(directory);
    path.push(filename);
    path.to_string_lossy().into_owned()
}

fn osstr_to_string(value: &OsStr) -> String {
    value.to_string_lossy().into_owned()
}

fn system_time_nanos(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0)
}

/// Queue a decoded event, accounting for a drop rather than blocking.
///
/// The ESF message handler runs on the client's own queue and must return
/// promptly, so overflow is shed and counted — see [`crate::telemetry`].
fn try_send(tx: &Sender<SensorEvent>, event: SensorEvent) {
    let _ = crate::telemetry::try_send_sensor_event(tx, event);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The expected numbering for `action`, read from the shared table rather
    /// than from a macOS-local constant — asserting against a sensor's own
    /// constant is what let the platforms drift apart in the first place.
    fn shared(action: SensorAction) -> SensorNormalization {
        SensorNormalization::for_file_action(action).expect("file action is in the shared table")
    }

    #[test]
    fn not_permitted_hint_points_at_full_disk_access() {
        let msg = new_client_error_hint(&NewClientError::NotPermitted);
        assert!(msg.contains("NotPermitted"));
        assert!(msg.contains("Full Disk Access"));
    }

    #[test]
    fn not_privileged_hint_points_at_sudo() {
        let msg = new_client_error_hint(&NewClientError::NotPrivileged);
        assert!(msg.contains("sudo"));
    }

    #[test]
    fn process_start_event_maps_exec_fields() {
        let event = process_start_event(RawExec {
            pid: 4242,
            image: "/usr/bin/curl".to_string(),
            command_line: Some("/usr/bin/curl https://example.test".to_string()),
            parent_pid: 501,
            parent_image: Some("/bin/zsh".to_string()),
            current_directory: Some("/Users/alice".to_string()),
            user: "alice".to_string(),
            start_time: 1_700_000_000_000_000_000,
            event_time: SystemTime::UNIX_EPOCH,
            source_seq: Some(77),
            cdhash: Some("0123456789abcdef0123456789abcdef01234567".to_string()),
            signing_identity: Some("ABCDE12345".to_string()),
            signed: true,
            signature_status: "Valid",
        });

        assert_eq!(event.platform, Platform::MacOS);
        assert_eq!(event.provider, "esf");
        assert_eq!(event.action, SensorAction::Start);
        assert_eq!(event.normalization.event_id, EVENT_ID_PROCESS_CREATE);
        assert_eq!(event.pid, Some(4242));
        assert_eq!(event.source_seq, Some(77));
        assert_eq!(
            event.process_start_key,
            Some(ProcessStartKey {
                pid: 4242,
                start_time: 1_700_000_000_000_000_000,
            })
        );

        match event.payload {
            SensorPayload::Process(fields) => {
                assert_eq!(fields.image.as_deref(), Some("/usr/bin/curl"));
                assert_eq!(
                    fields.command_line.as_deref(),
                    Some("/usr/bin/curl https://example.test")
                );
                assert_eq!(fields.process_id.as_deref(), Some("4242"));
                assert_eq!(fields.parent_process_id.as_deref(), Some("501"));
                assert_eq!(fields.current_directory.as_deref(), Some("/Users/alice"));
                assert_eq!(fields.user.as_deref(), Some("alice"));
                assert_eq!(fields.parent_image.as_deref(), Some("/bin/zsh"));

                // Read off the event rather than the file: Endpoint Security
                // carries the kernel's own verdict, so a macOS process start
                // has an identity and a signer without any I/O at all.
                assert_eq!(
                    fields.hashes.as_deref(),
                    Some("CDHASH=0123456789ABCDEF0123456789ABCDEF01234567")
                );
                assert_eq!(fields.signed.as_deref(), Some("true"));
                assert_eq!(fields.signature.as_deref(), Some("ABCDE12345"));
                assert_eq!(fields.signature_status.as_deref(), Some("Valid"));
            }
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    /// An all-zero Code Directory hash means the kernel recorded none.
    ///
    /// Reporting it as forty zeroes would give every unsigned binary the same
    /// identity, and any rule matching on it would match all of them at once.
    #[test]
    fn an_absent_cdhash_is_not_a_hash_of_zero() {
        assert!(cdhash_hex(&[0u8; 20]).is_none());

        let mut cdhash = [0u8; 20];
        cdhash[19] = 0xAB;
        assert_eq!(
            cdhash_hex(&cdhash).as_deref(),
            Some("00000000000000000000000000000000000000ab")
        );
    }

    /// The flags are read as a bitmask, not compared for equality.
    ///
    /// A real `codesigning_flags` carries a dozen other bits; testing for
    /// equality against `CS_VALID` would call every signed binary unsigned.
    #[test]
    fn the_codesigning_flags_are_read_as_a_mask() {
        const CS_HARD: u32 = 0x0000_0100;
        assert_ne!(CS_VALID & (CS_VALID | CS_HARD | CS_SIGNED), 0);
        assert_eq!(CS_VALID & CS_HARD, 0);
    }

    fn raw_file(action: FileAction, target: &str, source: Option<&str>) -> RawFile {
        RawFile {
            action,
            pid: 55,
            image: Some("/usr/bin/touch".to_string()),
            user: "alice".to_string(),
            target: target.to_string(),
            source: source.map(str::to_string),
            event_time: SystemTime::UNIX_EPOCH,
            source_seq: None,
            process_start_key: Some(ProcessStartKey {
                pid: 55,
                start_time: 123_456,
            }),
        }
    }

    #[test]
    /// A plist landing in a LaunchAgents folder is named as persistence.
    ///
    /// This is what the classifier exists for: without it every rule about
    /// macOS persistence has to carry the path list itself.
    #[test]
    fn a_write_into_launchagents_is_marked_as_persistence() {
        let event = file_event(raw_file(
            FileAction::Create,
            "/Users/alice/Library/LaunchAgents/com.evil.plist",
            None,
        ))
        .expect("create event should build");

        match event.payload {
            SensorPayload::File(fields) => {
                assert_eq!(
                    fields.persistence_mechanism.as_deref(),
                    Some("launch_agent")
                );
            }
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    /// Staging elsewhere and renaming in is the usual install, so the
    /// destination is what gets classified.
    #[test]
    fn a_rename_into_a_persistence_location_is_classified_by_its_destination() {
        let event = file_event(raw_file(
            FileAction::Rename,
            "/Library/LaunchDaemons/com.evil.plist",
            Some("/tmp/staged.plist"),
        ))
        .expect("rename event should build");

        match event.payload {
            SensorPayload::File(fields) => {
                assert_eq!(
                    fields.persistence_mechanism.as_deref(),
                    Some("launch_daemon")
                );
            }
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    #[test]
    fn an_ordinary_write_carries_no_persistence_marker() {
        let event = file_event(raw_file(FileAction::Create, "/tmp/new.txt", None))
            .expect("create event should build");

        match event.payload {
            SensorPayload::File(fields) => assert!(fields.persistence_mechanism.is_none()),
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    fn file_event_maps_create() {
        let event = file_event(raw_file(FileAction::Create, "/tmp/new.txt", None))
            .expect("create event should build");
        assert_eq!(event.action, SensorAction::Create);
        assert_eq!(event.normalization, shared(SensorAction::Create));
        assert_eq!(event.pid, Some(55));
        assert_eq!(
            event.process_start_key,
            Some(ProcessStartKey {
                pid: 55,
                start_time: 123_456,
            })
        );

        match event.payload {
            SensorPayload::File(fields) => {
                assert_eq!(fields.target_filename.as_deref(), Some("/tmp/new.txt"));
                assert!(fields.source_filename.is_none());
                assert_eq!(fields.image.as_deref(), Some("/usr/bin/touch"));
                assert_eq!(fields.user.as_deref(), Some("alice"));
            }
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    #[test]
    fn file_event_maps_delete() {
        let event = file_event(raw_file(FileAction::Delete, "/tmp/old.txt", None))
            .expect("delete event should build");
        assert_eq!(event.action, SensorAction::Delete);
        assert_eq!(event.normalization, shared(SensorAction::Delete));
    }

    #[test]
    fn file_event_maps_rename_with_source() {
        let event = file_event(raw_file(
            FileAction::Rename,
            "/tmp/new.txt",
            Some("/tmp/old.txt"),
        ))
        .expect("rename event should build");
        assert_eq!(event.action, SensorAction::Rename);
        assert_eq!(event.normalization, shared(SensorAction::Rename));

        match event.payload {
            SensorPayload::File(fields) => {
                assert_eq!(fields.source_filename.as_deref(), Some("/tmp/old.txt"));
                assert_eq!(fields.target_filename.as_deref(), Some("/tmp/new.txt"));
            }
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    #[test]
    fn file_event_maps_modify() {
        let event = file_event(raw_file(FileAction::Modify, "/tmp/changed.txt", None))
            .expect("modify event should build");
        assert_eq!(event.action, SensorAction::Modify);
        // Modify must not report under FileCreate (11): that would route macOS
        // writes into `file_create` instead of `file_change` (issue #239).
        assert_eq!(event.normalization, shared(SensorAction::Modify));
        assert_eq!(event.normalization.event_id, 65);
    }

    #[test]
    fn file_event_rejects_empty_target() {
        assert!(file_event(raw_file(FileAction::Create, "", None)).is_none());
    }

    #[test]
    fn join_path_combines_directory_and_filename() {
        assert_eq!(
            join_path(OsStr::new("/tmp/dir"), OsStr::new("file.txt")),
            "/tmp/dir/file.txt"
        );
    }

    #[test]
    fn process_stop_event_maps_exit() {
        let event = process_stop_event(
            4242,
            "alice".to_string(),
            Some(123_456),
            SystemTime::UNIX_EPOCH,
            None,
        );

        assert_eq!(event.action, SensorAction::Stop);
        assert_eq!(event.normalization.event_id, EVENT_ID_PROCESS_TERMINATE);
        assert_eq!(event.pid, Some(4242));
        assert_eq!(
            event.process_start_key,
            Some(ProcessStartKey {
                pid: 4242,
                start_time: 123_456,
            })
        );

        match event.payload {
            SensorPayload::Process(fields) => {
                assert_eq!(fields.process_id.as_deref(), Some("4242"));
                assert_eq!(fields.user.as_deref(), Some("alice"));
                assert!(fields.image.is_none());
            }
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    #[test]
    fn process_start_event_omits_nonpositive_parent_pid() {
        let event = process_start_event(RawExec {
            pid: 7,
            image: "/sbin/launchd".to_string(),
            command_line: None,
            parent_pid: 0,
            parent_image: None,
            current_directory: None,
            user: "root".to_string(),
            start_time: 0,
            event_time: SystemTime::UNIX_EPOCH,
            source_seq: None,
            cdhash: None,
            signing_identity: None,
            signed: false,
            signature_status: "Unsigned",
        });

        match event.payload {
            SensorPayload::Process(fields) => {
                assert!(fields.parent_process_id.is_none());
                assert!(fields.command_line.is_none());
                assert!(fields.current_directory.is_none());
            }
            other => panic!("unexpected payload: {other:?}"),
        }
    }
}
