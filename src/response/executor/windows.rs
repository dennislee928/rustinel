//! Windows-specific containment: registry, services, and scheduled tasks.
//!
//! Each of these is the user-mode answer to a kernel callback the agent cannot
//! register. `CmRegisterCallbackEx` would refuse the `RegSetValue` outright;
//! from here the value is already written, so it is deleted afterwards. The
//! difference is a race, not a capability: the persistence exists for the
//! milliseconds between the write and the revert, and survives only if the
//! machine reboots inside that window.
//!
//! Services and scheduled tasks have no kernel callback at all. They are
//! ordinary Win32 and COM surfaces, so what happens here is what a kernel
//! driver would do anyway.

use super::asep::AsepSnapshot;
use super::{ActionExecutor, Capabilities};
use crate::response::action::{
    ActionError, ActionKind, ActionReceipt, Enforcement, ResponseAction,
};
use windows::core::{BSTR, PCWSTR};
use windows::Win32::Foundation::VARIANT_BOOL;
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER,
    COINIT_APARTMENTTHREADED,
};
use windows::Win32::System::Registry::{
    RegCloseKey, RegDeleteKeyValueW, RegDeleteTreeW, RegOpenKeyExW, RegSetValueExW, HKEY,
    HKEY_CLASSES_ROOT, HKEY_CURRENT_CONFIG, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS,
    KEY_SET_VALUE, REG_VALUE_TYPE,
};
use windows::Win32::System::Services::{
    ChangeServiceConfigW, ControlService, OpenSCManagerW, OpenServiceW, SC_MANAGER_CONNECT,
    SERVICE_CHANGE_CONFIG, SERVICE_CONTROL_STOP, SERVICE_DISABLED, SERVICE_NO_CHANGE,
    SERVICE_STATUS, SERVICE_STOP,
};
use windows::Win32::System::TaskScheduler::{ITaskService, TaskScheduler};
use windows::Win32::System::Variant::VARIANT;

/// Services that must never be stopped or disabled.
///
/// Rustinel's own service is on the list for the obvious reason. `BFE` hosts
/// the filtering engine every network action depends on, and the Event Log is
/// where the audit trail goes: disabling either would blind the agent while
/// leaving it running.
const PROTECTED_SERVICES: &[&str] = &[
    "rustinel",
    "bfe",
    "mpssvc",
    "eventlog",
    "rpcss",
    "dcomlaunch",
    "plugplay",
    "power",
    "winmgmt",
    "lsm",
];

/// Registry keys that must never be reverted.
///
/// Deleting the agent's own configuration or service registration would be a
/// self-inflicted outage, and a detection can be steered to name any key.
const PROTECTED_KEY_FRAGMENTS: &[&str] = &[r"\services\rustinel", r"\rustinel"];

/// Executor for the Windows configuration surfaces.
#[derive(Debug)]
pub struct WindowsExecutor {
    capabilities: Capabilities,
    snapshot: AsepSnapshot,
}

impl Default for WindowsExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsExecutor {
    /// Build the executor, reading the auto-start keys as they are now.
    ///
    /// The snapshot is what makes restoring a modified value possible at all:
    /// a registry event says what was written, never what was there before, so
    /// the only way to have the previous value is to have read it earlier.
    pub fn new() -> Self {
        Self::with_snapshot(AsepSnapshot::capture())
    }

    /// Build with a specific snapshot, for tests.
    pub fn with_snapshot(snapshot: AsepSnapshot) -> Self {
        Self {
            capabilities: Capabilities::none("handled by another executor")
                .supporting(ActionKind::RevertRegistry, Enforcement::PostHoc)
                .supporting(ActionKind::DisableService, Enforcement::PostHoc)
                .supporting(ActionKind::DisableScheduledTask, Enforcement::PostHoc),
            snapshot,
        }
    }
}

impl ActionExecutor for WindowsExecutor {
    fn name(&self) -> &'static str {
        "windows"
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    fn execute(&self, action: &ResponseAction) -> Result<ActionReceipt, ActionError> {
        let enforcement = self.reject_unsupported(action)?;
        let kind = action.kind();
        let receipt = |detail: String| {
            ActionReceipt::new(kind, enforcement, "windows", action.target_key())
                .with_detail(detail)
        };

        match action {
            ResponseAction::RevertRegistry { key, value } => {
                let detail = revert_registry(key, value.as_deref(), &self.snapshot)
                    .map_err(|reason| ActionError::Failed { kind, reason })?;
                Ok(receipt(detail))
            }
            ResponseAction::DisableService { name } => {
                let detail =
                    disable_service(name).map_err(|reason| ActionError::Failed { kind, reason })?;
                Ok(receipt(detail))
            }
            ResponseAction::DisableScheduledTask { path } => {
                let detail =
                    disable_task(path).map_err(|reason| ActionError::Failed { kind, reason })?;
                Ok(receipt(detail))
            }
            other => Err(ActionError::Unsupported {
                kind: other.kind(),
                reason: "not a Windows configuration action",
            }),
        }
    }
}

/// Put a persistence write back the way it was.
///
/// A value the snapshot knows about existed before the attack, so it is
/// restored rather than deleted: `Winlogon\Userinit` and a service's
/// `ImagePath` are modified by an attacker, not created, and deleting one
/// breaks the logon path instead of repairing it. Only a value with no
/// recorded predecessor is deleted, because for that one deletion *is* the
/// original state.
fn revert_registry(
    key: &str,
    value: Option<&str>,
    snapshot: &AsepSnapshot,
) -> Result<String, String> {
    if is_protected_key(key) {
        return Err(format!("{key} is protected and will not be reverted"));
    }

    let (root, subkey) = split_root(key)?;

    if let Some(value) = value {
        if let Some(previous) = snapshot.value(key, value) {
            return restore_value(root, subkey, value, previous);
        }
    }

    match value {
        Some(value) => {
            let status = unsafe { RegDeleteKeyValueW(root, &wide(subkey), &wide(value)) };
            match WIN32_ERROR(status.0) {
                ERROR_SUCCESS => Ok(format!("deleted value {value}")),
                // Already gone is the desired end state, not a failure.
                ERROR_FILE_NOT_FOUND => Ok(format!("value {value} was already absent")),
                other => Err(format!("RegDeleteKeyValue failed: {:#x}", other.0)),
            }
        }
        None => {
            // Without a value name the whole key is the persistence, so the
            // key and everything under it goes. `RegDeleteTree` needs the key
            // open for write, which also proves it exists.
            let mut handle = HKEY::default();
            let status =
                unsafe { RegOpenKeyExW(root, &wide(subkey), None, KEY_SET_VALUE, &mut handle) };
            if WIN32_ERROR(status.0) != ERROR_SUCCESS {
                return Err(format!("RegOpenKeyEx failed: {:#x}", status.0));
            }

            let deleted = unsafe { RegDeleteTreeW(handle, PCWSTR::null()) };
            unsafe {
                let _ = RegCloseKey(handle);
            }

            match WIN32_ERROR(deleted.0) {
                ERROR_SUCCESS => Ok("deleted key contents".to_string()),
                other => Err(format!("RegDeleteTree failed: {:#x}", other.0)),
            }
        }
    }
}

/// Write a recorded value back over whatever replaced it.
fn restore_value(
    root: HKEY,
    subkey: &str,
    value: &str,
    previous: &crate::response::executor::asep::SnapshotValue,
) -> Result<String, String> {
    let mut handle = HKEY::default();
    let status = unsafe { RegOpenKeyExW(root, &wide(subkey), None, KEY_SET_VALUE, &mut handle) };
    if WIN32_ERROR(status.0) != ERROR_SUCCESS {
        return Err(format!("RegOpenKeyEx failed: {:#x}", status.0));
    }

    let written = unsafe {
        RegSetValueExW(
            handle,
            &wide(value),
            None,
            REG_VALUE_TYPE(previous.kind),
            Some(&previous.data),
        )
    };
    unsafe {
        let _ = RegCloseKey(handle);
    }

    match WIN32_ERROR(written.0) {
        ERROR_SUCCESS => Ok(format!("restored {value} to its value at agent start")),
        other => Err(format!("RegSetValueEx failed: {:#x}", other.0)),
    }
}

/// Stop a service and mark it disabled so it does not come back at boot.
fn disable_service(name: &str) -> Result<String, String> {
    if PROTECTED_SERVICES.contains(&name.to_ascii_lowercase().as_str()) {
        return Err(format!("{name} is protected and will not be disabled"));
    }

    let manager = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) }
        .map_err(|err| format!("OpenSCManager failed: {err}"))?;

    let service =
        unsafe { OpenServiceW(manager, &wide(name), SERVICE_STOP | SERVICE_CHANGE_CONFIG) }
            .map_err(|err| format!("OpenService failed: {err}"))?;

    // Disable first. If the stop fails the service is at least not coming
    // back after a reboot, which is the half that persists.
    let disabled = unsafe {
        ChangeServiceConfigW(
            service,
            windows::Win32::System::Services::ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE),
            SERVICE_DISABLED,
            windows::Win32::System::Services::SERVICE_ERROR(SERVICE_NO_CHANGE),
            PCWSTR::null(),
            PCWSTR::null(),
            None,
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
        )
    };

    let mut status = SERVICE_STATUS::default();
    let stopped = unsafe { ControlService(service, SERVICE_CONTROL_STOP, &mut status) };

    let detail = match (disabled.is_ok(), stopped.is_ok()) {
        (true, true) => "stopped and disabled".to_string(),
        (true, false) => "disabled; it was not running or would not stop".to_string(),
        (false, true) => "stopped; start type unchanged".to_string(),
        (false, false) => {
            return Err(format!(
                "could not stop or disable {name}: {}",
                disabled.err().map(|e| e.to_string()).unwrap_or_default()
            ))
        }
    };

    Ok(detail)
}

/// Disable a scheduled task through the Task Scheduler COM API.
///
/// Shelling out to `schtasks.exe` would work and would also create a process
/// event that the agent's own rules can match, feeding the response engine its
/// own tail. COM keeps the action invisible to the sensor.
fn disable_task(path: &str) -> Result<String, String> {
    let _com = ComScope::new()?;

    let service: ITaskService =
        unsafe { CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER) }
            .map_err(|err| format!("cannot create the task service: {err}"))?;

    unsafe {
        service.Connect(
            &VARIANT::default(),
            &VARIANT::default(),
            &VARIANT::default(),
            &VARIANT::default(),
        )
    }
    .map_err(|err| format!("cannot connect to the task service: {err}"))?;

    // A task path is `\Folder\Name`; the root folder plus the full path is
    // what `GetTask` expects.
    let root = unsafe { service.GetFolder(&BSTR::from("\\")) }
        .map_err(|err| format!("cannot open the task root folder: {err}"))?;

    let normalized = if path.starts_with('\\') {
        path.to_string()
    } else {
        format!("\\{path}")
    };

    let task = unsafe { root.GetTask(&BSTR::from(normalized.as_str())) }
        .map_err(|err| format!("cannot open task {normalized}: {err}"))?;

    unsafe { task.SetEnabled(VARIANT_BOOL(0)) }
        .map_err(|err| format!("cannot disable task {normalized}: {err}"))?;

    Ok("task disabled".to_string())
}

/// COM apartment held for the life of one action.
struct ComScope;

impl ComScope {
    fn new() -> Result<Self, String> {
        // `S_FALSE` means this thread was already initialised, which is fine;
        // only a hard failure is an error.
        let result = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
        if result.is_err() {
            return Err(format!("CoInitializeEx failed: {result:?}"));
        }
        Ok(Self)
    }
}

impl Drop for ComScope {
    fn drop(&mut self) {
        unsafe { CoUninitialize() };
    }
}

/// Split `HKLM\Software\...` into its predefined root and the rest.
fn split_root(key: &str) -> Result<(HKEY, &str), String> {
    let trimmed = key.trim_start_matches('\\');
    let (root, rest) = trimmed
        .split_once('\\')
        .ok_or_else(|| format!("{key} names no subkey"))?;

    let handle = match root.to_ascii_uppercase().as_str() {
        "HKLM" | "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
        "HKCU" | "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
        "HKCR" | "HKEY_CLASSES_ROOT" => HKEY_CLASSES_ROOT,
        "HKU" | "HKEY_USERS" => HKEY_USERS,
        "HKCC" | "HKEY_CURRENT_CONFIG" => HKEY_CURRENT_CONFIG,
        // The kernel spells the machine hive `\REGISTRY\MACHINE`; the sensor
        // converts it, but a rule or a recording may carry either.
        "REGISTRY" => return split_registry_prefix(rest),
        other => return Err(format!("unknown registry root {other}")),
    };

    Ok((handle, rest))
}

/// Handle the kernel's `\REGISTRY\MACHINE\...` spelling.
fn split_registry_prefix(rest: &str) -> Result<(HKEY, &str), String> {
    let (hive, tail) = rest
        .split_once('\\')
        .ok_or_else(|| format!("\\REGISTRY\\{rest} names no subkey"))?;

    match hive.to_ascii_uppercase().as_str() {
        "MACHINE" => Ok((HKEY_LOCAL_MACHINE, tail)),
        "USER" => Ok((HKEY_USERS, tail)),
        other => Err(format!("unknown registry hive {other}")),
    }
}

/// Whether a key is one the agent depends on.
fn is_protected_key(key: &str) -> bool {
    let lowered = key.to_ascii_lowercase();
    PROTECTED_KEY_FRAGMENTS
        .iter()
        .any(|fragment| lowered.contains(fragment))
}

/// Null-terminated UTF-16, as the Win32 registry API wants.
fn wide(value: &str) -> windows::core::HSTRING {
    windows::core::HSTRING::from(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_roots_are_recognised_in_both_spellings() {
        let (root, rest) = split_root(r"HKLM\Software\Microsoft").expect("hklm");
        assert_eq!(root, HKEY_LOCAL_MACHINE);
        assert_eq!(rest, r"Software\Microsoft");

        let (root, rest) = split_root(r"HKEY_CURRENT_USER\Software\Run").expect("long form");
        assert_eq!(root, HKEY_CURRENT_USER);
        assert_eq!(rest, r"Software\Run");

        // The kernel spelling, which a recording can carry.
        let (root, rest) =
            split_root(r"\REGISTRY\MACHINE\SOFTWARE\Microsoft").expect("kernel form");
        assert_eq!(root, HKEY_LOCAL_MACHINE);
        assert_eq!(rest, r"SOFTWARE\Microsoft");
    }

    #[test]
    fn an_unknown_registry_root_is_refused_rather_than_guessed() {
        assert!(split_root(r"HKXX\Software").is_err());
        assert!(split_root("NoBackslash").is_err());
    }

    #[test]
    fn the_agents_own_registry_keys_are_protected() {
        assert!(is_protected_key(
            r"HKLM\SYSTEM\CurrentControlSet\Services\Rustinel"
        ));
        assert!(is_protected_key(r"HKLM\SOFTWARE\Rustinel\Config"));
        assert!(!is_protected_key(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
        ));
    }

    #[test]
    fn reverting_a_protected_key_fails_before_touching_the_registry() {
        let error = revert_registry(
            r"HKLM\SYSTEM\CurrentControlSet\Services\Rustinel",
            Some("ImagePath"),
            &AsepSnapshot::empty(),
        )
        .expect_err("must refuse");
        assert!(error.contains("protected"), "unexpected error: {error}");
    }

    #[test]
    fn disabling_a_protected_service_fails_before_opening_the_manager() {
        for name in ["Rustinel", "rustinel", "BFE", "EventLog"] {
            let error = disable_service(name).expect_err("must refuse");
            assert!(error.contains("protected"), "unexpected error: {error}");
        }
    }

    #[test]
    fn a_value_the_snapshot_knows_is_restored_rather_than_deleted() {
        // Winlogon's Userinit is modified by an attacker, never created.
        // Deleting it would break the logon path instead of repairing it, so
        // the revert has to write the recorded value back.
        let key = r"HKCU\Software\ResponseExecutorRestoreTest";
        let mut snapshot = AsepSnapshot::empty();
        snapshot.insert(
            key,
            "Userinit",
            crate::response::executor::asep::SnapshotValue {
                kind: 1,
                data: Vec::new(),
            },
        );

        // The key does not exist, so the restore fails at the open rather than
        // succeeding; what matters is *which* path it took. A delete would
        // report RegDeleteKeyValue, a restore reports the open it needs first.
        let error = revert_registry(key, Some("Userinit"), &snapshot).expect_err("no such key");
        assert!(
            error.contains("RegOpenKeyEx"),
            "a known value must take the restore path, not the delete path: {error}"
        );
    }

    #[test]
    fn a_value_with_no_recorded_predecessor_is_deleted() {
        // Nothing recorded means the value did not exist before the attack,
        // and for that one deletion is the original state.
        let result = revert_registry(
            r"HKCU\Software\ResponseExecutorAbsentKey",
            Some("Created"),
            &AsepSnapshot::empty(),
        );

        match result {
            Ok(detail) => assert!(detail.contains("absent"), "{detail}"),
            Err(error) => assert!(
                error.contains("RegDeleteKeyValue"),
                "an unknown value must take the delete path: {error}"
            ),
        }
    }

    #[test]
    fn the_executor_claims_exactly_the_windows_configuration_actions() {
        let executor = WindowsExecutor::new();
        assert_eq!(
            executor.capabilities().supported_kinds(),
            vec![
                ActionKind::RevertRegistry,
                ActionKind::DisableService,
                ActionKind::DisableScheduledTask,
            ]
        );
        // Process and file actions belong to their own executors.
        assert!(!executor
            .capabilities()
            .supports(ActionKind::TerminateProcess));
        assert!(!executor.capabilities().supports(ActionKind::QuarantineFile));
    }

    #[test]
    fn reverting_a_value_that_is_already_gone_is_success_not_failure() {
        // The end state is what matters: the persistence is absent either way.
        let result = revert_registry(
            r"HKCU\Software\ResponseExecutorAbsentKey",
            Some("NoSuchValue"),
            &AsepSnapshot::empty(),
        );
        match result {
            Ok(detail) => assert!(detail.contains("already absent"), "{detail}"),
            // A machine that refuses the open at all is also acceptable here;
            // what must not happen is a silent success on a real deletion.
            Err(error) => assert!(
                error.contains("RegDeleteKeyValue"),
                "unexpected error: {error}"
            ),
        }
    }
}
