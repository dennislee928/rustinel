//! Snapshots of the registry keys malware writes itself into.
//!
//! Deleting a persistence value is the obvious revert, and it is wrong whenever
//! the value already existed. `HKLM\...\Winlogon\Userinit` and a service's
//! `ImagePath` are not created by an attacker, they are *modified*: deleting
//! them breaks the logon path or the service rather than restoring it.
//!
//! Restoring the previous value needs a previous value, and user mode has no
//! way to ask for one after the fact — a registry write event says what was
//! written, never what was there before. The only way to have it is to have
//! read it earlier, so this takes a snapshot of the auto-start keys when the
//! agent starts and keeps it for the life of the process.
//!
//! That has a real limit, stated here rather than discovered later: a value
//! written *and* attacked after the snapshot was taken restores to what the
//! snapshot holds, which is the state at agent start, not the state one
//! microsecond before the attack. For the auto-start keys this is nearly always
//! the same thing, because legitimate writes to them are rare.

use std::collections::HashMap;

/// Registry paths worth snapshotting.
///
/// Every one of these is a location where an existing value is more likely to
/// be modified than created, which is exactly the case a delete gets wrong.
/// Run keys are included even though they are usually created, because a
/// machine with a legitimate Run entry is common enough.
pub const SNAPSHOT_KEYS: &[&str] = &[
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
];

/// One recorded value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotValue {
    /// Registry value type, as `RegSetValueEx` takes it.
    pub kind: u32,
    /// Raw bytes, exactly as they were stored.
    pub data: Vec<u8>,
}

/// What the auto-start keys held when the agent started.
#[derive(Debug, Default, Clone)]
pub struct AsepSnapshot {
    /// `KEY\VALUE` to its contents, keys lowercased for lookup.
    values: HashMap<String, SnapshotValue>,
}

impl AsepSnapshot {
    /// An empty snapshot, which reverts nothing.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Read the auto-start keys.
    pub fn capture() -> Self {
        platform::capture(SNAPSHOT_KEYS)
    }

    /// The recorded contents of one value, if it was there at startup.
    pub fn value(&self, key: &str, value: &str) -> Option<&SnapshotValue> {
        self.values.get(&Self::lookup_key(key, value))
    }

    /// Whether anything was recorded.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// How many values are held.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Record one value.
    pub fn insert(&mut self, key: &str, value: &str, snapshot: SnapshotValue) {
        self.values.insert(Self::lookup_key(key, value), snapshot);
    }

    /// Registry paths are case-insensitive, so the lookup key is too.
    fn lookup_key(key: &str, value: &str) -> String {
        format!(
            "{}\\{}",
            key.trim_end_matches('\\').to_ascii_lowercase(),
            value.to_ascii_lowercase()
        )
    }
}

#[cfg(windows)]
mod platform {
    use super::{AsepSnapshot, SnapshotValue};
    use windows::core::HSTRING;
    use windows::Win32::Foundation::{
        ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, WIN32_ERROR,
    };
    use windows::Win32::System::Registry::{
        RegCloseKey, RegEnumValueW, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
        KEY_READ,
    };

    /// Read every value under each of `keys`.
    pub(super) fn capture(keys: &[&str]) -> AsepSnapshot {
        let mut snapshot = AsepSnapshot::default();

        for key in keys {
            let Some((root, subkey)) = split_root(key) else {
                continue;
            };

            let mut handle = HKEY::default();
            let opened =
                unsafe { RegOpenKeyExW(root, &HSTRING::from(subkey), None, KEY_READ, &mut handle) };
            if opened.is_err() {
                // A key that is not there is not an error: HKCU\...\RunOnce
                // does not exist on a machine that has never used it.
                continue;
            }

            enumerate_values(handle, key, &mut snapshot);

            unsafe {
                let _ = RegCloseKey(handle);
            }
        }

        snapshot
    }

    /// Record every value under one open key.
    fn enumerate_values(handle: HKEY, key: &str, snapshot: &mut AsepSnapshot) {
        // Names are capped at 16383 characters by the registry itself.
        const MAX_NAME_CCH: usize = 16_384;

        for index in 0.. {
            let mut name = vec![0u16; MAX_NAME_CCH];
            let mut name_len = MAX_NAME_CCH as u32;
            let mut kind = 0u32;
            let mut data_len = 0u32;

            // First pass: name and size, with no data buffer.
            let status = unsafe {
                RegEnumValueW(
                    handle,
                    index,
                    Some(windows::core::PWSTR(name.as_mut_ptr())),
                    &mut name_len,
                    None,
                    Some(&mut kind),
                    None,
                    Some(&mut data_len),
                )
            };

            match WIN32_ERROR(status.0) {
                ERROR_SUCCESS | ERROR_MORE_DATA => {}
                ERROR_NO_MORE_ITEMS => break,
                // Anything else means this key is not readable; the rest of
                // the snapshot is still worth having.
                _ => break,
            }

            let value_name = String::from_utf16_lossy(&name[..name_len as usize]);

            let mut data = vec![0u8; data_len as usize];
            let mut read_name_len = MAX_NAME_CCH as u32;
            let mut read_data_len = data_len;
            let read = unsafe {
                RegEnumValueW(
                    handle,
                    index,
                    Some(windows::core::PWSTR(name.as_mut_ptr())),
                    &mut read_name_len,
                    None,
                    Some(&mut kind),
                    Some(data.as_mut_ptr()),
                    Some(&mut read_data_len),
                )
            };

            if WIN32_ERROR(read.0) == ERROR_SUCCESS {
                data.truncate(read_data_len as usize);
                snapshot.insert(key, &value_name, SnapshotValue { kind, data });
            }
        }
    }

    /// Split `HKLM\...` into its predefined root and the rest.
    fn split_root(key: &str) -> Option<(HKEY, &str)> {
        let (root, rest) = key.split_once('\\')?;
        let handle = match root.to_ascii_uppercase().as_str() {
            "HKLM" | "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
            "HKCU" | "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
            _ => return None,
        };
        Some((handle, rest))
    }
}

#[cfg(not(windows))]
mod platform {
    use super::AsepSnapshot;

    /// There is no registry to snapshot.
    pub(super) fn capture(_keys: &[&str]) -> AsepSnapshot {
        AsepSnapshot::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookups_ignore_case_and_trailing_separators() {
        let mut snapshot = AsepSnapshot::empty();
        snapshot.insert(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "Updater",
            SnapshotValue {
                kind: 1,
                data: b"C:\\Program Files\\App\\app.exe".to_vec(),
            },
        );

        // Registry paths are case-insensitive, and an event may carry a
        // trailing separator the configured key does not.
        assert!(snapshot
            .value(
                r"hklm\software\microsoft\windows\currentversion\run",
                "updater"
            )
            .is_some());
        assert!(snapshot
            .value(
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\",
                "Updater"
            )
            .is_some());
        assert!(snapshot
            .value(
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "Other"
            )
            .is_none());
    }

    #[test]
    fn an_empty_snapshot_reverts_nothing() {
        let snapshot = AsepSnapshot::empty();
        assert!(snapshot.is_empty());
        assert_eq!(snapshot.len(), 0);
        assert!(snapshot.value(r"HKLM\SOFTWARE", "Anything").is_none());
    }

    #[test]
    fn the_snapshot_covers_the_keys_where_a_delete_would_be_wrong() {
        // Winlogon and Session Manager hold values Windows itself created.
        // Deleting one rather than restoring it breaks the logon path.
        let joined = SNAPSHOT_KEYS.join(" ").to_ascii_lowercase();
        assert!(joined.contains("winlogon"));
        assert!(joined.contains("session manager"));
        assert!(joined.contains(r"currentversion\run"));
    }

    #[test]
    #[cfg(windows)]
    fn capturing_the_real_keys_finds_something() {
        // Every Windows install has values under at least one of these; an
        // empty result means the enumeration is broken rather than the machine
        // being unusually clean.
        let snapshot = AsepSnapshot::capture();
        assert!(
            !snapshot.is_empty(),
            "snapshot of the auto-start keys came back empty"
        );
    }
}
