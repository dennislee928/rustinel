//! File quarantine.
//!
//! The user-mode answer to a minifilter's `FLT_PREOP_COMPLETE`: the write has
//! already happened, so instead of denying it the file is taken out of reach
//! and a record is kept of how to put it back.
//!
//! Three properties matter more than speed here.
//!
//! **It must be reversible.** A false positive that destroys a file is worse
//! than one that kills a process, because a process can be restarted. Every
//! quarantine writes a metadata document beside the stored file naming where it
//! came from, so `restore` can put it back exactly.
//!
//! **The stored copy must not be executable or scannable as itself.** It is
//! obfuscated with a single-byte XOR, which is not encryption and is not
//! claimed to be: it exists so the quarantine directory does not read as a
//! malware collection to the next scanner that walks it, and so a stored file
//! cannot be run by double-clicking it.
//!
//! **It must never quarantine Rustinel's own files.** A response engine that
//! can disarm itself is worse than one that cannot act.

use super::{ActionExecutor, Capabilities};
use crate::response::action::{
    ActionError, ActionKind, ActionReceipt, Enforcement, ResponseAction,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Byte the stored copy is XORed with.
///
/// Not a secret and not encryption. See the module note.
const OBFUSCATION_BYTE: u8 = 0xA5;

/// Largest file that will be quarantined.
///
/// Moving is cheap, but a same-volume move is not guaranteed, and a
/// cross-volume move of a very large file would block the response worker for
/// as long as the copy takes.
const MAX_QUARANTINE_BYTES: u64 = 512 * 1024 * 1024;

/// What was quarantined, and how to put it back.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuarantineEntry {
    /// SHA-256 of the original contents, and the stored file's name.
    pub id: String,
    /// Where the file was.
    pub original_path: PathBuf,
    /// Size in bytes.
    pub size: u64,
    /// When it was quarantined, RFC 3339.
    pub quarantined_at: String,
    /// Detection rule that led to it, when one did.
    pub rule_name: Option<String>,
}

/// A directory holding quarantined files and their metadata.
#[derive(Debug, Clone)]
pub struct QuarantineStore {
    root: PathBuf,
}

impl QuarantineStore {
    /// A store rooted at `root`. The directory is created on first write.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Directory this store writes into.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Take a file out of reach, returning what it takes to restore it.
    pub fn quarantine(
        &self,
        path: &Path,
        rule_name: Option<&str>,
    ) -> Result<QuarantineEntry, String> {
        let metadata =
            fs::metadata(path).map_err(|err| format!("cannot stat {}: {err}", path.display()))?;

        if !metadata.is_file() {
            return Err(format!("{} is not a regular file", path.display()));
        }
        if metadata.len() > MAX_QUARANTINE_BYTES {
            return Err(format!(
                "{} is {} bytes, over the {MAX_QUARANTINE_BYTES} byte quarantine limit",
                path.display(),
                metadata.len()
            ));
        }

        let contents =
            fs::read(path).map_err(|err| format!("cannot read {}: {err}", path.display()))?;
        let id = hex::encode(Sha256::digest(&contents));

        fs::create_dir_all(&self.root)
            .map_err(|err| format!("cannot create {}: {err}", self.root.display()))?;
        restrict_directory(&self.root);

        let entry = QuarantineEntry {
            id: id.clone(),
            original_path: path.to_path_buf(),
            size: metadata.len(),
            quarantined_at: chrono::Utc::now().to_rfc3339(),
            rule_name: rule_name.map(str::to_string),
        };

        // Write the stored copy first: a metadata document with no file behind
        // it would advertise a restore that cannot happen.
        let stored = self.blob_path(&id);
        let mut obfuscated = contents;
        for byte in &mut obfuscated {
            *byte ^= OBFUSCATION_BYTE;
        }
        write_new(&stored, &obfuscated)?;

        let metadata_json = serde_json::to_vec_pretty(&entry)
            .map_err(|err| format!("cannot serialize quarantine metadata: {err}"))?;
        if let Err(err) = write_new(&self.metadata_path(&id), &metadata_json) {
            let _ = fs::remove_file(&stored);
            return Err(err);
        }

        // Only now is the original removed. Losing the file after this point
        // still leaves a complete, restorable copy.
        fs::remove_file(path).map_err(|err| {
            let _ = fs::remove_file(&stored);
            let _ = fs::remove_file(self.metadata_path(&id));
            format!("cannot remove {}: {err}", path.display())
        })?;

        Ok(entry)
    }

    /// Put a quarantined file back.
    ///
    /// `to` overrides the original location, which is what an analyst wants
    /// when restoring for inspection rather than for use.
    pub fn restore(&self, id: &str, to: Option<&Path>) -> Result<PathBuf, String> {
        let entry = self.entry(id)?;
        let destination = to.unwrap_or(&entry.original_path).to_path_buf();

        let mut stored = fs::File::open(self.blob_path(id))
            .map_err(|err| format!("cannot open quarantined file {id}: {err}"))?;
        let mut contents = Vec::new();
        stored
            .read_to_end(&mut contents)
            .map_err(|err| format!("cannot read quarantined file {id}: {err}"))?;
        for byte in &mut contents {
            *byte ^= OBFUSCATION_BYTE;
        }

        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("cannot create {}: {err}", parent.display()))?;
        }
        write_new(&destination, &contents)?;

        let _ = fs::remove_file(self.blob_path(id));
        let _ = fs::remove_file(self.metadata_path(id));

        Ok(destination)
    }

    /// Everything currently held, newest first.
    pub fn list(&self) -> Vec<QuarantineEntry> {
        let Ok(dir) = fs::read_dir(&self.root) else {
            return Vec::new();
        };

        let mut entries: Vec<QuarantineEntry> = dir
            .filter_map(Result::ok)
            .filter(|item| item.path().extension().is_some_and(|ext| ext == "json"))
            .filter_map(|item| fs::read(item.path()).ok())
            .filter_map(|bytes| serde_json::from_slice(&bytes).ok())
            .collect();

        entries.sort_by(|a, b| b.quarantined_at.cmp(&a.quarantined_at));
        entries
    }

    /// One entry by id.
    pub fn entry(&self, id: &str) -> Result<QuarantineEntry, String> {
        let bytes = fs::read(self.metadata_path(id))
            .map_err(|err| format!("no quarantine entry {id}: {err}"))?;
        serde_json::from_slice(&bytes)
            .map_err(|err| format!("quarantine entry {id} is unreadable: {err}"))
    }

    fn blob_path(&self, id: &str) -> PathBuf {
        self.root.join(format!("{id}.bin"))
    }

    fn metadata_path(&self, id: &str) -> PathBuf {
        self.root.join(format!("{id}.json"))
    }
}

/// Write a file, refusing to clobber one that is already there.
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|err| format!("cannot write {}: {err}", path.display()))?;
    file.write_all(bytes)
        .map_err(|err| format!("cannot write {}: {err}", path.display()))?;
    file.flush()
        .map_err(|err| format!("cannot flush {}: {err}", path.display()))
}

/// Keep the quarantine directory out of reach of ordinary users.
#[cfg(unix)]
fn restrict_directory(root: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(root, fs::Permissions::from_mode(0o700));
}

/// On Windows the directory inherits the ACL of `C:\ProgramData\Rustinel`,
/// which the installer restricts to SYSTEM and Administrators.
#[cfg(not(unix))]
fn restrict_directory(_root: &Path) {}

/// Paths that must never be quarantined, whatever a rule says.
///
/// Quarantining Rustinel's own binary or rules would disarm the agent, which
/// is exactly what an attacker who can steer a detection would aim for.
pub fn is_self_owned(path: &Path, install_dirs: &[PathBuf]) -> bool {
    let normalized = crate::utils::normalize_path_for_comparison(&path.to_string_lossy());
    install_dirs.iter().any(|dir| {
        let prefix = crate::utils::normalize_path_for_comparison(&dir.to_string_lossy());
        !prefix.is_empty() && normalized.starts_with(&prefix)
    })
}

/// Executor for [`ActionKind::QuarantineFile`].
#[derive(Debug)]
pub struct QuarantineExecutor {
    store: QuarantineStore,
    protected_dirs: Vec<PathBuf>,
    capabilities: Capabilities,
}

impl QuarantineExecutor {
    /// Build an executor writing into `root`, refusing to touch anything under
    /// `protected_dirs`.
    pub fn new(root: impl Into<PathBuf>, protected_dirs: Vec<PathBuf>) -> Self {
        Self {
            store: QuarantineStore::new(root),
            protected_dirs,
            capabilities: Capabilities::none("handled by another executor")
                .supporting(ActionKind::QuarantineFile, Enforcement::PostHoc),
        }
    }

    /// The store behind this executor.
    pub fn store(&self) -> &QuarantineStore {
        &self.store
    }
}

impl ActionExecutor for QuarantineExecutor {
    fn name(&self) -> &'static str {
        "quarantine"
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    fn execute(&self, action: &ResponseAction) -> Result<ActionReceipt, ActionError> {
        let enforcement = self.reject_unsupported(action)?;
        let ResponseAction::QuarantineFile { path } = action else {
            return Err(ActionError::Unsupported {
                kind: action.kind(),
                reason: "quarantine executor only quarantines files",
            });
        };

        if is_self_owned(path, &self.protected_dirs) {
            return Err(ActionError::Failed {
                kind: ActionKind::QuarantineFile,
                reason: format!(
                    "{} belongs to the agent and will not be quarantined",
                    path.display()
                ),
            });
        }

        let entry = self
            .store
            .quarantine(path, None)
            .map_err(|reason| ActionError::Failed {
                kind: ActionKind::QuarantineFile,
                reason,
            })?;

        Ok(ActionReceipt::new(
            ActionKind::QuarantineFile,
            enforcement,
            "quarantine",
            action.target_key(),
        )
        .with_detail(format!("quarantine id {}", entry.id)))
    }

    fn rollback(&self, receipt: &ActionReceipt) -> Result<(), ActionError> {
        let id = receipt
            .detail
            .as_deref()
            .and_then(|detail| detail.strip_prefix("quarantine id "))
            .ok_or(ActionError::Unsupported {
                kind: receipt.kind,
                reason: "receipt carries no quarantine id",
            })?;

        self.store
            .restore(id, None)
            .map(|_| ())
            .map_err(|reason| ActionError::Failed {
                kind: ActionKind::QuarantineFile,
                reason,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, QuarantineStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = QuarantineStore::new(dir.path().join("quarantine"));
        (dir, store)
    }

    #[test]
    fn a_quarantined_file_leaves_its_original_location() {
        let (dir, store) = store();
        let victim = dir.path().join("dropper.exe");
        fs::write(&victim, b"malicious contents").expect("write");

        let entry = store
            .quarantine(&victim, Some("Test Rule"))
            .expect("quarantine");

        assert!(!victim.exists(), "the original must be gone");
        assert_eq!(entry.original_path, victim);
        assert_eq!(entry.size, b"malicious contents".len() as u64);
        assert_eq!(entry.rule_name.as_deref(), Some("Test Rule"));
    }

    #[test]
    fn the_stored_copy_is_not_the_original_bytes() {
        let (dir, store) = store();
        let victim = dir.path().join("dropper.exe");
        let original = b"MZ\x90\x00 this would be scanned as malware".to_vec();
        fs::write(&victim, &original).expect("write");

        let entry = store.quarantine(&victim, None).expect("quarantine");
        let stored = fs::read(store.root().join(format!("{}.bin", entry.id))).expect("read stored");

        assert_ne!(
            stored, original,
            "storing the original bytes would leave an executable copy on disk"
        );
        assert_eq!(stored.len(), original.len());
    }

    #[test]
    fn restore_reproduces_the_original_exactly() {
        let (dir, store) = store();
        let victim = dir.path().join("dropper.exe");
        let original = b"\x00\x01\xa5\xff binary contents \x7f".to_vec();
        fs::write(&victim, &original).expect("write");

        let entry = store.quarantine(&victim, None).expect("quarantine");
        let restored = store.restore(&entry.id, None).expect("restore");

        assert_eq!(restored, victim);
        assert_eq!(fs::read(&victim).expect("read restored"), original);
    }

    #[test]
    fn restore_can_divert_to_a_holding_location() {
        let (dir, store) = store();
        let victim = dir.path().join("dropper.exe");
        fs::write(&victim, b"contents").expect("write");
        let entry = store.quarantine(&victim, None).expect("quarantine");

        let holding = dir.path().join("triage").join("sample.bin");
        let restored = store.restore(&entry.id, Some(&holding)).expect("restore");

        assert_eq!(restored, holding);
        assert!(holding.exists());
        assert!(
            !victim.exists(),
            "diverting must not touch the original path"
        );
    }

    #[test]
    fn a_restored_entry_is_no_longer_listed() {
        let (dir, store) = store();
        let victim = dir.path().join("dropper.exe");
        fs::write(&victim, b"contents").expect("write");
        let entry = store.quarantine(&victim, None).expect("quarantine");

        assert_eq!(store.list().len(), 1);
        store.restore(&entry.id, None).expect("restore");
        assert!(store.list().is_empty());
    }

    #[test]
    fn quarantining_a_missing_file_fails_without_writing_anything() {
        let (dir, store) = store();

        let error = store
            .quarantine(&dir.path().join("absent.exe"), None)
            .expect_err("must fail");

        assert!(error.contains("cannot stat"), "unexpected error: {error}");
        assert!(store.list().is_empty());
    }

    #[test]
    fn the_agents_own_files_are_never_quarantined() {
        let install = PathBuf::from(if cfg!(windows) {
            r"C:\Program Files\Rustinel"
        } else {
            "/opt/rustinel"
        });
        let dirs = vec![install.clone()];

        assert!(is_self_owned(&install.join("rustinel.exe"), &dirs));
        assert!(is_self_owned(
            &install.join("rules").join("sigma.yml"),
            &dirs
        ));
        assert!(!is_self_owned(
            &PathBuf::from(if cfg!(windows) {
                r"C:\tmp\dropper.exe"
            } else {
                "/tmp/dropper"
            }),
            &dirs
        ));
    }

    #[test]
    fn the_executor_refuses_to_disarm_the_agent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let install = dir.path().join("install");
        fs::create_dir_all(&install).expect("create install dir");
        let agent = install.join("rustinel.exe");
        fs::write(&agent, b"the agent itself").expect("write");

        let executor =
            QuarantineExecutor::new(dir.path().join("quarantine"), vec![install.clone()]);
        let action = ResponseAction::QuarantineFile {
            path: agent.clone(),
        };

        let error = executor.execute(&action).expect_err("must refuse");
        assert!(matches!(error, ActionError::Failed { .. }), "{error:?}");
        assert!(agent.exists(), "the agent's own file must survive");
    }

    #[test]
    fn the_executor_round_trips_through_its_receipt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let victim = dir.path().join("dropper.exe");
        fs::write(&victim, b"contents").expect("write");

        let executor = QuarantineExecutor::new(dir.path().join("quarantine"), Vec::new());
        let action = ResponseAction::QuarantineFile {
            path: victim.clone(),
        };

        let receipt = executor.execute(&action).expect("quarantine");
        assert!(!victim.exists());

        executor.rollback(&receipt).expect("restore");
        assert!(victim.exists(), "rollback must put the file back");
        assert_eq!(fs::read(&victim).expect("read"), b"contents");
    }
}
