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

        // A cross-volume quarantine is a copy followed by a delete rather than
        // a rename, which is slower and leaves a window where the file exists
        // twice. It is allowed, but it is worth saying so: an operator whose
        // quarantine lives on a different disk from the malware is paying for
        // it on every action.
        if !same_volume(path, &self.root) {
            tracing::debug!(
                target: "response",
                file = %path.display(),
                quarantine = %self.root.display(),
                "Quarantine is on a different volume from the file; the move is a copy"
            );
        }

        fs::create_dir_all(&self.root)
            .map_err(|err| format!("cannot create {}: {err}", self.root.display()))?;
        restrict_directory(&self.root);

        // Write the stored copy first: a metadata document with no file behind
        // it would advertise a restore that cannot happen.
        //
        // The blob is content-addressed, so an existing one holds these exact
        // bytes and is reused. Rewriting it would be pointless work; refusing
        // would fail a quarantine over a file that is already safely stored.
        let stored = self.blob_path(&id);
        let mut obfuscated = contents;
        for byte in &mut obfuscated {
            *byte ^= OBFUSCATION_BYTE;
        }
        let blob_existed = match write_new_io(&stored, &obfuscated) {
            Ok(()) => false,
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => true,
            Err(err) => return Err(format!("cannot write {}: {err}", stored.display())),
        };

        // The metadata is the incident record, and it is not content-addressed:
        // the same bytes quarantined from a second path is a second event with
        // a different `original_path`. Overwriting the first record would lose
        // where that sample came from and send its restore to the wrong place,
        // so each event gets its own record id.
        let record_id = self.allocate_record_id(&id);
        let entry = QuarantineEntry {
            id: record_id.clone(),
            original_path: path.to_path_buf(),
            size: metadata.len(),
            quarantined_at: chrono::Utc::now().to_rfc3339(),
            rule_name: rule_name.map(str::to_string),
        };

        let metadata_json = serde_json::to_vec_pretty(&entry)
            .map_err(|err| format!("cannot serialize quarantine metadata: {err}"))?;
        if let Err(err) = write_new(&self.metadata_path(&record_id), &metadata_json) {
            // Only clean up a blob this call created. One that was already
            // there belongs to an earlier record that is still valid.
            if !blob_existed {
                let _ = fs::remove_file(&stored);
            }
            return Err(err);
        }

        // Only now is the original removed. Losing the file after this point
        // still leaves a complete, restorable copy.
        fs::remove_file(path).map_err(|err| {
            let _ = fs::remove_file(self.metadata_path(&record_id));
            if !blob_existed {
                let _ = fs::remove_file(&stored);
            }
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

        // The record goes unconditionally; the blob only when this was the
        // last record holding those bytes. Removing a shared blob would leave
        // the other records advertising a restore that cannot happen.
        let shared = self.blob_is_shared(id);
        let _ = fs::remove_file(self.metadata_path(id));
        if !shared {
            let _ = fs::remove_file(self.blob_path(id));
        }

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

    /// Resolve a possibly-abbreviated id to the full one.
    ///
    /// Ids are SHA-256 digests, which nobody types in full. A prefix is
    /// accepted as long as it names exactly one entry; an ambiguous prefix is
    /// an error rather than a coin toss over which file gets restored.
    pub fn resolve_id(&self, prefix: &str) -> Result<String, String> {
        let prefix = prefix.trim().to_ascii_lowercase();
        if prefix.is_empty() {
            return Err("no quarantine id given".to_string());
        }

        let matches: Vec<String> = self
            .list()
            .into_iter()
            .map(|entry| entry.id)
            .filter(|id| id.starts_with(&prefix))
            .collect();

        match matches.len() {
            0 => Err(format!("no quarantined file matches {prefix}")),
            1 => Ok(matches.into_iter().next().expect("one match")),
            count => Err(format!(
                "{prefix} matches {count} quarantined files; use more characters"
            )),
        }
    }

    /// One entry by id.
    pub fn entry(&self, id: &str) -> Result<QuarantineEntry, String> {
        let bytes = fs::read(self.metadata_path(id))
            .map_err(|err| format!("no quarantine entry {id}: {err}"))?;
        serde_json::from_slice(&bytes)
            .map_err(|err| format!("quarantine entry {id} is unreadable: {err}"))
    }

    /// The stored copy backing a record.
    ///
    /// Records for the same bytes share one blob, so this addresses it by the
    /// content hash rather than by the record id.
    fn blob_path(&self, id: &str) -> PathBuf {
        self.root.join(format!("{}.bin", content_hash_of(id)))
    }

    fn metadata_path(&self, id: &str) -> PathBuf {
        self.root.join(format!("{id}.json"))
    }

    /// A record id for a new quarantine of content `hash`.
    ///
    /// The first is the bare hash, which keeps the common case readable. Later
    /// quarantines of the same bytes take `<hash>.2`, `.3`, and so on.
    fn allocate_record_id(&self, hash: &str) -> String {
        if !self.metadata_path(hash).exists() {
            return hash.to_string();
        }
        // Bounded rather than `loop`: a store holding this many records of one
        // file has a problem that silently spinning here would not fix.
        for suffix in 2..=10_000u32 {
            let candidate = format!("{hash}.{suffix}");
            if !self.metadata_path(&candidate).exists() {
                return candidate;
            }
        }
        format!(
            "{hash}.{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        )
    }

    /// Whether any record other than `id` still needs `id`'s stored copy.
    fn blob_is_shared(&self, id: &str) -> bool {
        let hash = content_hash_of(id);
        self.list()
            .iter()
            .any(|entry| entry.id != id && content_hash_of(&entry.id) == hash)
    }
}

/// The content hash a record id addresses, dropping any `.n` discriminator.
fn content_hash_of(id: &str) -> &str {
    id.split_once('.').map_or(id, |(hash, _)| hash)
}

/// Whether two paths are on the same volume.
///
/// Compared by path prefix rather than by device id, because a device id needs
/// a handle to each path and the destination may not exist yet.
fn same_volume(left: &Path, right: &Path) -> bool {
    fn volume(path: &Path) -> Option<String> {
        let text = path.to_string_lossy().to_ascii_lowercase();

        #[cfg(windows)]
        {
            // `c:\...` or a UNC share root.
            const SEPARATOR: char = '\\';
            match text.strip_prefix(r"\\") {
                Some(stripped) => stripped.split(SEPARATOR).next().map(str::to_string),
                None => text.split(':').next().map(str::to_string),
            }
        }

        #[cfg(not(windows))]
        {
            // Without mount-point resolution every absolute path is treated as
            // one volume, which is true often enough and never claims a move
            // is cheap when it is not.
            let _ = text;
            Some("/".to_string())
        }
    }

    match (volume(left), volume(right)) {
        (Some(left), Some(right)) => left == right,
        _ => true,
    }
}

/// Write a file, refusing to clobber one that is already there.
///
/// `create_new` rather than `create`+`truncate`: this is the only thing
/// standing between a second quarantine of the same bytes and the loss of the
/// first one's record. An `AlreadyExists` error is a normal outcome the caller
/// is expected to handle, not a failure.
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    write_new_io(path, bytes).map_err(|err| format!("cannot write {}: {err}", path.display()))
}

/// [`write_new`], keeping the `io::Error` so a caller can tell "already there"
/// apart from "could not write".
fn write_new_io(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.flush()
}

/// Keep the quarantine directory out of reach of ordinary users.
#[cfg(unix)]
fn restrict_directory(root: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(root, fs::Permissions::from_mode(0o700));
}

/// Restrict the directory to SYSTEM, Administrators, and the agent's own account.
///
/// The quarantine holds live malware. A directory inheriting an ACL that lets
/// interactive users read it turns the quarantine into a distribution point,
/// and one that lets them write it turns a restore into an arbitrary file write
/// by whoever owns the agent.
///
/// The account the agent runs as is granted alongside the two well-known ones,
/// because it is not always SYSTEM: a portable install runs as an ordinary
/// user, and an ACL that omits it locks the agent out of its own quarantine.
///
/// `icacls` is used rather than the security APIs because building a DACL by
/// hand is a great deal of unsafe code for a directory created once, and
/// because the result is inspectable by an administrator afterwards.
#[cfg(windows)]
fn restrict_directory(root: &Path) {
    use std::process::{Command, Stdio};

    let mut command = Command::new("icacls");
    command.arg(root);
    // Drop inherited entries first; without this the grants below are
    // additions to whatever the parent directory already allowed.
    command.args(["/inheritance:r"]);
    command.args(["/grant:r", "*S-1-5-18:(OI)(CI)F"]);
    command.args(["/grant:r", "*S-1-5-32-544:(OI)(CI)F"]);

    if let Some(sid) = current_user_sid() {
        command.args(["/grant:r", &format!("*{sid}:(OI)(CI)F")]);
    }

    let result = command.stdout(Stdio::null()).stderr(Stdio::null()).status();

    if !result.is_ok_and(|status| status.success()) {
        tracing::warn!(
            target: "response",
            directory = %root.display(),
            "Could not restrict the quarantine directory; it may be readable by other users"
        );
    }
}

/// The SID of the account this process runs as, in string form.
#[cfg(windows)]
fn current_user_sid() -> Option<String> {
    use windows::Win32::Foundation::{CloseHandle, LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = windows::Win32::Foundation::HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).ok()?;

        // Ask for the size first: a TOKEN_USER carries the SID inline after
        // the struct, so its length is not known ahead of time.
        let mut needed = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut needed);
        if needed == 0 {
            let _ = CloseHandle(token);
            return None;
        }

        let mut buffer = vec![0u8; needed as usize];
        let queried = GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            needed,
            &mut needed,
        );
        let _ = CloseHandle(token);
        queried.ok()?;

        let user = &*buffer.as_ptr().cast::<TOKEN_USER>();
        let mut raw = windows::core::PWSTR::null();
        ConvertSidToStringSidW(user.User.Sid, &mut raw).ok()?;

        let sid = raw.to_string().ok();
        let _ = LocalFree(Some(HLOCAL(raw.0.cast())));
        sid
    }
}

/// Nothing to do on platforms that are neither Unix nor Windows.
#[cfg(not(any(unix, windows)))]
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

    /// The same bytes dropped in two places are two incidents. Before record
    /// ids were separated from the content hash, the second quarantine wrote
    /// over the first one's metadata: the first `original_path` was lost, and
    /// restoring it put the sample back in the wrong directory.
    #[test]
    fn quarantining_identical_bytes_twice_keeps_both_records() {
        let (dir, store) = store();
        let first = dir.path().join("one").join("dropper.exe");
        let second = dir.path().join("two").join("dropper.exe");
        for path in [&first, &second] {
            fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            fs::write(path, b"identical malicious contents").expect("write");
        }

        let one = store.quarantine(&first, Some("Rule A")).expect("first");
        let two = store.quarantine(&second, Some("Rule B")).expect("second");

        assert_ne!(one.id, two.id, "each quarantine needs its own record id");
        assert_eq!(store.list().len(), 2, "neither record may be lost");
        assert_eq!(
            store.entry(&one.id).expect("first entry").original_path,
            first
        );
        assert_eq!(
            store.entry(&two.id).expect("second entry").original_path,
            second
        );

        // Content-addressed: one blob backs both records.
        assert_eq!(store.blob_path(&one.id), store.blob_path(&two.id));

        // Restoring one must not strand the other.
        store.restore(&one.id, None).expect("restore first");
        assert!(
            first.exists(),
            "the first sample goes back where it came from"
        );
        assert!(
            store.blob_path(&two.id).exists(),
            "the shared blob must survive while another record still needs it"
        );

        store.restore(&two.id, None).expect("restore second");
        assert!(
            second.exists(),
            "the second sample goes back to its own path"
        );
        assert!(
            !store.blob_path(&two.id).exists(),
            "the last record out removes the blob"
        );
        assert!(store.list().is_empty());
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
