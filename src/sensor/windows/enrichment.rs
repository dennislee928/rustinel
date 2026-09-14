//! Post-callback enrichment for Windows sensor events.
//!
//! ETW callbacks only decode data already carried by an event. Work that can
//! block, including opening and mapping PE images, belongs here after the
//! bounded sensor channel has accepted the event.

use crate::config::ProcessConfig;
use crate::ioc::{ComputedHashes, HashCache, HashRequirements};
use crate::sensor::{SensorAction, SensorEvent, SensorPayload};
use crate::utils::authenticode::{self, SignatureInfo};
use crate::utils::file_identity::{self, FileIdentity};
use crate::utils::{parse_metadata, pe};
use std::collections::HashMap;
use std::path::Path;

/// Read buffer for hashing, matching the IOC worker's.
const HASH_BUFFER_BYTES: usize = 64 * 1024;

/// Distinct images whose signature verdict is remembered.
///
/// Verification is expensive — the catalog path hashes the whole file — and a
/// machine executes the same few binaries endlessly, so this is what keeps the
/// cost to once per image rather than once per event.
const SIGNATURE_CACHE_MAX_ENTRIES: usize = 4096;

/// Add PE version-resource fields to process-start and image-load events.
pub(crate) fn enrich_event(event: &mut SensorEvent) {
    match &mut event.payload {
        SensorPayload::Process(fields) if event.action == SensorAction::Start => {
            let metadata = fields.image.as_deref().and_then(parse_metadata);
            (
                fields.original_file_name,
                fields.product,
                fields.description,
                fields.company,
                fields.file_version,
            ) = pe::version_fields(metadata);
        }
        SensorPayload::ImageLoad(fields) => {
            let metadata = fields.image_loaded.as_deref().and_then(parse_metadata);
            (
                fields.original_file_name,
                fields.product,
                fields.description,
                fields.company,
                fields.file_version,
            ) = pe::version_fields(metadata);
        }
        _ => {}
    }
}

/// Per-thread enrichment state.
///
/// Holds the hash cache, which is the only thing making hashing affordable on
/// this thread: a machine executes the same handful of binaries thousands of
/// times, and each distinct image is read once per TTL rather than once per
/// event. One enricher belongs to one sensor worker thread, so the cache needs
/// no lock.
pub(crate) struct Enricher {
    hashing: Option<ImageHashing>,
}

/// Hash state, present only when the operator left hashing on.
struct ImageHashing {
    cache: HashCache,
    buffer: Vec<u8>,
    max_file_size_bytes: u64,
    /// Signature verdicts, keyed by file identity so a replaced binary at the
    /// same path is verified again rather than trusted from its predecessor.
    signatures: HashMap<FileIdentity, Option<SignatureInfo>>,
}

impl Enricher {
    /// Build the enricher for one sensor worker thread.
    pub(crate) fn new(config: &ProcessConfig) -> Self {
        Self {
            hashing: config.hash_images.then(|| ImageHashing {
                cache: HashCache::new(),
                buffer: vec![0u8; HASH_BUFFER_BYTES],
                // Saturating rather than wrapping: an operator who writes a
                // preposterous limit gets no limit, not a limit of nearly zero
                // that silently stops hashing anything.
                max_file_size_bytes: config.hash_max_file_size_mb.saturating_mul(1024 * 1024),
                signatures: HashMap::new(),
            }),
        }
    }

    /// Enrich one event in place.
    pub(crate) fn enrich(&mut self, event: &mut SensorEvent) {
        enrich_event(event);

        let Some(hashing) = self.hashing.as_mut() else {
            return;
        };

        match &mut event.payload {
            SensorPayload::Process(fields) if event.action == SensorAction::Start => {
                let image = fields.image.clone();
                if let Some(image) = image.as_deref() {
                    fields.hashes = hashing.hashes_for(image);
                    if let Some(signature) = hashing.signature_for(image) {
                        fields.signed = Some(signature.signed_str());
                        fields.signature_status = Some(signature.status.clone());
                        fields.signature = signature.subject.clone();
                    }
                }
            }
            SensorPayload::ImageLoad(fields) => {
                let image = fields.image_loaded.clone();
                if let Some(image) = image.as_deref() {
                    fields.hashes = hashing.hashes_for(image);
                    if let Some(signature) = hashing.signature_for(image) {
                        fields.signed = Some(signature.signed_str());
                        fields.signature_status = Some(signature.status.clone());
                        // ImageLoadFields already carried Signature; only fill
                        // it when the decoder left it empty.
                        if fields.signature.is_none() {
                            fields.signature = signature.subject.clone();
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

impl ImageHashing {
    /// Hashes for one image, in Sysmon's spelling, or `None`.
    fn hashes_for(&mut self, image: &str) -> Option<String> {
        if image.is_empty() {
            return None;
        }
        let path = Path::new(image);

        // Checked before the open so an oversized image costs a stat rather
        // than a full read.
        if self.max_file_size_bytes > 0 {
            match std::fs::metadata(path) {
                Ok(metadata) if metadata.len() > self.max_file_size_bytes => return None,
                Ok(_) => {}
                // Unreadable here means unreadable in a moment; skip quietly
                // rather than logging once per process start.
                Err(_) => return None,
            }
        }

        // MD5 and SHA-256 because that is what the corpus writes. SHA-1 is
        // computed by almost no rule and would be read cost for nothing.
        let requirements = HashRequirements {
            md5: true,
            sha1: false,
            sha256: true,
        };

        let hashes = self
            .cache
            .get_or_compute(path, requirements, &mut self.buffer)
            .ok()?;
        format_sysmon_hashes(&hashes)
    }

    /// The signature verdict for one image, remembered per file identity.
    ///
    /// `None` means the question could not be answered, which the caller must
    /// keep distinct from `Signed: false`: reporting an unreadable file as
    /// unsigned would fire every rule hunting unsigned binaries in system
    /// directories.
    fn signature_for(&mut self, image: &str) -> Option<&SignatureInfo> {
        if image.is_empty() {
            return None;
        }
        let path = Path::new(image);
        let identity = file_identity::from_path(path)?;

        if !self.signatures.contains_key(&identity) {
            // Bounded by dropping the whole table rather than tracking ages:
            // the entries are cheap to rebuild, and an agent that has seen
            // four thousand distinct images has already paid the interesting
            // part of the cost.
            if self.signatures.len() >= SIGNATURE_CACHE_MAX_ENTRIES {
                self.signatures.clear();
            }
            let verdict = authenticode::verify(path);
            self.signatures.insert(identity.clone(), verdict);
        }

        self.signatures.get(&identity)?.as_ref()
    }
}

/// Render hashes the way Sysmon writes them, and Sigma rules read them.
///
/// `MD5=...,SHA256=...`, uppercase hex, in Sysmon's field order. A rule
/// written as `Hashes|contains: 'SHA256=ABC...'` only matches this exact
/// spelling, so the format is part of the detection contract rather than a
/// display choice.
fn format_sysmon_hashes(hashes: &ComputedHashes) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(md5) = &hashes.md5 {
        parts.push(format!("MD5={}", md5.to_uppercase()));
    }
    if let Some(sha1) = &hashes.sha1 {
        parts.push(format!("SHA1={}", sha1.to_uppercase()));
    }
    if let Some(sha256) = &hashes.sha256 {
        parts.push(format!("SHA256={}", sha256.to_uppercase()));
    }
    (!parts.is_empty()).then(|| parts.join(","))
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use crate::models::{ImageLoadFields, ProcessCreationFields};
    use crate::sensor::{Platform, SensorNormalization};

    use super::*;

    fn event(action: SensorAction, payload: SensorPayload) -> SensorEvent {
        SensorEvent {
            platform: Platform::Windows,
            provider: "etw",
            action,
            normalization: SensorNormalization {
                event_id: 1,
                action_code: 1,
            },
            pid: Some(42),
            timestamp: UNIX_EPOCH,
            source_seq: None,
            process_start_key: None,
            parent_process_start_key: None,
            payload,
        }
    }

    fn process_fields(image: &str) -> ProcessCreationFields {
        ProcessCreationFields {
            hashes: None,
            signed: None,
            signature: None,
            signature_status: None,
            image: Some(image.to_string()),
            image_source: None,
            image_truncated: None,
            original_file_name: None,
            product: None,
            description: None,
            company: None,
            file_version: None,
            target_image: None,
            command_line: None,
            process_id: Some("42".to_string()),
            process_start_time: None,
            parent_process_id: None,
            parent_image: None,
            parent_command_line: None,
            current_directory: None,
            integrity_level: None,
            user: None,
        }
    }

    fn image_load_fields(image: &str) -> ImageLoadFields {
        ImageLoadFields {
            hashes: None,
            signature_status: None,
            image_loaded: Some(image.to_string()),
            process_id: Some("42".to_string()),
            image: None,
            original_file_name: None,
            product: None,
            description: None,
            company: None,
            file_version: None,
            signed: None,
            signature: None,
            user: None,
        }
    }

    #[test]
    fn process_start_is_enriched_after_decode() {
        let mut event = event(
            SensorAction::Start,
            SensorPayload::Process(process_fields(r"C:\Windows\System32\cmd.exe")),
        );

        enrich_event(&mut event);

        let SensorPayload::Process(fields) = event.payload else {
            panic!("expected process payload");
        };
        assert!(fields.original_file_name.is_some());
        assert!(fields.product.is_some());
        assert!(fields.description.is_some());
    }

    #[test]
    fn image_load_is_enriched_after_decode() {
        let mut event = event(
            SensorAction::Load,
            SensorPayload::ImageLoad(image_load_fields(r"C:\Windows\System32\cmd.exe")),
        );

        enrich_event(&mut event);

        let SensorPayload::ImageLoad(fields) = event.payload else {
            panic!("expected image-load payload");
        };
        assert!(fields.original_file_name.is_some());
        assert!(fields.product.is_some());
        assert!(fields.description.is_some());
    }

    fn process_config(hash_images: bool, hash_max_file_size_mb: u64) -> ProcessConfig {
        ProcessConfig {
            max_entries: 1024,
            hash_images,
            hash_max_file_size_mb,
        }
    }

    /// The spelling is the contract. A rule writes
    /// `Hashes|contains: 'SHA256=ABC...'`, so lowercase hex, a different
    /// separator, or a different algorithm order all mean "no match" rather
    /// than "nearly a match".
    #[test]
    fn hashes_are_written_the_way_sigma_rules_read_them() {
        let rendered = format_sysmon_hashes(&ComputedHashes {
            md5: Some("d41d8cd98f00b204e9800998ecf8427e".to_string()),
            sha1: None,
            sha256: Some(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            ),
        })
        .expect("hashes render");

        assert_eq!(
            rendered,
            "MD5=D41D8CD98F00B204E9800998ECF8427E,\
             SHA256=E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        );
    }

    #[test]
    fn no_hashes_at_all_is_absent_rather_than_an_empty_string() {
        assert!(format_sysmon_hashes(&ComputedHashes {
            md5: None,
            sha1: None,
            sha256: None,
        })
        .is_none());
    }

    /// The gap this closes: without `Hashes`, every SigmaHQ rule matching on a
    /// hash loads, sees the event, and never fires.
    #[test]
    fn a_process_start_carries_the_hashes_of_its_image() {
        let dir = tempfile::tempdir().expect("tempdir");
        let image = dir.path().join("sample.exe");
        std::fs::write(&image, b"").expect("write");

        let mut enricher = Enricher::new(&process_config(true, 64));
        let mut event = event(
            SensorAction::Start,
            SensorPayload::Process(process_fields(&image.to_string_lossy())),
        );

        enricher.enrich(&mut event);

        let SensorPayload::Process(fields) = event.payload else {
            panic!("expected process payload");
        };
        // The empty file's well-known digests, so this asserts the real bytes
        // were read rather than that something was merely written.
        assert_eq!(
            fields.hashes.as_deref(),
            Some(
                "MD5=D41D8CD98F00B204E9800998ECF8427E,\
                 SHA256=E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
            )
        );
    }

    /// The gap the 15 blocked SigmaHQ `Signed` rules describe.
    ///
    /// A real system binary is signed, so a rule asking for an unsigned binary
    /// in a system directory must not fire on it.
    #[test]
    fn a_process_start_carries_the_signature_of_its_image() {
        let image = std::path::PathBuf::from(
            std::env::var("WINDIR").unwrap_or_else(|_| r"C:\Windows".to_string()),
        )
        .join("System32")
        .join("notepad.exe");
        if !image.is_file() {
            return;
        }

        let mut enricher = Enricher::new(&process_config(true, 64));
        let mut event = event(
            SensorAction::Start,
            SensorPayload::Process(process_fields(&image.to_string_lossy())),
        );

        enricher.enrich(&mut event);

        let SensorPayload::Process(fields) = event.payload else {
            panic!("expected process payload");
        };
        assert_eq!(fields.signed.as_deref(), Some("true"));
        assert_eq!(fields.signature_status.as_deref(), Some("Valid"));
    }

    /// An image that cannot be judged carries no verdict at all.
    ///
    /// Writing `Signed: false` here would fire every rule hunting unsigned
    /// binaries, on a file the agent simply could not read.
    #[test]
    fn an_unreadable_image_carries_no_signature_verdict() {
        let mut enricher = Enricher::new(&process_config(true, 64));
        let mut event = event(
            SensorAction::Start,
            SensorPayload::Process(process_fields(
                r"C:\does
ot\exist\gone.exe",
            )),
        );

        enricher.enrich(&mut event);

        let SensorPayload::Process(fields) = event.payload else {
            panic!("expected process payload");
        };
        assert!(fields.signed.is_none());
        assert!(fields.signature_status.is_none());
        assert!(fields.signature.is_none());
    }

    #[test]
    fn hashing_can_be_switched_off() {
        let dir = tempfile::tempdir().expect("tempdir");
        let image = dir.path().join("sample.exe");
        std::fs::write(&image, b"whatever").expect("write");

        let mut enricher = Enricher::new(&process_config(false, 64));
        let mut event = event(
            SensorAction::Start,
            SensorPayload::Process(process_fields(&image.to_string_lossy())),
        );

        enricher.enrich(&mut event);

        let SensorPayload::Process(fields) = event.payload else {
            panic!("expected process payload");
        };
        assert!(fields.hashes.is_none());
    }

    /// An image over the limit is left unhashed rather than read anyway.
    ///
    /// This is what stops one enormous binary stalling the enrichment thread,
    /// which has no backpressure behind it: everything queued behind a slow
    /// hash is shed, not delayed.
    #[test]
    fn an_oversized_image_is_skipped_rather_than_stalling_the_thread() {
        let dir = tempfile::tempdir().expect("tempdir");
        let image = dir.path().join("huge.exe");
        std::fs::write(&image, vec![0u8; 2 * 1024 * 1024]).expect("write");

        // One MiB ceiling against a two MiB image.
        let mut enricher = Enricher::new(&process_config(true, 1));
        let mut event = event(
            SensorAction::Start,
            SensorPayload::Process(process_fields(&image.to_string_lossy())),
        );

        enricher.enrich(&mut event);

        let SensorPayload::Process(fields) = event.payload else {
            panic!("expected process payload");
        };
        assert!(fields.hashes.is_none());
    }

    #[test]
    fn an_image_that_is_gone_does_not_fail_the_event() {
        let mut enricher = Enricher::new(&process_config(true, 64));
        let mut event = event(
            SensorAction::Start,
            SensorPayload::Process(process_fields(r"C:\does\not\exist\gone.exe")),
        );

        enricher.enrich(&mut event);

        let SensorPayload::Process(fields) = event.payload else {
            panic!("expected process payload");
        };
        assert!(fields.hashes.is_none());
        // The rest of the event still has to survive a missing image.
        assert_eq!(fields.process_id.as_deref(), Some("42"));
    }

    #[test]
    fn process_stop_does_not_read_the_image() {
        let mut event = event(
            SensorAction::Stop,
            SensorPayload::Process(process_fields(r"C:\Windows\System32\cmd.exe")),
        );

        enrich_event(&mut event);

        let SensorPayload::Process(fields) = event.payload else {
            panic!("expected process payload");
        };
        assert!(fields.original_file_name.is_none());
        assert!(fields.product.is_none());
        assert!(fields.description.is_none());
    }
}
