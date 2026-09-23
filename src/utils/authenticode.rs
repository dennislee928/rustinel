//! Authenticode signature checks for Windows images.
//!
//! Fills the `Signed`, `Signature`, and `SignatureStatus` fields Sigma rules
//! written against Sysmon expect. Without them, a rule asking for an unsigned
//! binary in a directory that should only hold signed ones loads, sees every
//! process start, and never fires.
//!
//! # Two decisions worth knowing about
//!
//! **Revocation is never checked over the network.** `WinVerifyTrust` will
//! happily reach a CRL or OCSP responder, and it does so on the calling
//! thread. That thread here is the enrichment worker, which sits between the
//! sensor channel and the detection engine with no backpressure behind it: a
//! single slow responder would shed telemetry for as long as it took to time
//! out. Verification therefore runs cache-only, and a certificate revoked
//! since the last cache refresh reads as valid. That is a deliberate trade,
//! and it is the same one Sysmon makes.
//!
//! **An absent answer is not "unsigned".** A file that cannot be opened, or a
//! check that fails for its own reasons, yields `None` rather than
//! `Signed: false`. Reporting an unreadable file as unsigned would fire every
//! rule hunting for unsigned binaries in system directories.

use std::path::Path;

/// What a signature check concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureInfo {
    /// Whether the image carries a signature that verified.
    pub signed: bool,
    /// Sysmon's vocabulary: `Valid`, `Expired`, `Unsigned`, `Distrusted`, …
    pub status: String,
    /// The signing certificate's subject, when one could be read.
    pub subject: Option<String>,
}

impl SignatureInfo {
    /// Sysmon writes `Signed` as the strings `true` and `false`.
    pub fn signed_str(&self) -> String {
        self.signed.to_string()
    }
}

/// Check one image's Authenticode signature.
///
/// `None` means the question could not be answered, which is different from
/// answering "unsigned"; see the module note.
pub fn verify(path: &Path) -> Option<SignatureInfo> {
    platform::verify(path)
}

#[cfg(windows)]
mod platform {
    use super::SignatureInfo;
    use std::fs::File;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{
        CERT_E_EXPIRED, CERT_E_REVOKED, CERT_E_UNTRUSTEDROOT, CRYPT_E_SECURITY_SETTINGS, HANDLE,
        HWND, TRUST_E_BAD_DIGEST, TRUST_E_NOSIGNATURE, TRUST_E_PROVIDER_UNKNOWN,
        TRUST_E_SUBJECT_FORM_UNKNOWN, TRUST_E_SUBJECT_NOT_TRUSTED,
    };
    use windows::Win32::Security::Cryptography::Catalog::{
        CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
        CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
        CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, CATALOG_INFO,
    };
    use windows::Win32::Security::Cryptography::{
        CertCloseStore, CertFreeCertificateContext, CertGetNameStringW, CryptMsgClose,
        CryptMsgGetParam, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_QUERY_CONTENT_FLAG_ALL,
        CERT_QUERY_FORMAT_FLAG_ALL, CERT_QUERY_OBJECT_FILE, CMSG_SIGNER_INFO_PARAM, HCERTSTORE,
    };
    use windows::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA,
        WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG,
        WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
        WTD_UI_NONE,
    };

    /// Hash algorithm the catalogs are indexed under on current Windows.
    ///
    /// UTF-16 and NUL-terminated. The default is SHA-1, under which a modern
    /// catalog holds nothing.
    const SHA256_ALGORITHM: &[u16] = &[
        b'S' as u16,
        b'H' as u16,
        b'A' as u16,
        b'2' as u16,
        b'5' as u16,
        b'6' as u16,
        0,
    ];

    /// UTF-16, NUL-terminated, as every one of these APIs expects.
    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    pub(super) fn verify(path: &Path) -> Option<SignatureInfo> {
        if !path.is_file() {
            return None;
        }
        let wide_path = wide(path);

        let mut file_info = WINTRUST_FILE_INFO {
            cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: PCWSTR(wide_path.as_ptr()),
            hFile: HANDLE::default(),
            pgKnownSubject: std::ptr::null_mut(),
        };

        let mut trust_data = WINTRUST_DATA {
            cbStruct: size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            // Never over the network; see the module note.
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: WINTRUST_DATA_0 {
                pFile: &mut file_info,
            },
            dwStateAction: WTD_STATEACTION_VERIFY,
            dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
            ..Default::default()
        };

        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let status = unsafe {
            WinVerifyTrust(
                HWND::default(),
                &mut action,
                &mut trust_data as *mut WINTRUST_DATA as *mut core::ffi::c_void,
            )
        };

        // The close pass frees the state the verify pass allocated. Skipping it
        // leaks a handle per call, and this runs once per distinct image.
        trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
        unsafe {
            WinVerifyTrust(
                HWND::default(),
                &mut action,
                &mut trust_data as *mut WINTRUST_DATA as *mut core::ffi::c_void,
            );
        }

        // Most Windows system binaries carry no embedded signature; they are
        // signed by membership of a security catalog. Concluding "unsigned"
        // from the embedded check alone would report every one of them as
        // unsigned and fire every rule hunting unsigned binaries in
        // system directories, so an absent embedded signature is a question
        // for the catalogs rather than an answer.
        // The signature lives in the file itself, or in a catalog that vouches
        // for it. Whichever it is, that is the file the publisher name has to
        // be read from: a catalog-signed binary contains no certificate of its
        // own, so asking it would always answer "no publisher".
        let (status, signature_holder) = if status == TRUST_E_NOSIGNATURE.0 {
            match verify_by_catalog(path, &wide_path) {
                Some((catalog_status, catalog_path)) => (catalog_status, catalog_path),
                None => (status, wide_path.clone()),
            }
        } else {
            (status, wide_path.clone())
        };

        let (signed, verdict) = classify(status)?;

        Some(SignatureInfo {
            signed,
            status: verdict.to_string(),
            // Only worth reading when there is a signature to read it from.
            subject: signed.then(|| signer_subject(&signature_holder)).flatten(),
        })
    }

    /// Verify through the security catalogs.
    ///
    /// The file's hash is looked up across the installed catalogs; a hit names
    /// the catalog, and that catalog is what `WinVerifyTrust` is then asked
    /// about, with the file as a named member of it.
    ///
    /// Returns the verdict and the catalog that produced it, because the
    /// publisher name has to be read out of that catalog rather than out of the
    /// file, which carries no certificate of its own.
    ///
    /// `None` means no catalog claims this file, which leaves the caller with
    /// the embedded verdict it already had.
    fn verify_by_catalog(path: &Path, wide_path: &[u16]) -> Option<(i32, Vec<u16>)> {
        let file = File::open(path).ok()?;
        let handle = HANDLE(file.as_raw_handle() as _);

        let mut admin: isize = 0;
        unsafe {
            // SHA-256 explicitly: the default algorithm on older systems is
            // SHA-1, and catalogs written for current Windows are not indexed
            // under it.
            CryptCATAdminAcquireContext2(
                &mut admin,
                None,
                PCWSTR(SHA256_ALGORITHM.as_ptr()),
                None,
                None,
            )
            .ok()?;
        }

        let result = catalog_status(admin, handle, wide_path);

        unsafe {
            let _ = CryptCATAdminReleaseContext(admin, 0);
        }
        result
    }

    /// The verdict for a file that some catalog vouches for, and that catalog.
    fn catalog_status(admin: isize, file: HANDLE, wide_path: &[u16]) -> Option<(i32, Vec<u16>)> {
        // Sized, then filled: the usual two-call CryptoAPI shape.
        let mut hash_len = 0u32;
        unsafe {
            let _ = CryptCATAdminCalcHashFromFileHandle2(admin, file, &mut hash_len, None, None);
        }
        if hash_len == 0 {
            return None;
        }

        let mut hash = vec![0u8; hash_len as usize];
        unsafe {
            CryptCATAdminCalcHashFromFileHandle2(
                admin,
                file,
                &mut hash_len,
                Some(hash.as_mut_ptr()),
                None,
            )
            .ok()?;
        }

        let catalog = unsafe { CryptCATAdminEnumCatalogFromHash(admin, &hash, None, None) };
        if catalog == 0 {
            // No catalog claims it. Genuinely unsigned files land here, which
            // is the answer the caller keeps.
            return None;
        }

        let mut info = CATALOG_INFO {
            cbStruct: size_of::<CATALOG_INFO>() as u32,
            ..Default::default()
        };
        let named = unsafe { CryptCATCatalogInfoFromContext(catalog, &mut info, 0).is_ok() };

        let status = named.then(|| {
            // The member tag is the file hash as uppercase hex, which is how a
            // catalog indexes its members.
            let mut tag: Vec<u16> = hex_upper(&hash).encode_utf16().collect();
            tag.push(0);

            let mut catalog_info = WINTRUST_CATALOG_INFO {
                cbStruct: size_of::<WINTRUST_CATALOG_INFO>() as u32,
                pcwszCatalogFilePath: PCWSTR(info.wszCatalogFile.as_ptr()),
                pcwszMemberTag: PCWSTR(tag.as_ptr()),
                pcwszMemberFilePath: PCWSTR(wide_path.as_ptr()),
                hMemberFile: file,
                pbCalculatedFileHash: hash.as_mut_ptr(),
                cbCalculatedFileHash: hash_len,
                hCatAdmin: admin,
                ..Default::default()
            };

            let mut trust_data = WINTRUST_DATA {
                cbStruct: size_of::<WINTRUST_DATA>() as u32,
                dwUIChoice: WTD_UI_NONE,
                fdwRevocationChecks: WTD_REVOKE_NONE,
                dwUnionChoice: WTD_CHOICE_CATALOG,
                Anonymous: WINTRUST_DATA_0 {
                    pCatalog: &mut catalog_info,
                },
                dwStateAction: WTD_STATEACTION_VERIFY,
                dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
                ..Default::default()
            };

            let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            let status = unsafe {
                WinVerifyTrust(
                    HWND::default(),
                    &mut action,
                    &mut trust_data as *mut WINTRUST_DATA as *mut core::ffi::c_void,
                )
            };

            trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
            unsafe {
                WinVerifyTrust(
                    HWND::default(),
                    &mut action,
                    &mut trust_data as *mut WINTRUST_DATA as *mut core::ffi::c_void,
                );
            }
            // Copied before the catalog context is released below.
            let catalog_path: Vec<u16> = info
                .wszCatalogFile
                .iter()
                .copied()
                .take_while(|unit| *unit != 0)
                .chain(std::iter::once(0))
                .collect();
            (status, catalog_path)
        });

        unsafe {
            let _ = CryptCATAdminReleaseCatalogContext(admin, catalog, 0);
        }
        status
    }

    /// Uppercase hex, which is the spelling a catalog member tag uses.
    fn hex_upper(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use std::fmt::Write;
            let _ = write!(out, "{byte:02X}");
        }
        out
    }

    /// Turn `WinVerifyTrust`'s status into Sysmon's vocabulary.
    ///
    /// `None` for a status that says the check itself did not happen, so the
    /// caller reports nothing rather than reporting "unsigned".
    fn classify(status: i32) -> Option<(bool, &'static str)> {
        match status {
            0 => Some((true, "Valid")),
            s if s == TRUST_E_NOSIGNATURE.0 => Some((false, "Unsigned")),
            s if s == TRUST_E_BAD_DIGEST.0 => Some((false, "Modified")),
            s if s == CERT_E_EXPIRED.0 => Some((false, "Expired")),
            s if s == CERT_E_REVOKED.0 => Some((false, "Revoked")),
            s if s == CERT_E_UNTRUSTEDROOT.0 || s == TRUST_E_SUBJECT_NOT_TRUSTED.0 => {
                Some((false, "Distrusted"))
            }
            s if s == CRYPT_E_SECURITY_SETTINGS.0 => Some((false, "Distrusted")),
            // The provider could not handle the file at all: not a PE, or a
            // format Authenticode does not cover. The file is not "unsigned",
            // the question simply does not apply.
            s if s == TRUST_E_PROVIDER_UNKNOWN.0 || s == TRUST_E_SUBJECT_FORM_UNKNOWN.0 => None,
            _ => None,
        }
    }

    /// The signing certificate's subject name.
    ///
    /// Best-effort: a signature that verified but whose subject cannot be read
    /// still reports `Signed: true`, because the verdict and the name come
    /// from two different calls and only the verdict decides whether a rule
    /// about signing fires.
    fn signer_subject(wide_path: &[u16]) -> Option<String> {
        let mut store = HCERTSTORE::default();
        let mut message: *mut core::ffi::c_void = std::ptr::null_mut();

        unsafe {
            windows::Win32::Security::Cryptography::CryptQueryObject(
                CERT_QUERY_OBJECT_FILE,
                wide_path.as_ptr() as *const core::ffi::c_void,
                CERT_QUERY_CONTENT_FLAG_ALL,
                CERT_QUERY_FORMAT_FLAG_ALL,
                0,
                None,
                None,
                None,
                Some(&mut store),
                Some(&mut message),
                None,
            )
            .ok()?;
        }

        // CryptQueryObject reports success for content types that carry no
        // signed message, leaving this handle null. Passing a null handle to
        // CryptMsgGetParam faults rather than failing, so it is checked here.
        let subject = (!message.is_null())
            .then(|| read_subject(store, message))
            .flatten();

        unsafe {
            if !message.is_null() {
                let _ = CryptMsgClose(Some(message));
            }
            if !store.is_invalid() {
                let _ = CertCloseStore(Some(store), 0);
            }
        }

        subject
    }

    /// Pull the signer out of the message and name it from the store.
    fn read_subject(store: HCERTSTORE, message: *const core::ffi::c_void) -> Option<String> {
        // Two calls: the first sizes the buffer, the second fills it. This is
        // the standard CryptoAPI shape and there is no way to skip the first.
        let mut needed = 0u32;
        unsafe {
            CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, None, &mut needed).ok()?;
        }
        if needed == 0 {
            return None;
        }

        let mut buffer = vec![0u8; needed as usize];
        unsafe {
            CryptMsgGetParam(
                message,
                CMSG_SIGNER_INFO_PARAM,
                0,
                Some(buffer.as_mut_ptr() as *mut core::ffi::c_void),
                &mut needed,
            )
            .ok()?;
        }

        // SAFETY: the buffer holds a CMSG_SIGNER_INFO written by CryptoAPI,
        // sized by the call above.
        let signer = unsafe {
            &*(buffer.as_ptr() as *const windows::Win32::Security::Cryptography::CMSG_SIGNER_INFO)
        };

        let mut info = windows::Win32::Security::Cryptography::CERT_INFO {
            Issuer: signer.Issuer,
            SerialNumber: signer.SerialNumber,
            ..Default::default()
        };

        let context = unsafe {
            windows::Win32::Security::Cryptography::CertFindCertificateInStore(
                store,
                windows::Win32::Security::Cryptography::X509_ASN_ENCODING
                    | windows::Win32::Security::Cryptography::PKCS_7_ASN_ENCODING,
                0,
                windows::Win32::Security::Cryptography::CERT_FIND_SUBJECT_CERT,
                Some(&mut info as *mut _ as *const core::ffi::c_void),
                None,
            )
        };
        if context.is_null() {
            return None;
        }

        let length =
            unsafe { CertGetNameStringW(context, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None) };
        // One means the terminator alone: a present but empty name.
        let name = if length > 1 {
            let mut buffer = vec![0u16; length as usize];
            let written = unsafe {
                CertGetNameStringW(
                    context,
                    CERT_NAME_SIMPLE_DISPLAY_TYPE,
                    0,
                    None,
                    Some(&mut buffer),
                )
            };
            (written > 1).then(|| String::from_utf16_lossy(&buffer[..written as usize - 1]))
        } else {
            None
        };

        unsafe {
            let _ = CertFreeCertificateContext(Some(context));
        }
        name
    }
}

#[cfg(not(windows))]
mod platform {
    use super::SignatureInfo;
    use std::path::Path;

    /// Authenticode is a Windows notion.
    ///
    /// macOS signing is read straight off the Endpoint Security event, which
    /// carries it without any file being opened, so nothing routes here.
    pub(super) fn verify(_path: &Path) -> Option<SignatureInfo> {
        None
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn system32(name: &str) -> PathBuf {
        PathBuf::from(std::env::var("WINDIR").unwrap_or_else(|_| r"C:\Windows".to_string()))
            .join("System32")
            .join(name)
    }

    /// A catalog-signed system binary verifies.
    ///
    /// This is the case that makes the whole catalog path necessary: most
    /// Windows system binaries carry no embedded signature at all, and an
    /// embedded-only check reports every one of them as unsigned. That would
    /// fire every rule hunting for unsigned binaries in system directories,
    /// which is worse than reporting nothing.
    #[test]
    fn a_catalog_signed_system_binary_verifies() {
        let path = system32("notepad.exe");
        if !path.is_file() {
            return;
        }

        let Some(info) = verify(&path) else {
            panic!("a system binary must produce a verdict");
        };

        assert!(info.signed, "a system binary must verify: {info:?}");
        assert_eq!(info.status, "Valid");
        assert_eq!(info.signed_str(), "true");
    }

    /// An embedded signature also yields the publisher.
    ///
    /// The name is read out of the certificate in the file, so it is available
    /// for embedded signatures and not for catalog ones, where the file holds
    /// no certificate of its own. Third-party binaries — the ones a rule about
    /// publishers is usually written for — are embedded-signed.
    #[test]
    fn an_embedded_signature_names_its_publisher() {
        // Picked by probing rather than hard-coded: which system binaries are
        // embedded-signed rather than catalog-signed varies by Windows build.
        let Some((path, info)) = std::fs::read_dir(system32(""))
            .into_iter()
            .flatten()
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "exe"))
            .take(60)
            .filter_map(|path| {
                let info = verify(&path)?;
                (info.signed && info.subject.is_some()).then_some((path, info))
            })
            .next()
        else {
            // No embedded-signed binary in the sample; nothing to assert.
            return;
        };

        let subject = info.subject.as_deref().expect("filtered for a subject");
        assert!(
            subject.contains("Microsoft"),
            "expected a Microsoft publisher for {}, got {subject}",
            path.display()
        );
    }

    /// The case the 15 blocked SigmaHQ rules are actually written for.
    #[test]
    fn an_unsigned_file_is_reported_unsigned_rather_than_unknown() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("dropper.exe");
        // A real PE, so Authenticode judges it rather than declining the
        // format: the smallest thing WinVerifyTrust will call unsigned is a
        // file it recognises as an image.
        std::fs::copy(system32("notepad.exe"), &path).expect("copy");

        // Truncating breaks the embedded signature's digest.
        let bytes = std::fs::read(&path).expect("read");
        std::fs::write(&path, &bytes[..bytes.len() / 2]).expect("truncate");

        if let Some(info) = verify(&path) {
            assert!(!info.signed, "a mangled copy must not verify: {:?}", info);
            assert_ne!(info.status, "Valid");
        }
    }

    /// A file that is not there yields no answer at all.
    ///
    /// Reporting it as unsigned would fire every rule hunting unsigned
    /// binaries in system directories.
    #[test]
    fn a_missing_file_is_unanswered_rather_than_unsigned() {
        assert!(verify(Path::new(r"C:\does\not\exist\gone.exe")).is_none());
    }
}
