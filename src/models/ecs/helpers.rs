pub(super) fn parse_u64(value: &Option<String>) -> Option<u64> {
    value.as_ref().and_then(|v| v.trim().parse::<u64>().ok())
}

pub(super) fn parse_u16(value: &Option<String>) -> Option<u16> {
    value.as_ref().and_then(|v| v.trim().parse::<u16>().ok())
}

pub(super) fn parse_bool(value: &Option<String>) -> Option<bool> {
    let normalized = value.as_ref()?.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "true" | "signed" | "valid" | "yes" => Some(true),
        "false" | "unsigned" | "invalid" | "no" => Some(false),
        _ => None,
    }
}

pub(super) fn basename(path: &str) -> Option<String> {
    let trimmed = path.trim_matches('"');
    let name = trimmed.rsplit(['\\', '/']).next().unwrap_or("");
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

pub(super) fn file_extension_from_path(path: &str) -> Option<String> {
    let name = basename(path)?;
    let (_, ext) = name.rsplit_once('.')?;
    if ext.is_empty() {
        None
    } else {
        Some(ext.to_string())
    }
}

/// Split Sysmon's `ALGO=VALUE,ALGO=VALUE` string into ECS hash fields.
///
/// Returns `(md5, sha256)`, lowercased. Sysmon writes uppercase hex and ECS
/// specifies lowercase, so this is a conversion rather than a copy; a SIEM
/// joining these against a threat-intelligence feed compares them as strings
/// and would miss on case alone.
///
/// Algorithms other than MD5 and SHA-256 are ignored here. They stay readable
/// in the `Hashes` field, which is the one rules match on.
pub(super) fn split_sysmon_hashes(hashes: Option<&str>) -> (Option<String>, Option<String>) {
    let Some(hashes) = hashes else {
        return (None, None);
    };

    let mut md5 = None;
    let mut sha256 = None;
    for part in hashes.split(',') {
        let Some((algorithm, value)) = part.split_once('=') else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match algorithm.trim().to_ascii_uppercase().as_str() {
            "MD5" => md5 = Some(value.to_ascii_lowercase()),
            "SHA256" => sha256 = Some(value.to_ascii_lowercase()),
            _ => {}
        }
    }
    (md5, sha256)
}

#[cfg(test)]
mod hash_tests {
    use super::split_sysmon_hashes;

    #[test]
    fn sysmon_hashes_become_lowercase_ecs_fields() {
        let (md5, sha256) = split_sysmon_hashes(Some(
            "MD5=D41D8CD98F00B204E9800998ECF8427E,\
             SHA256=E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
        ));

        // ECS specifies lowercase; Sysmon writes uppercase. A SIEM joining
        // these against an intelligence feed compares strings, so the case
        // conversion is the whole point of this function.
        assert_eq!(md5.as_deref(), Some("d41d8cd98f00b204e9800998ecf8427e"));
        assert_eq!(
            sha256.as_deref(),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
    }

    #[test]
    fn an_absent_or_unparseable_value_yields_nothing() {
        assert_eq!(split_sysmon_hashes(None), (None, None));
        assert_eq!(split_sysmon_hashes(Some("")), (None, None));
        assert_eq!(split_sysmon_hashes(Some("garbage")), (None, None));
        assert_eq!(split_sysmon_hashes(Some("SHA256=")), (None, None));
    }

    #[test]
    fn algorithms_without_an_ecs_field_are_left_alone() {
        // IMPHASH and SHA1 stay readable in `Hashes`, which is what rules
        // match on; only the two ECS fields are extracted here.
        let (md5, sha256) = split_sysmon_hashes(Some("IMPHASH=ABC123,SHA1=DEF456"));
        assert!(md5.is_none() && sha256.is_none());
    }
}
