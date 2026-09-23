//! Platform hardening the agent depends on but cannot provide.
//!
//! Rustinel runs in user mode, which means an attacker who reaches kernel mode
//! is past it entirely: they can unload a driver, patch the kernel structures
//! the agent's telemetry comes from, or read `lsass` memory the agent is
//! watching for. Nothing Rustinel does can stop that. What stops it is the
//! platform's own virtualization-based protections, and those are either
//! switched on or they are not.
//!
//! So the agent reports on them. These checks are warnings rather than
//! failures: a machine without them is not misconfigured for Rustinel, it is
//! simply a machine where a kernel-level attacker will win, and the operator
//! should know which one they are running on.
//!
//! Every check reads state. None of them changes it: turning on Credential
//! Guard or memory integrity has reboot and driver-compatibility consequences
//! that belong to whoever owns the machine.

use super::inspect::DiagnosticResult;

/// Report on the platform protections that sit underneath the agent.
pub fn posture_results() -> Vec<DiagnosticResult> {
    platform::posture_results()
}

#[cfg(windows)]
mod platform {
    use super::DiagnosticResult;
    use windows::core::w;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegGetValueW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
        RRF_RT_REG_DWORD,
    };

    /// Read one REG_DWORD, returning `None` when the key or value is absent.
    fn read_dword(subkey: windows::core::PCWSTR, value: windows::core::PCWSTR) -> Option<u32> {
        let mut key = HKEY::default();
        let opened = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey, None, KEY_READ, &mut key) };
        if opened.is_err() {
            return None;
        }

        let mut data = 0u32;
        let mut size = std::mem::size_of::<u32>() as u32;
        let status = unsafe {
            RegGetValueW(
                key,
                None,
                value,
                RRF_RT_REG_DWORD,
                None,
                Some(std::ptr::from_mut(&mut data).cast()),
                Some(&mut size),
            )
        };
        unsafe {
            let _ = RegCloseKey(key);
        }

        status.is_ok().then_some(data)
    }

    /// Whether the hypervisor's code-integrity enforcement is running.
    ///
    /// Reported by the kernel rather than by policy: the policy key says what
    /// was asked for, this says what is actually in force.
    fn code_integrity() -> Option<(bool, bool)> {
        // Declared here rather than pulled from the WDK bindings, matching how
        // `platform::windows` already reaches this call.
        #[link(name = "ntdll")]
        extern "system" {
            fn NtQuerySystemInformation(
                SystemInformationClass: u32,
                SystemInformation: *mut u8,
                SystemInformationLength: u32,
                ReturnLength: *mut u32,
            ) -> i32;
        }

        #[repr(C)]
        struct CodeIntegrityInformation {
            length: u32,
            options: u32,
        }

        /// `SystemCodeIntegrityInformation`
        const CLASS: u32 = 103;
        /// `CODEINTEGRITY_OPTION_ENABLED`
        const ENABLED: u32 = 0x01;
        /// `CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED`
        const HVCI: u32 = 0x400;

        let mut info = CodeIntegrityInformation {
            length: std::mem::size_of::<CodeIntegrityInformation>() as u32,
            options: 0,
        };
        let mut returned = 0u32;

        let status = unsafe {
            NtQuerySystemInformation(
                CLASS,
                std::ptr::from_mut(&mut info).cast::<u8>(),
                info.length,
                &mut returned,
            )
        };

        // NTSTATUS: negative is a failure.
        (status >= 0).then_some((info.options & ENABLED != 0, info.options & HVCI != 0))
    }

    pub(super) fn posture_results() -> Vec<DiagnosticResult> {
        let mut results = Vec::new();

        // Virtualization-based security, the foundation the rest sits on.
        let vbs_configured = read_dword(
            w!(r"SYSTEM\CurrentControlSet\Control\DeviceGuard"),
            w!("EnableVirtualizationBasedSecurity"),
        )
        .unwrap_or(0);

        results.push(if vbs_configured == 1 {
            DiagnosticResult::pass("posture_vbs", "Virtualization-based security is configured")
        } else {
            DiagnosticResult::warn(
                "posture_vbs",
                "Virtualization-based security is not configured",
                "Without VBS the kernel has no isolated world to protect itself with, so an \
                 attacker who reaches kernel mode can tamper with the telemetry Rustinel \
                 depends on.",
            )
            .with_fix("Enable Virtualization Based Security under Device Guard policy, then reboot")
        });

        // Memory integrity: the part that stops unsigned code in the kernel.
        match code_integrity() {
            Some((enabled, hvci)) => {
                results.push(if hvci {
                    DiagnosticResult::pass(
                        "posture_hvci",
                        "Memory integrity (HVCI) is enforcing kernel code signing",
                    )
                } else if enabled {
                    DiagnosticResult::warn(
                        "posture_hvci",
                        "Code integrity is on but memory integrity (HVCI) is not",
                        "Kernel code signing is enforced by the kernel rather than by the \
                         hypervisor, so a kernel-mode attacker can disable it.",
                    )
                    .with_fix("Enable Memory integrity under Core isolation, then reboot")
                } else {
                    DiagnosticResult::warn(
                        "posture_hvci",
                        "Kernel code integrity is not enforced",
                        "Unsigned drivers can load, which is how a vulnerable-driver attack \
                         reaches kernel mode.",
                    )
                    .with_fix("Enable Memory integrity under Core isolation, then reboot")
                });
            }
            None => results.push(DiagnosticResult::warn(
                "posture_hvci",
                "Could not read the kernel code integrity state",
                "NtQuerySystemInformation(SystemCodeIntegrityInformation) failed.",
            )),
        }

        // Credential Guard: what keeps lsass secrets out of reach even when
        // the handle-access detection misses.
        let credential_guard = read_dword(
            w!(r"SYSTEM\CurrentControlSet\Control\LSA"),
            w!("LsaCfgFlags"),
        )
        .unwrap_or(0);

        results.push(if credential_guard > 0 {
            DiagnosticResult::pass("posture_credential_guard", "Credential Guard is configured")
        } else {
            DiagnosticResult::warn(
                "posture_credential_guard",
                "Credential Guard is not configured",
                "Domain credentials live in lsass memory where a process with the right \
                 handle can read them. Rustinel detects the handle open; Credential Guard \
                 makes the read worthless.",
            )
            .with_fix("Enable Credential Guard under Device Guard policy, then reboot")
        });

        // LSA protection: makes lsass a protected process, so the handle open
        // Rustinel watches for is refused by the kernel outright.
        let lsa_ppl =
            read_dword(w!(r"SYSTEM\CurrentControlSet\Control\LSA"), w!("RunAsPPL")).unwrap_or(0);

        results.push(if lsa_ppl > 0 {
            DiagnosticResult::pass(
                "posture_lsa_protection",
                "LSA protection is enabled; lsass runs as a protected process",
            )
        } else {
            DiagnosticResult::warn(
                "posture_lsa_protection",
                "LSA protection is not enabled",
                "lsass accepts memory-read handles from any administrator, so credential \
                 dumping succeeds and Rustinel can only report it after the fact.",
            )
            .with_fix(
                "Set RunAsPPL under HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA, then reboot",
            )
        });

        // Kernel DMA protection: the IOMMU standing between a malicious
        // peripheral and physical memory.
        let dma_guard = read_dword(
            w!(r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard"),
            w!("Enabled"),
        )
        .or_else(|| {
            read_dword(
                w!(r"SYSTEM\CurrentControlSet\Control\DmaSecurity"),
                w!("DeviceEnumerationPolicy"),
            )
        })
        .unwrap_or(0);

        results.push(if dma_guard > 0 {
            DiagnosticResult::pass(
                "posture_dma_protection",
                "Kernel DMA protection is configured",
            )
        } else {
            DiagnosticResult::warn(
                "posture_dma_protection",
                "Kernel DMA protection is not configured",
                "A peripheral on a directly-attached bus can read physical memory without \
                 involving the CPU, which no software agent can observe.",
            )
            .with_fix("Enable Kernel DMA Protection in firmware and under Device Guard policy")
        });

        results
    }
}

#[cfg(not(windows))]
mod platform {
    use super::DiagnosticResult;

    /// These protections are Windows-specific.
    ///
    /// The equivalents elsewhere (lockdown mode, IMA, SIP) are not read here
    /// rather than being reported as absent, which would be misleading.
    pub(super) fn posture_results() -> Vec<DiagnosticResult> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor::inspect::DiagnosticStatus;

    #[test]
    fn posture_checks_never_fail_the_report() {
        // A machine without these protections is not misconfigured for
        // Rustinel; it is a machine where a kernel-mode attacker wins. That is
        // a warning, and making it a failure would train operators to ignore
        // the exit code.
        for result in posture_results() {
            assert_ne!(
                result.status,
                DiagnosticStatus::Fail,
                "{} must not fail the report",
                result.id
            );
        }
    }

    #[test]
    #[cfg(windows)]
    fn every_windows_posture_check_is_reported() {
        let ids: Vec<String> = posture_results()
            .into_iter()
            .map(|result| result.id)
            .collect();

        for expected in [
            "posture_vbs",
            "posture_hvci",
            "posture_credential_guard",
            "posture_lsa_protection",
            "posture_dma_protection",
        ] {
            assert!(
                ids.iter().any(|id| id == expected),
                "{expected} is missing from the posture report"
            );
        }
    }

    #[test]
    #[cfg(windows)]
    fn a_warning_always_says_how_to_fix_it() {
        for result in posture_results() {
            if result.status == DiagnosticStatus::Warn && result.id != "posture_hvci" {
                assert!(
                    result.fix.is_some(),
                    "{} warns without saying what to do about it",
                    result.id
                );
            }
        }
    }
}
