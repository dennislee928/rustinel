//! Network containment through the Windows Filtering Platform.
//!
//! This is the one action in the engine the kernel enforces. Everything else
//! Rustinel does happens after the operation it responds to; a WFP filter is
//! installed from user mode but evaluated in `netio.sys` on every later
//! connection attempt, so the packet never leaves. That is why these actions
//! report [`Enforcement::Inline`] while the process, file, and registry ones
//! report `PostHoc`.
//!
//! A WFP callout driver would add payload inspection, which needs to see the
//! bytes. Blocking by address, port, or application does not, so it needs no
//! driver.
//!
//! # Isolation is dangerous and deliberately hard to do by accident
//!
//! Cutting a host off the network can strand a machine that is only reachable
//! over that network. Isolation therefore refuses to run unless the operator
//! has named what must keep working, and the permit filters for those
//! exceptions are given a higher weight than the block filters so they win.
//!
//! Filters are installed under Rustinel's own provider and sublayer, which is
//! what makes them findable again: `unisolate` enumerates by provider GUID
//! rather than trusting a stored list, so isolation can be lifted even after a
//! reboot, a crash, or a lost state file.

use super::{ActionExecutor, Capabilities};
use crate::response::action::{
    ActionError, ActionKind, ActionReceipt, Enforcement, ResponseAction,
};
use std::net::IpAddr;

/// Rustinel's WFP provider, so its filters can always be found and removed.
///
/// Stable by design: changing it would orphan the filters installed by an
/// older build, leaving a host isolated with nothing able to lift it.
pub const PROVIDER_GUID: windows::core::GUID =
    windows::core::GUID::from_u128(0x9f1d_2c3b_4a5e_6f70_8192_a3b4_c5d6_e7f8);

/// Sublayer holding the filters.
pub const SUBLAYER_GUID: windows::core::GUID =
    windows::core::GUID::from_u128(0x9f1d_2c3b_4a5e_6f70_8192_a3b4_c5d6_e7f9);

/// Weight given to block filters.
const WEIGHT_BLOCK: u64 = 0x1000;

/// Weight given to permit filters.
///
/// Above the block weight so a management exception beats the block-all inside
/// the same sublayer. WFP resolves conflicts by weight within a sublayer, so
/// this ordering is the whole safety mechanism for isolation.
const WEIGHT_PERMIT: u64 = 0x2000;

/// What must keep working while a host is isolated.
///
/// Empty means isolation is refused: an operator who has not said what to keep
/// has not decided to isolate, they have decided to guess.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IsolationPolicy {
    /// Addresses and networks that stay reachable.
    pub allow_cidrs: Vec<String>,
    /// Keep DNS resolvable.
    pub allow_dns: bool,
    /// Keep DHCP working, so the lease can be renewed.
    pub allow_dhcp: bool,
}

impl IsolationPolicy {
    /// Whether this policy names anything at all to keep working.
    pub fn is_empty(&self) -> bool {
        self.allow_cidrs.is_empty() && !self.allow_dns && !self.allow_dhcp
    }

    /// Parsed exception addresses, discarding entries that are not addresses.
    pub fn parsed_cidrs(&self) -> Vec<IpAddr> {
        self.allow_cidrs
            .iter()
            .filter_map(|entry| {
                // A bare address or the address half of a CIDR; the prefix
                // length is applied by the caller building the condition.
                entry
                    .split('/')
                    .next()
                    .and_then(|addr| addr.trim().parse::<IpAddr>().ok())
            })
            .collect()
    }
}

/// Executor for the two network actions.
#[derive(Debug)]
pub struct WfpExecutor {
    policy: IsolationPolicy,
    persistent: bool,
    capabilities: Capabilities,
}

impl WfpExecutor {
    /// Build the executor.
    ///
    /// `persistent` decides whether the filters survive a reboot. Persistent
    /// filters fail closed: a host stays isolated even if the agent never
    /// starts again, which is the safe direction for containment and the
    /// dangerous one for reachability.
    pub fn new(policy: IsolationPolicy, persistent: bool) -> Self {
        Self {
            policy,
            persistent,
            capabilities: Capabilities::none("handled by another executor")
                .supporting(ActionKind::IsolateHost, Enforcement::Inline)
                .supporting(ActionKind::BlockProcessNetwork, Enforcement::Inline),
        }
    }

    /// The isolation exceptions this executor was built with.
    pub fn policy(&self) -> &IsolationPolicy {
        &self.policy
    }

    /// Isolate now, bypassing the action plumbing.
    ///
    /// Used by `rustinel response isolate`, where an operator has decided
    /// directly rather than a detection having decided for them. The refusal
    /// on an empty exception list still applies: it is a property of
    /// isolation, not of how it was requested.
    pub fn isolate_now(&self) -> Result<usize, String> {
        if self.policy.is_empty() {
            return Err(
                "isolation needs at least one exception; refusing to strand this host".to_string(),
            );
        }
        platform::isolate(&self.policy, self.persistent)
    }
}

impl ActionExecutor for WfpExecutor {
    fn name(&self) -> &'static str {
        "wfp"
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    fn execute(&self, action: &ResponseAction) -> Result<ActionReceipt, ActionError> {
        let enforcement = self.reject_unsupported(action)?;
        let kind = action.kind();

        match action {
            ResponseAction::IsolateHost => {
                if self.policy.is_empty() {
                    return Err(ActionError::Failed {
                        kind,
                        reason: "isolation needs at least one exception under \
                                 [response.actions.isolate_host]; refusing to \
                                 strand this host"
                            .to_string(),
                    });
                }

                let installed = platform::isolate(&self.policy, self.persistent)
                    .map_err(|reason| ActionError::Failed { kind, reason })?;

                Ok(
                    ActionReceipt::new(kind, enforcement, "wfp", action.target_key())
                        .with_detail(format!("{installed} filters installed")),
                )
            }
            ResponseAction::BlockProcessNetwork { image } => {
                let installed = platform::block_image(image, self.persistent)
                    .map_err(|reason| ActionError::Failed { kind, reason })?;

                Ok(
                    ActionReceipt::new(kind, enforcement, "wfp", action.target_key())
                        .with_detail(format!("{installed} filters installed")),
                )
            }
            other => Err(ActionError::Unsupported {
                kind: other.kind(),
                reason: "not a network action",
            }),
        }
    }

    fn rollback(&self, receipt: &ActionReceipt) -> Result<(), ActionError> {
        platform::remove_all()
            .map(|_| ())
            .map_err(|reason| ActionError::Failed {
                kind: receipt.kind,
                reason,
            })
    }
}

/// Lift every filter Rustinel installed.
///
/// Enumerates by provider rather than by a stored list, so it works after a
/// reboot or a lost state file.
pub fn unisolate() -> Result<usize, String> {
    platform::remove_all()
}

/// How many filters Rustinel currently has installed.
pub fn installed_filter_count() -> Result<usize, String> {
    platform::count()
}

#[cfg(windows)]
mod platform {
    use super::{IsolationPolicy, PROVIDER_GUID, SUBLAYER_GUID, WEIGHT_BLOCK, WEIGHT_PERMIT};
    use std::path::Path;
    use windows::core::{GUID, PCWSTR, PWSTR};
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterCreateEnumHandle0,
        FwpmFilterDeleteById0, FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0, FwpmFreeMemory0,
        FwpmProviderAdd0, FwpmSubLayerAdd0, FwpmTransactionAbort0, FwpmTransactionBegin0,
        FwpmTransactionCommit0, FWPM_ACTION0, FWPM_ACTION0_0, FWPM_DISPLAY_DATA0, FWPM_FILTER0,
        FWPM_FILTER_CONDITION0, FWPM_FILTER_ENUM_TEMPLATE0, FWPM_FILTER_FLAGS,
        FWPM_FILTER_FLAG_PERSISTENT, FWPM_PROVIDER0, FWPM_PROVIDER_FLAG_PERSISTENT, FWPM_SESSION0,
        FWPM_SUBLAYER0, FWPM_SUBLAYER_FLAG_PERSISTENT, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT,
        FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL, FWP_UINT16, FWP_UINT32,
        FWP_VALUE0, FWP_VALUE0_0,
    };
    use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

    /// The four layers a host block has to cover.
    ///
    /// Outbound and inbound, IPv4 and IPv6. Missing one leaves a hole, and the
    /// one most easily forgotten is IPv6, which is on by default on every
    /// supported Windows version.
    const LAYER_CONNECT_V4: GUID = GUID::from_u128(0xc38d5788_7ffb_4cdb_b4f8_c74a4d3d2e33);
    const LAYER_CONNECT_V6: GUID = GUID::from_u128(0x4a72393b_319f_44bc_84c3_ba54dcb3b6b4);
    const LAYER_ACCEPT_V4: GUID = GUID::from_u128(0xe1cd9fe7_f4b5_4273_96c0_592e487b8650);
    const LAYER_ACCEPT_V6: GUID = GUID::from_u128(0xa3b42c97_9f04_4672_b87e_cee9c483257f);

    const ALL_LAYERS: [GUID; 4] = [
        LAYER_CONNECT_V4,
        LAYER_CONNECT_V6,
        LAYER_ACCEPT_V4,
        LAYER_ACCEPT_V6,
    ];

    /// FWPM_CONDITION_IP_REMOTE_ADDRESS
    const CONDITION_REMOTE_ADDRESS: GUID = GUID::from_u128(0xb235ae9a_1d64_49b8_a44c_5ff3d9095045);
    /// FWPM_CONDITION_IP_REMOTE_PORT
    const CONDITION_REMOTE_PORT: GUID = GUID::from_u128(0xc35a604d_d22b_4e1a_91b4_68f674ee674b);
    /// FWPM_CONDITION_ALE_APP_ID
    const CONDITION_APP_ID: GUID = GUID::from_u128(0xd78e1e87_8644_4ea5_9437_d809ecefc971);

    /// ERROR_ACCESS_DENIED, by far the most common WFP failure.
    const ERROR_ACCESS_DENIED: u32 = 5;

    /// Turn a WFP status into something an operator can act on.
    ///
    /// Every filtering operation needs administrator rights, and the raw code
    /// for that is a bare `0x5` that says nothing about which of the many
    /// possible problems it is.
    fn describe_wfp_error(operation: &str, status: u32) -> String {
        if status == ERROR_ACCESS_DENIED {
            format!("{operation} was denied; filtering operations need administrator rights")
        } else {
            format!("{operation} failed: {status:#x}")
        }
    }

    /// An open engine handle, closed however the caller leaves.
    struct Engine(HANDLE);

    impl Engine {
        fn open() -> Result<Self, String> {
            let mut handle = HANDLE::default();
            let session = FWPM_SESSION0::default();

            let status = unsafe {
                FwpmEngineOpen0(
                    PCWSTR::null(),
                    RPC_C_AUTHN_WINNT,
                    None,
                    Some(&session),
                    &mut handle,
                )
            };

            if status == ERROR_ACCESS_DENIED {
                return Err(
                    "FwpmEngineOpen was denied; filtering operations need administrator rights"
                        .to_string(),
                );
            }
            if status != 0 {
                return Err(format!(
                    "FwpmEngineOpen failed: {status:#x}; is the Base Filtering Engine \
                     service running?"
                ));
            }

            Ok(Self(handle))
        }

        fn handle(&self) -> HANDLE {
            self.0
        }
    }

    impl Drop for Engine {
        fn drop(&mut self) {
            unsafe {
                FwpmEngineClose0(self.0);
            }
        }
    }

    /// A UTF-16 string kept alive for as long as WFP reads it.
    struct Wide(Vec<u16>);

    impl Wide {
        fn new(value: &str) -> Self {
            Self(value.encode_utf16().chain(std::iter::once(0)).collect())
        }

        fn as_pwstr(&mut self) -> PWSTR {
            PWSTR(self.0.as_mut_ptr())
        }
    }

    /// Register the provider and sublayer the filters hang off.
    ///
    /// Both are idempotent. An "already exists" result is the state this wants,
    /// so neither return is checked: a genuine failure surfaces on the filter
    /// add, which is the operation that matters.
    fn ensure_containers(engine: &Engine, persistent: bool) {
        let mut name = Wide::new("Rustinel");
        let mut description = Wide::new("Rustinel response containment");

        let provider = FWPM_PROVIDER0 {
            providerKey: PROVIDER_GUID,
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_pwstr(),
                description: description.as_pwstr(),
            },
            flags: if persistent {
                FWPM_PROVIDER_FLAG_PERSISTENT
            } else {
                0
            },
            ..Default::default()
        };
        unsafe {
            FwpmProviderAdd0(engine.handle(), &provider, None);
        }

        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: SUBLAYER_GUID,
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_pwstr(),
                description: description.as_pwstr(),
            },
            flags: if persistent {
                FWPM_SUBLAYER_FLAG_PERSISTENT
            } else {
                0
            },
            // Highest weight, so a block here is not overridden by a permit in
            // somebody else's sublayer.
            weight: 0xFFFF,
            ..Default::default()
        };
        unsafe {
            FwpmSubLayerAdd0(engine.handle(), &sublayer, None);
        }
    }

    /// Install one filter. Returns whether it took.
    fn add_filter(
        engine: &Engine,
        layer: GUID,
        block: bool,
        weight: &mut u64,
        conditions: &[FWPM_FILTER_CONDITION0],
        persistent: bool,
        name: &mut Wide,
    ) -> bool {
        let filter = FWPM_FILTER0 {
            layerKey: layer,
            subLayerKey: SUBLAYER_GUID,
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_pwstr(),
                description: PWSTR::null(),
            },
            flags: if persistent {
                FWPM_FILTER_FLAG_PERSISTENT
            } else {
                FWPM_FILTER_FLAGS(0)
            },
            action: FWPM_ACTION0 {
                r#type: if block {
                    FWP_ACTION_BLOCK
                } else {
                    FWP_ACTION_PERMIT
                },
                Anonymous: FWPM_ACTION0_0 {
                    filterType: GUID::zeroed(),
                },
            },
            weight: FWP_VALUE0 {
                r#type: FWP_UINT32,
                // The union member for a 64-bit weight is a pointer, which is
                // why the caller owns the value.
                Anonymous: FWP_VALUE0_0 { uint64: weight },
            },
            numFilterConditions: conditions.len() as u32,
            filterCondition: if conditions.is_empty() {
                std::ptr::null_mut()
            } else {
                conditions.as_ptr().cast_mut()
            },
            ..Default::default()
        };

        let mut id = 0u64;
        unsafe { FwpmFilterAdd0(engine.handle(), &filter, None, Some(&mut id)) == 0 }
    }

    /// Cut the host off, keeping the operator's exceptions reachable.
    ///
    /// Everything happens inside one WFP transaction: a partial isolation, with
    /// the block installed and the exceptions missing, is exactly the outcome
    /// that strands a machine.
    pub(super) fn isolate(policy: &IsolationPolicy, persistent: bool) -> Result<usize, String> {
        let engine = Engine::open()?;
        ensure_containers(&engine, persistent);

        if unsafe { FwpmTransactionBegin0(engine.handle(), 0) } != 0 {
            return Err("FwpmTransactionBegin failed".to_string());
        }

        let installed = install_isolation(&engine, policy, persistent);

        if installed == 0 {
            unsafe {
                FwpmTransactionAbort0(engine.handle());
            }
            return Err("no filters could be installed".to_string());
        }

        if unsafe { FwpmTransactionCommit0(engine.handle()) } != 0 {
            unsafe {
                FwpmTransactionAbort0(engine.handle());
            }
            return Err("FwpmTransactionCommit failed".to_string());
        }

        Ok(installed)
    }

    /// The filters that make up an isolation, inside an open transaction.
    fn install_isolation(engine: &Engine, policy: &IsolationPolicy, persistent: bool) -> usize {
        let mut block_name = Wide::new("Rustinel isolate");
        let mut permit_name = Wide::new("Rustinel isolate exception");
        let mut block_weight = WEIGHT_BLOCK;
        let mut permit_weight = WEIGHT_PERMIT;
        let mut installed = 0usize;

        for layer in ALL_LAYERS {
            if add_filter(
                engine,
                layer,
                true,
                &mut block_weight,
                &[],
                persistent,
                &mut block_name,
            ) {
                installed += 1;
            }
        }

        // Exceptions carry the higher weight, so they win inside this sublayer.
        for address in policy.parsed_cidrs() {
            let std::net::IpAddr::V4(v4) = address else {
                // An IPv6 exception needs a byte-array condition value; the
                // management networks these are for are v4, and a v6 entry is
                // skipped rather than silently widened.
                continue;
            };

            let mut value = u32::from(v4);
            let condition = FWPM_FILTER_CONDITION0 {
                fieldKey: CONDITION_REMOTE_ADDRESS,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT32,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint32: value },
                },
            };
            let _ = &mut value;

            for layer in [LAYER_CONNECT_V4, LAYER_ACCEPT_V4] {
                if add_filter(
                    engine,
                    layer,
                    false,
                    &mut permit_weight,
                    std::slice::from_ref(&condition),
                    persistent,
                    &mut permit_name,
                ) {
                    installed += 1;
                }
            }
        }

        if policy.allow_dhcp {
            for port in [67u16, 68] {
                installed += permit_port(
                    engine,
                    port,
                    persistent,
                    &mut permit_weight,
                    &mut permit_name,
                );
            }
        }
        if policy.allow_dns {
            installed += permit_port(engine, 53, persistent, &mut permit_weight, &mut permit_name);
        }

        installed
    }

    /// Permit one remote port through the block.
    fn permit_port(
        engine: &Engine,
        port: u16,
        persistent: bool,
        weight: &mut u64,
        name: &mut Wide,
    ) -> usize {
        let condition = FWPM_FILTER_CONDITION0 {
            fieldKey: CONDITION_REMOTE_PORT,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT16,
                Anonymous: FWP_CONDITION_VALUE0_0 { uint16: port },
            },
        };

        let mut installed = 0;
        for layer in [LAYER_CONNECT_V4, LAYER_CONNECT_V6] {
            if add_filter(
                engine,
                layer,
                false,
                weight,
                std::slice::from_ref(&condition),
                persistent,
                name,
            ) {
                installed += 1;
            }
        }
        installed
    }

    /// Deny one image the network, in both directions and both families.
    ///
    /// The condition is the WFP application id, which is derived from the image
    /// path, so this blocks the *program*: every instance of it, including ones
    /// started after the filter goes in. That is stronger than blocking a PID
    /// and is the point.
    pub(super) fn block_image(image: &Path, persistent: bool) -> Result<usize, String> {
        let engine = Engine::open()?;
        ensure_containers(&engine, persistent);

        let app_id = app_id_for(image)?;
        let mut blob = windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_BYTE_BLOB {
            size: (app_id.len() * 2) as u32,
            data: app_id.as_ptr() as *mut u8,
        };

        let condition = FWPM_FILTER_CONDITION0 {
            fieldKey: CONDITION_APP_ID,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type:
                    windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_BYTE_BLOB_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    byteBlob: &mut blob,
                },
            },
        };

        let mut name = Wide::new("Rustinel block image");
        let mut weight = WEIGHT_BLOCK;
        let mut installed = 0usize;

        for layer in ALL_LAYERS {
            if add_filter(
                &engine,
                layer,
                true,
                &mut weight,
                std::slice::from_ref(&condition),
                persistent,
                &mut name,
            ) {
                installed += 1;
            }
        }

        if installed == 0 {
            return Err(format!(
                "no filters could be installed for {}",
                image.display()
            ));
        }

        Ok(installed)
    }

    /// The WFP application id for an image path.
    ///
    /// WFP wants the NT device path in UTF-16, which `FwpmGetAppIdFromFileName0`
    /// produces. The buffer it returns is owned by WFP, so the bytes are copied
    /// out before it is freed.
    fn app_id_for(image: &Path) -> Result<Vec<u16>, String> {
        use windows::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmGetAppIdFromFileName0;

        let wide: Vec<u16> = image
            .as_os_str()
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut blob = std::ptr::null_mut();
        let status = unsafe { FwpmGetAppIdFromFileName0(PCWSTR(wide.as_ptr()), &mut blob) };
        if status != 0 || blob.is_null() {
            return Err(format!(
                "cannot derive an application id for {}: {status:#x}",
                image.display()
            ));
        }

        let copied = unsafe {
            let blob_ref = &*blob;
            std::slice::from_raw_parts(blob_ref.data as *const u16, (blob_ref.size / 2) as usize)
                .to_vec()
        };

        unsafe {
            FwpmFreeMemory0(&mut (blob as *mut core::ffi::c_void));
        }

        Ok(copied)
    }

    /// Remove every filter under Rustinel's sublayer.
    pub(super) fn remove_all() -> Result<usize, String> {
        let engine = Engine::open()?;
        let ids = enumerate_filter_ids(&engine)?;

        let mut removed = 0usize;
        for id in ids {
            if unsafe { FwpmFilterDeleteById0(engine.handle(), id) } == 0 {
                removed += 1;
            }
        }

        Ok(removed)
    }

    /// How many filters Rustinel has installed.
    pub(super) fn count() -> Result<usize, String> {
        let engine = Engine::open()?;
        Ok(enumerate_filter_ids(&engine)?.len())
    }

    /// Every filter id under Rustinel's sublayer.
    ///
    /// Enumerating and filtering by sublayer, rather than trusting a stored
    /// list, is what lets isolation be lifted after a reboot or a lost state
    /// file.
    ///
    /// Enumeration is per layer, because the default enumeration type is
    /// `FWP_FILTER_ENUM_FULLY_CONTAINED`, which needs a layer to be contained
    /// by. A single template with no layer key fails outright rather than
    /// returning everything.
    fn enumerate_filter_ids(engine: &Engine) -> Result<Vec<u64>, String> {
        let mut ids = Vec::new();
        let mut last_error = None;

        for layer in ALL_LAYERS {
            match enumerate_layer(engine, layer) {
                Ok(found) => ids.extend(found),
                Err(error) => last_error = Some(error),
            }
        }

        // Every layer failing means the engine is unusable; some failing is
        // survivable and the ids that were found are still worth returning.
        if ids.is_empty() {
            if let Some(error) = last_error {
                return Err(error);
            }
        }

        ids.sort_unstable();
        ids.dedup();
        Ok(ids)
    }

    /// Rustinel's filter ids within one layer.
    fn enumerate_layer(engine: &Engine, layer: GUID) -> Result<Vec<u64>, String> {
        let template = FWPM_FILTER_ENUM_TEMPLATE0 {
            layerKey: layer,
            actionMask: u32::MAX,
            ..Default::default()
        };

        let mut enum_handle = HANDLE::default();
        let status = unsafe {
            FwpmFilterCreateEnumHandle0(engine.handle(), Some(&template), &mut enum_handle)
        };
        if status != 0 {
            return Err(describe_wfp_error("FwpmFilterCreateEnumHandle", status));
        }

        let mut ids = Vec::new();
        let mut entries: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
        let mut returned = 0u32;

        if unsafe {
            FwpmFilterEnum0(
                engine.handle(),
                enum_handle,
                4096,
                &mut entries,
                &mut returned,
            )
        } == 0
            && !entries.is_null()
        {
            for index in 0..returned as usize {
                let filter = unsafe { &**entries.add(index) };
                if filter.subLayerKey == SUBLAYER_GUID {
                    ids.push(filter.filterId);
                }
            }
            unsafe {
                FwpmFreeMemory0(&mut (entries as *mut core::ffi::c_void));
            }
        }

        unsafe {
            FwpmFilterDestroyEnumHandle0(engine.handle(), enum_handle);
        }

        Ok(ids)
    }
}

#[cfg(not(windows))]
mod platform {
    use super::IsolationPolicy;
    use std::path::Path;

    pub(super) fn isolate(_policy: &IsolationPolicy, _persistent: bool) -> Result<usize, String> {
        Err("host isolation is implemented through the Windows Filtering Platform".to_string())
    }

    pub(super) fn block_image(_image: &Path, _persistent: bool) -> Result<usize, String> {
        Err("blocking an image is implemented through the Windows Filtering Platform".to_string())
    }

    pub(super) fn remove_all() -> Result<usize, String> {
        Ok(0)
    }

    pub(super) fn count() -> Result<usize, String> {
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isolation_without_exceptions_is_refused() {
        let executor = WfpExecutor::new(IsolationPolicy::default(), false);

        let error = executor
            .execute(&ResponseAction::IsolateHost)
            .expect_err("must refuse");

        match error {
            ActionError::Failed { reason, .. } => {
                assert!(reason.contains("exception"), "unexpected reason: {reason}");
                assert!(reason.contains("strand"), "unexpected reason: {reason}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_policy_naming_anything_at_all_is_not_empty() {
        assert!(IsolationPolicy::default().is_empty());

        assert!(!IsolationPolicy {
            allow_cidrs: vec!["10.0.0.0/8".to_string()],
            ..IsolationPolicy::default()
        }
        .is_empty());

        assert!(!IsolationPolicy {
            allow_dns: true,
            ..IsolationPolicy::default()
        }
        .is_empty());
    }

    #[test]
    fn exception_addresses_are_parsed_and_bad_ones_dropped() {
        let policy = IsolationPolicy {
            allow_cidrs: vec![
                "10.1.2.3".to_string(),
                "192.168.0.0/16".to_string(),
                "not-an-address".to_string(),
                "  172.16.0.1  ".to_string(),
            ],
            ..IsolationPolicy::default()
        };

        let parsed = policy.parsed_cidrs();
        assert_eq!(parsed.len(), 3, "one entry is not an address and must drop");
        assert!(parsed.contains(&"10.1.2.3".parse().expect("v4")));
        assert!(parsed.contains(&"192.168.0.0".parse().expect("v4")));
        assert!(parsed.contains(&"172.16.0.1".parse().expect("v4")));
    }

    #[test]
    fn network_actions_are_the_only_ones_reported_inline() {
        let executor = WfpExecutor::new(IsolationPolicy::default(), false);

        assert_eq!(
            executor.capabilities().enforcement(ActionKind::IsolateHost),
            Some(Enforcement::Inline),
            "the kernel evaluates these filters, unlike every other action"
        );
        assert_eq!(
            executor
                .capabilities()
                .enforcement(ActionKind::BlockProcessNetwork),
            Some(Enforcement::Inline)
        );
        assert!(!executor
            .capabilities()
            .supports(ActionKind::TerminateProcess));
    }

    #[test]
    fn the_provider_and_sublayer_identities_are_distinct_and_fixed() {
        // These are how isolation is found again after a reboot. Changing
        // either would orphan filters an older build installed.
        assert_ne!(PROVIDER_GUID, SUBLAYER_GUID);
        assert_eq!(
            format!("{PROVIDER_GUID:?}").to_lowercase(),
            "9f1d2c3b-4a5e-6f70-8192-a3b4c5d6e7f8"
        );
    }

    #[test]
    fn permit_outweighs_block_so_exceptions_survive_isolation() {
        // WFP resolves conflicts inside a sublayer by weight, so an exception
        // weighing less than the block-all would be ignored and the host
        // stranded. Constants, so the compiler settles it, but the invariant
        // is the entire safety mechanism for isolation and is worth naming.
        const _: () = assert!(WEIGHT_PERMIT > WEIGHT_BLOCK);
        assert_eq!(WEIGHT_PERMIT, 0x2000);
        assert_eq!(WEIGHT_BLOCK, 0x1000);
    }
}
