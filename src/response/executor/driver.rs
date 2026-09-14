//! Kernel-mode executor.
//!
//! Everything else in this module tree acts after the operation it responds to.
//! This is the seam for acting *instead of* it, which on Windows means a kernel
//! driver, because the four APIs that can refuse an operation while it is
//! happening are all kernel-mode callbacks:
//!
//! | Kernel API | What it denies | Reached through |
//! | --- | --- | --- |
//! | `ObRegisterCallbacks` pre-operation | Strips `PROCESS_VM_READ`/`VM_WRITE`/`CREATE_THREAD` on a handle open, so the dump or the injection never starts | [`KernelDriverExecutor::set_policy`] |
//! | `CmRegisterCallbackEx` pre-operation | Fails the `RegSetValue`, so the Run key is never written | [`KernelDriverExecutor::set_policy`] |
//! | Minifilter pre-operation | Completes the IRP with `STATUS_ACCESS_DENIED`, so the write never lands | [`KernelDriverExecutor::set_policy`] |
//! | `FwpsCalloutRegister` | Drops a packet after inspecting its payload | Not implemented, and not planned |
//!
//! The last row is deliberate. WFP *filters*, which block by address, port, and
//! application, are installed from user mode by [`super::wfp`] and are already
//! enforced by the kernel; a callout only adds payload inspection, which
//! Rustinel does not do.
//!
//! Separately from the policy, the driver exposes a kernel-mode terminate. It
//! is not faster than the user-mode one and it is still post-hoc, but it
//! reaches targets a user-mode kill cannot: a protected-process-light process
//! refuses the agent a handle carrying `PROCESS_TERMINATE` however privileged
//! the agent is, and the kernel is not asking for a handle.
//!
//! # The ABI is the dangerous part
//!
//! The driver source is in `driver/` and its interface is
//! `driver/include/rustinel_ioctl.h`. The structures in [`abi`] mirror that
//! header and the two must agree exactly: a struct that disagrees across this
//! boundary is kernel memory corruption, not a parse error. The driver checks
//! `Version` and every count before it copies, and the tests at the bottom of
//! this file pin the sizes, offsets, and control codes so a change to either
//! side fails here rather than on a machine.
//!
//! # What this does when no driver is loaded
//!
//! Reports every action unsupported, which is what makes the rest of the engine
//! fall through to the user-mode executors. Nothing here fails loudly on a
//! machine without the driver, because that is the normal case: the driver is
//! optional and most deployments will not have one.
//!
//! # Why most deployments will not have one
//!
//! A driver loads on 64-bit Windows only with a signature chaining to a
//! Microsoft cross-signing certificate, obtained through attestation signing or
//! WHQL with an EV certificate. `ObRegisterCallbacks` additionally refuses to
//! register for an image not linked with `/INTEGRITYCHECK`. Neither is a coding
//! problem, which is why the seam exists and the driver does not ship.

use super::{ActionExecutor, Capabilities};
use crate::response::action::{
    ActionError, ActionKind, ActionReceipt, Enforcement, ResponseAction,
};

/// Reason reported for every action while no driver is present.
const NO_DRIVER: &str = "kernel driver is not installed";

/// Device the driver exposes, mirroring `RUSTINEL_USER_PATH`.
pub const DEVICE_PATH: &str = r"\\.\Rustinel";

/// Policy structure version, mirroring `RUSTINEL_POLICY_VERSION`.
pub const POLICY_VERSION: u32 = 1;

/// What the driver should do when a rule matches.
///
/// Mirrors `RUSTINEL_DISPOSITION`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Report only; the operation proceeds untouched.
    Audit = 0,
    /// Remove the dangerous rights and let the open succeed.
    ///
    /// Preferred over outright denial for process handles: a caller refused
    /// entirely knows it was blocked, whereas one handed a handle without
    /// `PROCESS_VM_READ` sees something indistinguishable from an ordinary
    /// permissions problem.
    Strip = 1,
    /// Fail the operation.
    Deny = 2,
}

/// The wire format shared with `driver/include/rustinel_ioctl.h`.
///
/// Every item here is laid out by the C compiler's rules and must not be
/// reordered, resized, or given a different representation. See the module
/// note on why this matters more than usual.
pub mod abi {
    /// `RUSTINEL_TYPE`.
    pub const DEVICE_TYPE: u32 = 40000;

    /// `METHOD_BUFFERED`: the I/O manager copies the buffer for us.
    const METHOD_BUFFERED: u32 = 0;
    /// `FILE_READ_ACCESS`.
    const FILE_READ_ACCESS: u32 = 1;
    /// `FILE_WRITE_ACCESS`.
    const FILE_WRITE_ACCESS: u32 = 2;

    /// The `CTL_CODE` macro from `devioctl.h`, which has no Rust equivalent.
    pub const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
        (device_type << 16) | (access << 14) | (function << 2) | method
    }

    /// `IOCTL_RUSTINEL_SET_POLICY`: replace the whole policy table.
    pub const IOCTL_SET_POLICY: u32 =
        ctl_code(DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_WRITE_ACCESS);
    /// `IOCTL_RUSTINEL_CLEAR_POLICY`: drop the policy, denying nothing.
    pub const IOCTL_CLEAR_POLICY: u32 =
        ctl_code(DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_WRITE_ACCESS);
    /// `IOCTL_RUSTINEL_QUERY_STATE`: which callbacks registered, and counters.
    pub const IOCTL_QUERY_STATE: u32 =
        ctl_code(DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS);
    /// `IOCTL_RUSTINEL_PROTECT_PROCESS`: terminate from kernel mode.
    ///
    /// Named for the structure it carries rather than for what it does; the
    /// driver dispatches it to `RustinelTerminateProcess`.
    pub const IOCTL_PROTECT_PROCESS: u32 =
        ctl_code(DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_WRITE_ACCESS);

    /// `RUSTINEL_MAX_PROTECTED_PROCESSES`.
    pub const MAX_PROTECTED_PROCESSES: usize = 64;
    /// `RUSTINEL_MAX_PROTECTED_KEYS`.
    pub const MAX_PROTECTED_KEYS: usize = 64;
    /// `RUSTINEL_MAX_BLOCKED_IMAGES`.
    pub const MAX_BLOCKED_IMAGES: usize = 256;
    /// `RUSTINEL_MAX_PATH_CCH`, in UTF-16 code units including the terminator.
    pub const MAX_PATH_CCH: usize = 260;

    /// `RUSTINEL_PROTECTED_PROCESS`.
    #[repr(C)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ProtectedProcess {
        /// Target PID.
        pub process_id: u32,
        /// Process start key, so a recycled PID is not policed by mistake.
        pub start_key: u64,
        /// Rights to remove or refuse.
        pub denied_access: u32,
        /// A [`super::Disposition`] value.
        pub disposition: u32,
    }

    /// `RUSTINEL_PROTECTED_KEY`.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct ProtectedKey {
        /// `\REGISTRY\MACHINE\...` prefix, UTF-16, not necessarily terminated.
        pub prefix: [u16; MAX_PATH_CCH],
        /// Length of `prefix` in code units.
        pub prefix_cch: u32,
        /// A [`super::Disposition`] value.
        pub disposition: u32,
    }

    /// `RUSTINEL_BLOCKED_IMAGE`.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct BlockedImage {
        /// Image path, UTF-16, not necessarily terminated.
        pub path: [u16; MAX_PATH_CCH],
        /// Length of `path` in code units.
        pub path_cch: u32,
        /// A [`super::Disposition`] value.
        pub disposition: u32,
    }

    /// `RUSTINEL_POLICY`, sent as one buffer and swapped atomically.
    ///
    /// Around 166 KiB, which is why every constructor here boxes it: this is
    /// several times the default thread stack budget worth of one value.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Policy {
        /// Must equal [`super::POLICY_VERSION`] or the driver refuses it.
        pub version: u32,
        /// Entries of `processes` that are in use.
        pub process_count: u32,
        /// Entries of `keys` that are in use.
        pub key_count: u32,
        /// Entries of `images` that are in use.
        pub image_count: u32,
        /// The agent's own PID, which the driver never polices or blocks.
        pub agent_process_id: u32,
        /// Processes whose handle opens are policed.
        pub processes: [ProtectedProcess; MAX_PROTECTED_PROCESSES],
        /// Registry subtrees that may not be written.
        pub keys: [ProtectedKey; MAX_PROTECTED_KEYS],
        /// Images that may not be created, opened for write, or executed.
        pub images: [BlockedImage; MAX_BLOCKED_IMAGES],
    }

    /// `RUSTINEL_STATE`.
    #[repr(C)]
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct State {
        /// Policy version the driver speaks.
        pub version: u32,
        /// `BOOLEAN`: whether `ObRegisterCallbacks` registered.
        pub object_callbacks_active: u8,
        /// `BOOLEAN`: whether `CmRegisterCallbackEx` registered.
        pub registry_callback_active: u8,
        /// `BOOLEAN`: whether the minifilter registered.
        pub minifilter_active: u8,
        /// Handle opens stripped of rights since load.
        pub handles_stripped: u64,
        /// Handle opens refused since load.
        pub handles_denied: u64,
        /// Registry writes refused since load.
        pub registry_writes_denied: u64,
        /// File operations refused since load.
        pub file_operations_denied: u64,
    }

    impl Policy {
        /// An empty policy that denies nothing, naming the agent.
        pub fn new(agent_process_id: u32) -> Box<Self> {
            Box::new(Self {
                version: super::POLICY_VERSION,
                process_count: 0,
                key_count: 0,
                image_count: 0,
                agent_process_id,
                processes: [ProtectedProcess {
                    process_id: 0,
                    start_key: 0,
                    denied_access: 0,
                    disposition: 0,
                }; MAX_PROTECTED_PROCESSES],
                keys: [ProtectedKey {
                    prefix: [0; MAX_PATH_CCH],
                    prefix_cch: 0,
                    disposition: 0,
                }; MAX_PROTECTED_KEYS],
                images: [BlockedImage {
                    path: [0; MAX_PATH_CCH],
                    path_cch: 0,
                    disposition: 0,
                }; MAX_BLOCKED_IMAGES],
            })
        }

        /// Police handle opens against one process.
        ///
        /// Returns whether it fit; the table is fixed-size and the driver
        /// rejects a count over the maximum outright, so an overflow is
        /// reported rather than silently dropped.
        pub fn protect_process(
            &mut self,
            process_id: u32,
            start_key: u64,
            denied_access: u32,
            disposition: super::Disposition,
        ) -> bool {
            let index = self.process_count as usize;
            if index >= MAX_PROTECTED_PROCESSES {
                return false;
            }
            self.processes[index] = ProtectedProcess {
                process_id,
                start_key,
                denied_access,
                disposition: disposition as u32,
            };
            self.process_count += 1;
            true
        }

        /// Refuse writes under a registry subtree.
        ///
        /// `prefix` is compared case-insensitively by the driver against the
        /// kernel's own `\REGISTRY\MACHINE\...` spelling, which is not the
        /// `HKEY_LOCAL_MACHINE\...` form a user-mode API would hand back.
        pub fn protect_key(&mut self, prefix: &str, disposition: super::Disposition) -> bool {
            let index = self.key_count as usize;
            if index >= MAX_PROTECTED_KEYS {
                return false;
            }
            let Some(encoded) = encode_fixed(prefix) else {
                return false;
            };
            self.keys[index] = ProtectedKey {
                prefix: encoded.0,
                prefix_cch: encoded.1,
                disposition: disposition as u32,
            };
            self.key_count += 1;
            true
        }

        /// Refuse create, write, and execute against one image path.
        pub fn block_image(&mut self, path: &str, disposition: super::Disposition) -> bool {
            let index = self.image_count as usize;
            if index >= MAX_BLOCKED_IMAGES {
                return false;
            }
            let Some(encoded) = encode_fixed(path) else {
                return false;
            };
            self.images[index] = BlockedImage {
                path: encoded.0,
                path_cch: encoded.1,
                disposition: disposition as u32,
            };
            self.image_count += 1;
            true
        }
    }

    /// UTF-16-encode into the fixed buffer, leaving room for a terminator.
    ///
    /// Refuses rather than truncates. A silently shortened registry prefix
    /// matches a *wider* subtree than the caller asked to protect, and a
    /// shortened image path matches the wrong file.
    fn encode_fixed(value: &str) -> Option<([u16; MAX_PATH_CCH], u32)> {
        let units: Vec<u16> = value.encode_utf16().collect();
        if units.is_empty() || units.len() >= MAX_PATH_CCH {
            return None;
        }
        let mut buffer = [0u16; MAX_PATH_CCH];
        buffer[..units.len()].copy_from_slice(&units);
        Some((buffer, units.len() as u32))
    }
}

/// What the driver reports about itself.
///
/// A driver can load with some callbacks registered and others not:
/// `ObRegisterCallbacks` refuses an image that was not linked
/// `/INTEGRITYCHECK`, while the minifilter does not care. Reporting the three
/// separately is what lets `rustinel doctor` say which half is missing rather
/// than "the driver is present".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriverState {
    /// Policy version the driver speaks.
    pub version: u32,
    /// Whether handle opens are being policed.
    pub object_callbacks_active: bool,
    /// Whether registry writes are being policed.
    pub registry_callback_active: bool,
    /// Whether file operations are being policed.
    pub minifilter_active: bool,
    /// Handle opens stripped of rights since load.
    pub handles_stripped: u64,
    /// Handle opens refused since load.
    pub handles_denied: u64,
    /// Registry writes refused since load.
    pub registry_writes_denied: u64,
    /// File operations refused since load.
    pub file_operations_denied: u64,
}

impl From<abi::State> for DriverState {
    fn from(state: abi::State) -> Self {
        Self {
            version: state.version,
            object_callbacks_active: state.object_callbacks_active != 0,
            registry_callback_active: state.registry_callback_active != 0,
            minifilter_active: state.minifilter_active != 0,
            handles_stripped: state.handles_stripped,
            handles_denied: state.handles_denied,
            registry_writes_denied: state.registry_writes_denied,
            file_operations_denied: state.file_operations_denied,
        }
    }
}

/// Executor that delegates to the Rustinel kernel driver.
#[derive(Debug)]
pub struct KernelDriverExecutor {
    capabilities: Capabilities,
    device_present: bool,
}

impl Default for KernelDriverExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl KernelDriverExecutor {
    /// Build the executor, probing for the driver.
    ///
    /// The probe is a device open, which is the only reliable answer: a service
    /// entry can exist for a driver that failed to register its callbacks, and
    /// a driver that registered nothing should not be treated as present.
    pub fn new() -> Self {
        let device_present = platform::device_present();

        // Only what the driver actually serves. Claiming a kind here routes it
        // away from the user-mode executors, so an over-claim strands the
        // action rather than improving it.
        //
        // The terminate is reported `PostHoc` on purpose. It reaches further
        // than a user-mode kill, but it is still a kill: the process has
        // already run. The inline half of this driver is the policy, which is
        // a standing configuration rather than an action.
        let capabilities = if device_present {
            Capabilities::none("handled by another executor")
                .supporting(ActionKind::TerminateProcess, Enforcement::PostHoc)
        } else {
            Capabilities::none(NO_DRIVER)
        };

        Self {
            capabilities,
            device_present,
        }
    }

    /// Whether a Rustinel kernel driver is loaded.
    pub fn driver_present(&self) -> bool {
        self.device_present
    }

    /// Replace the driver's policy table.
    ///
    /// The whole table goes down at once because the driver swaps a pointer
    /// under a lock: a callback firing during the update sees either all of the
    /// old policy or all of the new one, never a mixture.
    pub fn set_policy(&self, policy: &abi::Policy) -> Result<(), String> {
        if !self.device_present {
            return Err(NO_DRIVER.to_string());
        }
        platform::set_policy(policy)
    }

    /// Drop the driver's policy, so it denies nothing.
    pub fn clear_policy(&self) -> Result<(), String> {
        if !self.device_present {
            return Err(NO_DRIVER.to_string());
        }
        platform::clear_policy()
    }

    /// Ask the driver which callbacks registered, and for its counters.
    pub fn query_state(&self) -> Result<DriverState, String> {
        if !self.device_present {
            return Err(NO_DRIVER.to_string());
        }
        platform::query_state().map(DriverState::from)
    }

    /// Protect the agent itself, and nothing else.
    ///
    /// The first thing worth denying is a handle to Rustinel carrying the
    /// rights to read its memory, write it, or start a thread in it, and a
    /// write to the registry key that decides whether it starts at all. Both
    /// are things an attacker does *before* the rest of the policy matters, and
    /// neither needs an operator to have configured anything.
    ///
    /// `Strip` rather than `Deny` for the handle: a caller refused outright
    /// learns it was blocked, while one handed a handle without `VM_READ` sees
    /// something it cannot tell from an ordinary permissions failure.
    pub fn protect_self(&self) -> Result<(), String> {
        if !self.device_present {
            return Err(NO_DRIVER.to_string());
        }

        let pid = std::process::id();
        let mut policy = abi::Policy::new(pid);

        // PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION
        // | PROCESS_CREATE_THREAD | PROCESS_TERMINATE | PROCESS_DUP_HANDLE
        const DENIED: u32 = 0x0010 | 0x0020 | 0x0008 | 0x0002 | 0x0001 | 0x0040;
        policy.protect_process(pid, 0, DENIED, Disposition::Strip);

        // The kernel spells it this way; `HKEY_LOCAL_MACHINE\...` would never
        // match.
        policy.protect_key(
            r"\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Services\Rustinel",
            Disposition::Deny,
        );

        self.set_policy(&policy)
    }
}

impl ActionExecutor for KernelDriverExecutor {
    fn name(&self) -> &'static str {
        "kernel_driver"
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    fn execute(&self, action: &ResponseAction) -> Result<ActionReceipt, ActionError> {
        let enforcement = self.reject_unsupported(action)?;
        let kind = action.kind();

        match action {
            ResponseAction::TerminateProcess { target } => {
                // The start key is what stops a recycled PID being killed in
                // place of the target. `ProcessIdentity` carries the start time
                // rather than the kernel's start key, so zero is sent when it
                // is unknown and the driver falls back to the PID alone; the
                // caller has already revalidated identity immediately before
                // this point.
                platform::terminate_process(target.pid, 0)
                    .map_err(|reason| ActionError::Failed { kind, reason })?;

                Ok(
                    ActionReceipt::new(kind, enforcement, "kernel_driver", action.target_key())
                        .with_detail(format!("terminated pid {} from kernel mode", target.pid)),
                )
            }
            other => Err(ActionError::Unsupported {
                kind: other.kind(),
                reason: "not served by the kernel driver",
            }),
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::{abi, DEVICE_PATH};
    use windows::core::HSTRING;
    use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::IO::DeviceIoControl;

    /// An open handle to the driver's control device.
    struct Device(HANDLE);

    impl Drop for Device {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    impl Device {
        /// Open the control device for the access an IOCTL needs.
        fn open(write: bool) -> Result<Self, String> {
            let access = if write {
                GENERIC_READ.0 | GENERIC_WRITE.0
            } else {
                GENERIC_READ.0
            };

            let handle = unsafe {
                CreateFileW(
                    &HSTRING::from(DEVICE_PATH),
                    access,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    None,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    None,
                )
            }
            .map_err(|err| format!("cannot open {DEVICE_PATH}: {err}"))?;

            Ok(Self(handle))
        }
    }

    /// Whether the driver's control device can be opened.
    pub(super) fn device_present() -> bool {
        Device::open(false).is_ok()
    }

    /// Issue one buffered control code.
    ///
    /// `input` and `output` are raw byte views of the mirrored structures; the
    /// I/O manager copies both, so neither has to outlive the call.
    fn control(
        device: &Device,
        code: u32,
        input: Option<&[u8]>,
        output: Option<&mut [u8]>,
    ) -> Result<u32, String> {
        let (in_ptr, in_len) = match input {
            Some(bytes) => (
                bytes.as_ptr() as *const core::ffi::c_void,
                bytes.len() as u32,
            ),
            None => (std::ptr::null(), 0),
        };
        let (out_ptr, out_len) = match output {
            Some(bytes) => (
                bytes.as_mut_ptr() as *mut core::ffi::c_void,
                bytes.len() as u32,
            ),
            None => (std::ptr::null_mut(), 0),
        };

        let mut returned = 0u32;
        unsafe {
            DeviceIoControl(
                device.0,
                code,
                if in_len == 0 { None } else { Some(in_ptr) },
                in_len,
                if out_len == 0 { None } else { Some(out_ptr) },
                out_len,
                Some(&mut returned),
                None,
            )
        }
        .map_err(|err| format!("DeviceIoControl({code:#x}) failed: {err}"))?;

        Ok(returned)
    }

    /// Byte view of a mirrored structure.
    ///
    /// # Safety
    ///
    /// `T` must be `repr(C)` and hold no padding the driver would read as
    /// meaningful. Every structure in [`abi`] satisfies that, and the driver
    /// validates lengths and counts before it copies.
    unsafe fn as_bytes<T>(value: &T) -> &[u8] {
        core::slice::from_raw_parts(value as *const T as *const u8, size_of::<T>())
    }

    pub(super) fn set_policy(policy: &abi::Policy) -> Result<(), String> {
        let device = Device::open(true)?;
        let bytes = unsafe { as_bytes(policy) };
        control(&device, abi::IOCTL_SET_POLICY, Some(bytes), None).map(|_| ())
    }

    pub(super) fn clear_policy() -> Result<(), String> {
        let device = Device::open(true)?;
        control(&device, abi::IOCTL_CLEAR_POLICY, None, None).map(|_| ())
    }

    pub(super) fn query_state() -> Result<abi::State, String> {
        let device = Device::open(false)?;
        let mut state = abi::State::default();
        let mut buffer = [0u8; size_of::<abi::State>()];

        let returned = control(&device, abi::IOCTL_QUERY_STATE, None, Some(&mut buffer))?;
        if (returned as usize) < size_of::<abi::State>() {
            return Err(format!(
                "driver returned {returned} bytes of state, expected {}",
                size_of::<abi::State>()
            ));
        }

        // SAFETY: `State` is `repr(C)` and plain data, and the buffer is
        // exactly its size and fully written, as the length check above
        // established.
        unsafe {
            std::ptr::copy_nonoverlapping(
                buffer.as_ptr(),
                &mut state as *mut abi::State as *mut u8,
                size_of::<abi::State>(),
            );
        }
        Ok(state)
    }

    pub(super) fn terminate_process(pid: u32, start_key: u64) -> Result<(), String> {
        let device = Device::open(true)?;
        let target = abi::ProtectedProcess {
            process_id: pid,
            start_key,
            denied_access: 0,
            disposition: 0,
        };
        let bytes = unsafe { as_bytes(&target) };
        control(&device, abi::IOCTL_PROTECT_PROCESS, Some(bytes), None).map(|_| ())
    }
}

#[cfg(not(windows))]
mod platform {
    use super::abi;

    /// The driver is Windows-only.
    pub(super) fn device_present() -> bool {
        false
    }

    pub(super) fn set_policy(_policy: &abi::Policy) -> Result<(), String> {
        Err("the kernel driver is Windows-only".to_string())
    }

    pub(super) fn clear_policy() -> Result<(), String> {
        Err("the kernel driver is Windows-only".to_string())
    }

    pub(super) fn query_state() -> Result<abi::State, String> {
        Err("the kernel driver is Windows-only".to_string())
    }

    pub(super) fn terminate_process(_pid: u32, _start_key: u64) -> Result<(), String> {
        Err("the kernel driver is Windows-only".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::ProcessIdentity;

    #[test]
    fn without_a_driver_every_action_is_unsupported() {
        let executor = KernelDriverExecutor::new();

        // No driver ships, so this is the state on every machine that runs
        // the test suite.
        assert!(!executor.driver_present());
        assert!(executor.capabilities().supported_kinds().is_empty());

        let action = ResponseAction::TerminateProcess {
            target: ProcessIdentity {
                pid: 4242,
                image: "C:\\tmp\\target.exe".to_string(),
                start_time: None,
                command_line_hash: None,
            },
        };

        assert_eq!(
            executor.execute(&action),
            Err(ActionError::Unsupported {
                kind: ActionKind::TerminateProcess,
                reason: NO_DRIVER,
            })
        );
    }

    #[test]
    fn the_policy_interface_refuses_rather_than_pretending_without_a_driver() {
        let executor = KernelDriverExecutor::new();

        assert_eq!(executor.clear_policy(), Err(NO_DRIVER.to_string()));
        assert_eq!(executor.protect_self(), Err(NO_DRIVER.to_string()));
        assert!(executor.query_state().is_err());
    }

    #[test]
    fn the_device_path_matches_the_driver_header() {
        // `RUSTINEL_USER_PATH` in driver/include/rustinel_ioctl.h. A mismatch
        // means the agent probes a device the driver never created, and the
        // driver silently never gets used.
        assert_eq!(DEVICE_PATH, r"\\.\Rustinel");
    }

    #[test]
    fn dispositions_match_the_driver_enum() {
        // These are sent as integers over the IOCTL boundary, so the values
        // matter more than the names.
        assert_eq!(Disposition::Audit as u32, 0);
        assert_eq!(Disposition::Strip as u32, 1);
        assert_eq!(Disposition::Deny as u32, 2);
    }

    /// The control codes the driver's `switch` compares against.
    ///
    /// Recomputed here from the same `CTL_CODE` arithmetic the header uses. A
    /// wrong code is not a failure the driver can report: it falls through to
    /// `STATUS_INVALID_DEVICE_REQUEST` and the agent sees a generic error.
    #[test]
    fn control_codes_match_the_driver_header() {
        assert_eq!(abi::DEVICE_TYPE, 40000);
        assert_eq!(
            abi::IOCTL_SET_POLICY,
            (40000 << 16) | (2 << 14) | (0x800 << 2)
        );
        assert_eq!(
            abi::IOCTL_CLEAR_POLICY,
            (40000 << 16) | (2 << 14) | (0x801 << 2)
        );
        assert_eq!(
            abi::IOCTL_QUERY_STATE,
            (40000 << 16) | (1 << 14) | (0x802 << 2)
        );
        assert_eq!(
            abi::IOCTL_PROTECT_PROCESS,
            (40000 << 16) | (2 << 14) | (0x803 << 2)
        );
    }

    /// Sizes and offsets of every structure crossing the boundary.
    ///
    /// These are the numbers a C compiler produces for
    /// `driver/include/rustinel_ioctl.h` on x64. The driver copies
    /// `sizeof(RUSTINEL_POLICY)` bytes out of the buffer the agent sent, so a
    /// disagreement here is kernel memory corruption rather than a bad parse.
    #[test]
    fn the_abi_matches_the_driver_header() {
        use std::mem::{align_of, offset_of, size_of};

        // RUSTINEL_PROTECTED_PROCESS: ULONG, ULONG64, ACCESS_MASK, ULONG.
        assert_eq!(size_of::<abi::ProtectedProcess>(), 24);
        assert_eq!(align_of::<abi::ProtectedProcess>(), 8);
        assert_eq!(offset_of!(abi::ProtectedProcess, process_id), 0);
        assert_eq!(offset_of!(abi::ProtectedProcess, start_key), 8);
        assert_eq!(offset_of!(abi::ProtectedProcess, denied_access), 16);
        assert_eq!(offset_of!(abi::ProtectedProcess, disposition), 20);

        // WCHAR[260] is 520 bytes, then two ULONGs.
        assert_eq!(size_of::<abi::ProtectedKey>(), 528);
        assert_eq!(offset_of!(abi::ProtectedKey, prefix_cch), 520);
        assert_eq!(offset_of!(abi::ProtectedKey, disposition), 524);
        assert_eq!(size_of::<abi::BlockedImage>(), 528);
        assert_eq!(offset_of!(abi::BlockedImage, path_cch), 520);

        // Five ULONGs, then an 8-aligned array: the compiler pads to 24.
        assert_eq!(offset_of!(abi::Policy, processes), 24);
        assert_eq!(offset_of!(abi::Policy, keys), 24 + 64 * 24);
        assert_eq!(offset_of!(abi::Policy, images), 24 + 64 * 24 + 64 * 528);
        assert_eq!(
            size_of::<abi::Policy>(),
            24 + 64 * 24 + 64 * 528 + 256 * 528
        );

        // RUSTINEL_STATE: ULONG, three BOOLEAN, then ULONG64s from offset 8.
        assert_eq!(size_of::<abi::State>(), 40);
        assert_eq!(offset_of!(abi::State, object_callbacks_active), 4);
        assert_eq!(offset_of!(abi::State, handles_stripped), 8);
        assert_eq!(offset_of!(abi::State, file_operations_denied), 32);
    }

    #[test]
    fn a_fresh_policy_denies_nothing_and_names_the_agent() {
        let policy = abi::Policy::new(1234);

        assert_eq!(policy.version, POLICY_VERSION);
        assert_eq!(policy.agent_process_id, 1234);
        assert_eq!(policy.process_count, 0);
        assert_eq!(policy.key_count, 0);
        assert_eq!(policy.image_count, 0);
    }

    #[test]
    fn policy_entries_are_encoded_where_the_driver_looks_for_them() {
        let mut policy = abi::Policy::new(1);

        assert!(policy.protect_process(99, 0xdead_beef, 0x0010, Disposition::Strip));
        assert_eq!(policy.process_count, 1);
        assert_eq!(policy.processes[0].process_id, 99);
        assert_eq!(policy.processes[0].start_key, 0xdead_beef);
        assert_eq!(policy.processes[0].disposition, Disposition::Strip as u32);

        assert!(policy.protect_key(r"\REGISTRY\MACHINE\SOFTWARE\Rustinel", Disposition::Deny));
        assert_eq!(policy.key_count, 1);
        let key = &policy.keys[0];
        let prefix = String::from_utf16_lossy(&key.prefix[..key.prefix_cch as usize]);
        assert_eq!(prefix, r"\REGISTRY\MACHINE\SOFTWARE\Rustinel");
        // The driver writes a terminator at `prefix_cch`, so that slot must be
        // inside the buffer.
        assert!((key.prefix_cch as usize) < abi::MAX_PATH_CCH);
    }

    /// A prefix that does not fit is refused, never truncated.
    ///
    /// Truncation would silently widen the protected subtree: half of
    /// `...\Services\Rustinel` is `...\Services`, which is every service on
    /// the machine.
    #[test]
    fn an_oversized_entry_is_refused_rather_than_truncated() {
        let mut policy = abi::Policy::new(1);
        let too_long = "A".repeat(abi::MAX_PATH_CCH);

        assert!(!policy.protect_key(&too_long, Disposition::Deny));
        assert_eq!(policy.key_count, 0);
        assert!(!policy.block_image(&too_long, Disposition::Deny));
        assert_eq!(policy.image_count, 0);
    }

    #[test]
    fn the_fixed_tables_refuse_to_overflow() {
        let mut policy = abi::Policy::new(1);

        for index in 0..abi::MAX_PROTECTED_PROCESSES {
            assert!(policy.protect_process(index as u32 + 1, 0, 0, Disposition::Audit));
        }
        // The driver rejects a count over the maximum outright, so the caller
        // has to learn about the overflow here.
        assert!(!policy.protect_process(9999, 0, 0, Disposition::Audit));
        assert_eq!(policy.process_count as usize, abi::MAX_PROTECTED_PROCESSES);
    }

    #[test]
    fn driver_state_reads_the_c_booleans() {
        let state = abi::State {
            version: POLICY_VERSION,
            object_callbacks_active: 1,
            registry_callback_active: 0,
            minifilter_active: 1,
            handles_stripped: 7,
            handles_denied: 3,
            registry_writes_denied: 1,
            file_operations_denied: 9,
        };

        let reported = DriverState::from(state);
        assert!(reported.object_callbacks_active);
        // A driver can load with only some callbacks registered; reporting
        // them separately is what lets the doctor say which half is missing.
        assert!(!reported.registry_callback_active);
        assert!(reported.minifilter_active);
        assert_eq!(reported.handles_stripped, 7);
        assert_eq!(reported.file_operations_denied, 9);
    }
}
