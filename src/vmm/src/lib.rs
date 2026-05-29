// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Virtual Machine Monitor that leverages the Linux Kernel-based Virtual Machine (KVM),
//! and other virtualization features to run a single lightweight micro-virtual
//! machine (microVM).
#![warn(missing_docs)]
#![warn(clippy::undocumented_unsafe_blocks)]
#![allow(clippy::blanket_clippy_restriction_lints)]

/// Implements platform specific functionality.
/// Supported platforms: x86_64 and aarch64.
pub mod arch;

/// High-level interface over Linux io_uring.
///
/// Aims to provide an easy-to-use interface, while making some Firecracker-specific simplifying
/// assumptions. The crate does not currently aim at supporting all io_uring features and use
/// cases. For example, it only works with pre-registered fds and read/write/fsync requests.
///
/// Requires at least kernel version 5.10.51.
/// For more information on io_uring, refer to the man pages.
/// [This pdf](https://kernel.dk/io_uring.pdf) is also very useful, though outdated at times.
pub mod io_uring;

/// # Rate Limiter
///
/// Provides a rate limiter written in Rust useful for IO operations that need to
/// be throttled.
///
/// ## Behavior
///
/// The rate limiter starts off as 'unblocked' with two token buckets configured
/// with the values passed in the `RateLimiter::new()` constructor.
/// All subsequent accounting is done independently for each token bucket based
/// on the `TokenType` used. If any of the buckets runs out of budget, the limiter
/// goes in the 'blocked' state. At this point an internal timer is set up which
/// will later 'wake up' the user in order to retry sending data. The 'wake up'
/// notification will be dispatched as an event on the FD provided by the `AsRawFD`
/// trait implementation.
///
/// The contract is that the user shall also call the `event_handler()` method on
/// receipt of such an event.
///
/// The token buckets are replenished when a called `consume()` doesn't find enough
/// tokens in the bucket. The amount of tokens replenished is automatically calculated
/// to respect the `complete_refill_time` configuration parameter provided by the user.
/// The token buckets will never replenish above their respective `size`.
///
/// Each token bucket can start off with a `one_time_burst` initial extra capacity
/// on top of their `size`. This initial extra credit does not replenish and
/// can be used for an initial burst of data.
///
/// The granularity for 'wake up' events when the rate limiter is blocked is
/// currently hardcoded to `100 milliseconds`.
///
/// ## Limitations
///
/// This rate limiter implementation relies on the *Linux kernel's timerfd* so its
/// usage is limited to Linux systems.
///
/// Another particularity of this implementation is that it is not self-driving.
/// It is meant to be used in an external event loop and thus implements the `AsRawFd`
/// trait and provides an *event-handler* as part of its API. This *event-handler*
/// needs to be called by the user on every event on the rate limiter's `AsRawFd` FD.
pub mod rate_limiter;

/// Module for handling ACPI tables.
/// Currently, we only use ACPI on x86 microVMs.
#[cfg(target_arch = "x86_64")]
pub mod acpi;
/// Handles setup and initialization a `Vmm` object.
pub mod builder;
/// Types for guest configuration.
pub mod cpu_config;
pub(crate) mod device_manager;
/// Emulates virtual and hardware devices.
#[allow(missing_docs)]
pub mod devices;
/// minimalist HTTP/TCP/IPv4 stack named DUMBO
pub mod dumbo;
/// Support for GDB debugging the guest
#[cfg(feature = "gdb")]
pub mod gdb;
/// Logger
pub mod logger;
/// microVM Metadata Service MMDS
pub mod mmds;
/// PCI specific emulation code.
pub mod pci;
/// Save/restore utilities.
pub mod persist;
/// Resource store for configured microVM resources.
pub mod resources;
/// microVM RPC API adapters.
pub mod rpc_interface;
/// Seccomp filter utilities.
pub mod seccomp;
/// Signal handling utilities.
pub mod signal_handler;
/// Serialization and deserialization facilities
pub mod snapshot;
/// Utility functions for integration and benchmark testing
pub mod test_utils;
/// Utility functions and struct
pub mod utils;
/// Wrappers over structures used to configure the VMM.
pub mod vmm_config;
/// Module with virtual state structs.
pub mod vstate;

/// Module with initrd.
pub mod initrd;

use std::collections::HashMap;
use std::io;
use std::os::unix::io::AsRawFd;
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Barrier, Mutex};
use std::time::Duration;

use device_manager::DeviceManager;
use event_manager::{EventManager as BaseEventManager, EventOps, Events, MutEventSubscriber};
use seccomp::BpfProgram;
use snapshot::Persist;
use userfaultfd::Uffd;
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::terminal::Terminal;
use vstate::kvm::Kvm;
use vstate::vcpu::{self, StartThreadedError, VcpuSendEventError};

use crate::cpu_config::templates::CpuConfiguration;
use crate::devices::virtio::balloon::device::{HintingStatus, StartHintingCmd};
use crate::devices::virtio::balloon::{
    BALLOON_DEV_ID, Balloon, BalloonConfig, BalloonError, BalloonStats,
};
use crate::devices::virtio::block::BlockError;
use crate::devices::virtio::block::device::Block;
use crate::devices::virtio::mem::{VIRTIO_MEM_DEV_ID, VirtioMem, VirtioMemError, VirtioMemStatus};
use crate::devices::virtio::net::Net;
use crate::logger::{METRICS, MetricsError, error, info, warn};
use crate::persist::{GuestRegionUffdMapping, MicrovmState, MicrovmStateError, VmInfo};
use crate::rate_limiter::BucketUpdate;
use crate::utils::usize_to_u64;
use crate::vmm_config::instance_info::{InstanceInfo, VmState};
use crate::vmm_config::meminfo::DirtyDeltaPacked;
use crate::vstate::memory::{GuestMemory, GuestMemoryMmap, GuestMemoryRegion};
use crate::vstate::vcpu::VcpuState;
pub use crate::vstate::vcpu::{Vcpu, VcpuConfig, VcpuEvent, VcpuHandle, VcpuResponse};
pub use crate::vstate::vm::Vm;
use crate::vstate::vm::mincore_bitmap;

/// Shorthand type for the EventManager flavour used by Firecracker.
pub type EventManager = BaseEventManager<Arc<Mutex<dyn MutEventSubscriber>>>;

// Since the exit code names e.g. `SIGBUS` are most appropriate yet trigger a test error with the
// clippy lint `upper_case_acronyms` we have disabled this lint for this enum.
/// Vmm exit-code type.
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FcExitCode {
    /// Success exit code.
    Ok = 0,
    /// Generic error exit code.
    GenericError = 1,
    /// Generic exit code error; not possible to occur if the program logic is sound.
    UnexpectedError = 2,
    /// Firecracker was shut down after intercepting a restricted system call.
    BadSyscall = 148,
    /// Firecracker was shut down after intercepting `SIGBUS`.
    SIGBUS = 149,
    /// Firecracker was shut down after intercepting `SIGSEGV`.
    SIGSEGV = 150,
    /// Firecracker was shut down after intercepting `SIGXFSZ`.
    SIGXFSZ = 151,
    /// Firecracker was shut down after intercepting `SIGXCPU`.
    SIGXCPU = 154,
    /// Firecracker was shut down after intercepting `SIGPIPE`.
    SIGPIPE = 155,
    /// Firecracker was shut down after intercepting `SIGHUP`.
    SIGHUP = 156,
    /// Firecracker was shut down after intercepting `SIGILL`.
    SIGILL = 157,
    /// Bad configuration for microvm's resources, when using a single json.
    BadConfiguration = 152,
    /// Command line arguments parsing error.
    ArgParsing = 153,
}

/// Timeout used in recv_timeout, when waiting for a vcpu response on
/// Pause/Resume/Save/Restore. A high enough limit that should not be reached during normal usage,
/// used to detect a potential vcpu deadlock.
pub const RECV_TIMEOUT_SEC: Duration = Duration::from_secs(30);

/// Default byte limit of accepted http requests on API and MMDS servers.
pub const HTTP_MAX_PAYLOAD_SIZE: usize = 51200;

/// Errors associated with the VMM internal logic. These errors cannot be generated by direct user
/// input, but can result from bad configuration of the host (for example if Firecracker doesn't
/// have permissions to open the KVM fd).
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VmmError {
    #[cfg(target_arch = "aarch64")]
    /// Invalid command line error.
    Cmdline,
    /// Device manager error: {0}
    DeviceManager(#[from] device_manager::DeviceManagerCreateError),
    /// MMIO Device manager error: {0}
    MmioDeviceManager(device_manager::mmio::MmioError),
    /// Error getting the KVM dirty bitmap. {0}
    DirtyBitmap(kvm_ioctls::Error),
    /// I8042 error: {0}
    I8042Error(devices::legacy::I8042DeviceError),
    #[cfg(target_arch = "x86_64")]
    /// Cannot add devices to the legacy I/O Bus. {0}
    LegacyIOBus(device_manager::legacy::LegacyDeviceError),
    /// Metrics error: {0}
    Metrics(MetricsError),
    /// Cannot add a device to the MMIO Bus. {0}
    RegisterMMIODevice(device_manager::mmio::MmioError),
    /// Cannot install seccomp filters: {0}
    SeccompFilters(seccomp::InstallationError),
    /// Error writing to the serial console: {0}
    Serial(io::Error),
    /// Error creating timer fd: {0}
    TimerFd(io::Error),
    /// Error creating the vcpu: {0}
    VcpuCreate(vstate::vcpu::VcpuError),
    /// Cannot send event to vCPU. {0}
    VcpuEvent(vstate::vcpu::VcpuError),
    /// Cannot create a vCPU handle. {0}
    VcpuHandle(vstate::vcpu::VcpuError),
    /// Failed to start vCPUs
    VcpuStart(StartVcpusError),
    /// Failed to pause the vCPUs.
    VcpuPause,
    /// Failed to exit the vCPUs.
    VcpuExit,
    /// Failed to resume the vCPUs.
    VcpuResume,
    /// Failed to message the vCPUs.
    VcpuMessage,
    /// Cannot spawn Vcpu thread: {0}
    VcpuSpawn(io::Error),
    /// Vm error: {0}
    Vm(#[from] vstate::vm::VmError),
    /// Kvm error: {0}
    Kvm(#[from] vstate::kvm::KvmError),
    /// Failed perform action on device: {0}
    FindDeviceError(#[from] device_manager::FindDeviceError),
    /// Block: {0}
    Block(#[from] BlockError),
    /// Balloon: {0}
    Balloon(#[from] BalloonError),
    /// Pagemap error: {0}
    Pagemap(#[from] utils::pagemap::PagemapError),
    /// Failed to create memory hotplug device: {0}
    VirtioMem(#[from] VirtioMemError),
    /// Internal error: {0}
    InternalError(String),
}

/// Shorthand type for KVM dirty page bitmap.
pub type DirtyBitmap = HashMap<u32, Vec<u64>>;

/// Returns the size of guest memory, in MiB.
pub(crate) fn mem_size_mib(guest_memory: &GuestMemoryMmap) -> u64 {
    guest_memory.iter().map(|region| region.len()).sum::<u64>() >> 20
}

// Error type for [`Vmm::emulate_serial_init`].
/// Emulate serial init error: {0}
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub struct EmulateSerialInitError(#[from] std::io::Error);

/// Error type for [`Vmm::start_vcpus`].
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum StartVcpusError {
    /// VMM observer init error: {0}
    VmmObserverInit(#[from] vmm_sys_util::errno::Error),
    /// Vcpu handle error: {0}
    VcpuHandle(#[from] StartThreadedError),
}

/// Error type for [`Vmm::dump_cpu_config()`]
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum DumpCpuConfigError {
    /// Failed to send event to vcpu thread: {0}
    SendEvent(#[from] VcpuSendEventError),
    /// Got unexpected response from vcpu thread.
    UnexpectedResponse,
    /// Failed to dump CPU config: {0}
    DumpCpuConfig(#[from] vcpu::VcpuError),
    /// Operation not allowed: {0}
    NotAllowed(String),
}

/// Contains the state and associated methods required for the Firecracker VMM.
#[derive(Debug)]
pub struct Vmm {
    /// The [`InstanceInfo`] state of this [`Vmm`].
    pub instance_info: InstanceInfo,
    shutdown_exit_code: Option<FcExitCode>,

    // Guest VM core resources.
    kvm: Kvm,
    /// VM object
    pub vm: Arc<Vm>,
    // Save UFFD in order to keep it open in the Firecracker process, as well.
    #[allow(unused)]
    uffd: Option<Uffd>,
    /// Handles to the vcpu threads with vcpu_fds inside them.
    pub vcpus_handles: Vec<VcpuHandle>,
    // Used by Vcpus and devices to initiate teardown; Vmm should never write here.
    vcpus_exit_evt: EventFd,
    // Device manager
    device_manager: DeviceManager,
    /// Page size used for backing guest memory
    pub page_size: usize,
    /// Per-4KB-block xxh3 hashes for dirty delta tracking.
    /// Initialized from golden mem.snap via PUT /memory/delta-hashes/init.
    /// Updated on each GET /memory/dirty-delta call.
    delta_hashes: Vec<u64>,
    /// Golden mem.snap mmap for XOR delta compression.
    /// Kept alive after init_delta_hashes() for use by get_dirty_delta_packed().
    /// (ptr, len) — raw mmap, PROT_READ, MAP_SHARED.
    golden_base: Option<(*const u8, usize)>,
    /// Previous checkpoint's dirty block data for P-frame XOR.
    /// Maps block_index → raw 4KB block data from the previous checkpoint.
    /// Used as XOR base for P-frame checkpoints (XOR against previous instead
    /// of golden).  Cleared on I-frame (keyframe) to reset memory.
    /// Cap: 4096 blocks (16MB) — if exceeded, cleared and next becomes I-frame.
    prev_checkpoint_blocks: HashMap<u32, Vec<u8>>,
}

// SAFETY: golden_base is a read-only mmap pointer that is only accessed
// from the VMM thread while the VM is paused.  The pointer is valid for
// the lifetime of the Vmm (cleaned up in Drop).
unsafe impl Send for Vmm {}

impl Vmm {
    /// Gets Vmm version.
    pub fn version(&self) -> String {
        self.instance_info.vmm_version.clone()
    }

    /// Gets Vmm instance info.
    pub fn instance_info(&self) -> InstanceInfo {
        self.instance_info.clone()
    }

    /// Provides the Vmm shutdown exit code if there is one.
    pub fn shutdown_exit_code(&self) -> Option<FcExitCode> {
        self.shutdown_exit_code
    }

    /// Starts the microVM vcpus.
    ///
    /// # Errors
    ///
    /// When:
    /// - [`vmm::VmmEventsObserver::on_vmm_boot`] errors.
    /// - [`vmm::vstate::vcpu::Vcpu::start_threaded`] errors.
    pub fn start_vcpus(
        &mut self,
        mut vcpus: Vec<Vcpu>,
        vcpu_seccomp_filter: Arc<BpfProgram>,
    ) -> Result<(), StartVcpusError> {
        let vcpu_count = vcpus.len();
        let barrier = Arc::new(Barrier::new(vcpu_count + 1));

        let stdin = std::io::stdin().lock();
        // Set raw mode for stdin.
        stdin.set_raw_mode().inspect_err(|&err| {
            warn!("Cannot set raw mode for the terminal. {:?}", err);
        })?;

        // Set non blocking stdin.
        stdin.set_non_block(true).inspect_err(|&err| {
            warn!("Cannot set non block for the terminal. {:?}", err);
        })?;

        self.vcpus_handles.reserve(vcpu_count);

        for mut vcpu in vcpus.drain(..) {
            vcpu.set_mmio_bus(self.vm.common.mmio_bus.clone());
            #[cfg(target_arch = "x86_64")]
            vcpu.kvm_vcpu.set_pio_bus(self.vm.pio_bus.clone());

            self.vcpus_handles.push(vcpu.start_threaded(
                &self.vm,
                vcpu_seccomp_filter.clone(),
                barrier.clone(),
            )?);
        }
        self.instance_info.state = VmState::Paused;
        // Wait for vCPUs to initialize their TLS before moving forward.
        barrier.wait();

        Ok(())
    }

    /// Sends a resume command to the vCPUs.
    pub fn resume_vm(&mut self) -> Result<(), VmmError> {
        self.device_manager.kick_virtio_devices();

        // Send the events.
        self.vcpus_handles
            .iter_mut()
            .try_for_each(|handle| handle.send_event(VcpuEvent::Resume))
            .map_err(|_| VmmError::VcpuMessage)?;

        // Check the responses.
        if self
            .vcpus_handles
            .iter()
            .map(|handle| handle.response_receiver().recv_timeout(RECV_TIMEOUT_SEC))
            .any(|response| !matches!(response, Ok(VcpuResponse::Resumed)))
        {
            return Err(VmmError::VcpuMessage);
        }

        self.instance_info.state = VmState::Running;
        Ok(())
    }

    /// Sends a pause command to the vCPUs.
    pub fn pause_vm(&mut self) -> Result<(), VmmError> {
        // Send the events.
        self.vcpus_handles
            .iter_mut()
            .try_for_each(|handle| handle.send_event(VcpuEvent::Pause))
            .map_err(|_| VmmError::VcpuMessage)?;

        // Check the responses.
        if self
            .vcpus_handles
            .iter()
            .map(|handle| handle.response_receiver().recv_timeout(RECV_TIMEOUT_SEC))
            .any(|response| !matches!(response, Ok(VcpuResponse::Paused)))
        {
            return Err(VmmError::VcpuMessage);
        }

        self.instance_info.state = VmState::Paused;
        Ok(())
    }

    /// Injects CTRL+ALT+DEL keystroke combo in the i8042 device.
    #[cfg(target_arch = "x86_64")]
    pub fn send_ctrl_alt_del(&mut self) -> Result<(), VmmError> {
        self.device_manager
            .legacy_devices
            .i8042
            .lock()
            .expect("i8042 lock was poisoned")
            .trigger_ctrl_alt_del()
            .map_err(VmmError::I8042Error)
    }

    /// Saves the state of a paused Microvm.
    pub fn save_state(&mut self, vm_info: &VmInfo) -> Result<MicrovmState, MicrovmStateError> {
        use self::MicrovmStateError::SaveVmState;
        let vcpu_states = self.save_vcpu_states()?;
        let kvm_state = self.kvm.save_state();
        let vm_state = {
            #[cfg(target_arch = "x86_64")]
            {
                self.vm.save_state().map_err(SaveVmState)?
            }
            #[cfg(target_arch = "aarch64")]
            {
                let mpidrs = construct_kvm_mpidrs(&vcpu_states);

                self.vm.save_state(&mpidrs).map_err(SaveVmState)?
            }
        };
        let device_states = self.device_manager.save();

        Ok(MicrovmState {
            vm_info: vm_info.clone(),
            kvm_state,
            vm_state,
            vcpu_states,
            device_states,
        })
    }

    fn save_vcpu_states(&mut self) -> Result<Vec<VcpuState>, MicrovmStateError> {
        for handle in self.vcpus_handles.iter_mut() {
            handle
                .send_event(VcpuEvent::SaveState)
                .map_err(MicrovmStateError::SignalVcpu)?;
        }

        let vcpu_responses = self
            .vcpus_handles
            .iter()
            // `Iterator::collect` can transform a `Vec<Result>` into a `Result<Vec>`.
            .map(|handle| handle.response_receiver().recv_timeout(RECV_TIMEOUT_SEC))
            .collect::<Result<Vec<VcpuResponse>, RecvTimeoutError>>()
            .map_err(|_| MicrovmStateError::UnexpectedVcpuResponse)?;

        let vcpu_states = vcpu_responses
            .into_iter()
            .map(|response| match response {
                VcpuResponse::SavedState(state) => Ok(*state),
                VcpuResponse::Error(err) => Err(MicrovmStateError::SaveVcpuState(err)),
                VcpuResponse::NotAllowed(reason) => Err(MicrovmStateError::NotAllowed(reason)),
                _ => Err(MicrovmStateError::UnexpectedVcpuResponse),
            })
            .collect::<Result<Vec<VcpuState>, MicrovmStateError>>()?;

        Ok(vcpu_states)
    }

    /// Dumps CPU configuration.
    pub fn dump_cpu_config(&mut self) -> Result<Vec<CpuConfiguration>, DumpCpuConfigError> {
        for handle in self.vcpus_handles.iter_mut() {
            handle
                .send_event(VcpuEvent::DumpCpuConfig)
                .map_err(DumpCpuConfigError::SendEvent)?;
        }

        let vcpu_responses = self
            .vcpus_handles
            .iter()
            .map(|handle| handle.response_receiver().recv_timeout(RECV_TIMEOUT_SEC))
            .collect::<Result<Vec<VcpuResponse>, RecvTimeoutError>>()
            .map_err(|_| DumpCpuConfigError::UnexpectedResponse)?;

        let cpu_configs = vcpu_responses
            .into_iter()
            .map(|response| match response {
                VcpuResponse::DumpedCpuConfig(cpu_config) => Ok(*cpu_config),
                VcpuResponse::Error(err) => Err(DumpCpuConfigError::DumpCpuConfig(err)),
                VcpuResponse::NotAllowed(reason) => Err(DumpCpuConfigError::NotAllowed(reason)),
                _ => Err(DumpCpuConfigError::UnexpectedResponse),
            })
            .collect::<Result<Vec<CpuConfiguration>, DumpCpuConfigError>>()?;

        Ok(cpu_configs)
    }

    /// Get dirty block bitmap for a drive, optionally resetting it.
    pub fn get_block_dirty_bitmap(
        &self,
        drive_id: &str,
        reset: bool,
    ) -> Result<crate::vmm_config::meminfo::DriveDirty, VmmError> {
        Ok(self.device_manager
            .with_virtio_device(drive_id, |block: &mut Block| {
                block.get_dirty_bitmap(reset)
            })?)
    }

    /// Updates the path of the host file backing the emulated block device with id `drive_id`.
    /// We update the disk image on the device and its virtio configuration.
    pub fn update_block_device_path(
        &mut self,
        drive_id: &str,
        path_on_host: String,
    ) -> Result<(), VmmError> {
        self.device_manager
            .with_virtio_device(drive_id, |block: &mut Block| {
                block.update_disk_image(path_on_host)
            })??;
        Ok(())
    }

    /// Updates the rate limiter parameters for block device with `drive_id` id.
    pub fn update_block_rate_limiter(
        &mut self,
        drive_id: &str,
        rl_bytes: BucketUpdate,
        rl_ops: BucketUpdate,
    ) -> Result<(), VmmError> {
        self.device_manager
            .with_virtio_device(drive_id, |block: &mut Block| {
                block.update_rate_limiter(rl_bytes, rl_ops)
            })??;
        Ok(())
    }

    /// Updates the rate limiter parameters for block device with `drive_id` id.
    pub fn update_vhost_user_block_config(&mut self, drive_id: &str) -> Result<(), VmmError> {
        self.device_manager
            .with_virtio_device(drive_id, |block: &mut Block| block.update_config())??;
        Ok(())
    }

    /// Updates the rate limiter parameters for net device with `net_id` id.
    pub fn update_net_rate_limiters(
        &mut self,
        net_id: &str,
        rx_bytes: BucketUpdate,
        rx_ops: BucketUpdate,
        tx_bytes: BucketUpdate,
        tx_ops: BucketUpdate,
    ) -> Result<(), VmmError> {
        self.device_manager
            .with_virtio_device(net_id, |net: &mut Net| {
                net.patch_rate_limiters(rx_bytes, rx_ops, tx_bytes, tx_ops)
            })?;
        Ok(())
    }

    /// Returns a reference to the balloon device if present.
    pub fn balloon_config(&self) -> Result<BalloonConfig, VmmError> {
        let config = self
            .device_manager
            .with_virtio_device(BALLOON_DEV_ID, |dev: &mut Balloon| dev.config())?;
        Ok(config)
    }

    /// Returns the latest balloon statistics if they are enabled.
    pub fn latest_balloon_stats(&self) -> Result<BalloonStats, VmmError> {
        let stats = self
            .device_manager
            .with_virtio_device(BALLOON_DEV_ID, |dev: &mut Balloon| dev.latest_stats())??;
        Ok(stats)
    }

    /// Updates configuration for the balloon device target size.
    pub fn update_balloon_config(&mut self, amount_mib: u32) -> Result<(), VmmError> {
        self.device_manager
            .with_virtio_device(BALLOON_DEV_ID, |dev: &mut Balloon| {
                dev.update_size(amount_mib)
            })??;
        Ok(())
    }

    /// Updates configuration for the balloon device as described in `balloon_stats_update`.
    pub fn update_balloon_stats_config(
        &mut self,
        stats_polling_interval_s: u16,
    ) -> Result<(), VmmError> {
        self.device_manager
            .with_virtio_device(BALLOON_DEV_ID, |dev: &mut Balloon| {
                dev.update_stats_polling_interval(stats_polling_interval_s)
            })??;
        Ok(())
    }

    /// Returns the current state of the memory hotplug device.
    pub fn memory_hotplug_status(&self) -> Result<VirtioMemStatus, VmmError> {
        self.device_manager
            .with_virtio_device(VIRTIO_MEM_DEV_ID, |dev: &mut VirtioMem| dev.status())
            .map_err(VmmError::FindDeviceError)
    }

    /// Returns the current state of the memory hotplug device.
    pub fn update_memory_hotplug_size(&self, requested_size_mib: usize) -> Result<(), VmmError> {
        self.device_manager
            .with_virtio_device(VIRTIO_MEM_DEV_ID, |dev: &mut VirtioMem| {
                dev.update_requested_size(requested_size_mib)
            })
            .map_err(VmmError::FindDeviceError)??;
        Ok(())
    }

    /// Starts the balloon free page hinting run
    pub fn start_balloon_hinting(&mut self, cmd: StartHintingCmd) -> Result<(), VmmError> {
        self.device_manager
            .with_virtio_device(BALLOON_DEV_ID, |dev: &mut Balloon| dev.start_hinting(cmd))??;
        Ok(())
    }

    /// Retrieves the status of the balloon hinting run
    pub fn get_balloon_hinting_status(&mut self) -> Result<HintingStatus, VmmError> {
        let status = self
            .device_manager
            .with_virtio_device(BALLOON_DEV_ID, |dev: &mut Balloon| dev.get_hinting_status())??;
        Ok(status)
    }

    /// Stops the balloon free page hinting run
    pub fn stop_balloon_hinting(&mut self) -> Result<(), VmmError> {
        self.device_manager
            .with_virtio_device(BALLOON_DEV_ID, |dev: &mut Balloon| dev.stop_hinting())??;
        Ok(())
    }

    /// Signals Vmm to stop and exit.
    pub fn stop(&mut self, exit_code: FcExitCode) {
        // To avoid cycles, all teardown paths take the following route:
        //   +------------------------+----------------------------+------------------------+
        //   |        Vmm             |           Action           |           Vcpu         |
        //   +------------------------+----------------------------+------------------------+
        // 1 |                        |                            | vcpu.exit(exit_code)   |
        // 2 |                        |                            | vcpu.exit_evt.write(1) |
        // 3 |                        | <--- EventFd::exit_evt --- |                        |
        // 4 | vmm.stop()             |                            |                        |
        // 5 |                        | --- VcpuEvent::Finish ---> |                        |
        // 6 |                        |                            | StateMachine::finish() |
        // 7 | VcpuHandle::join()     |                            |                        |
        // 8 | vmm.shutdown_exit_code becomes Some(exit_code) breaking the main event loop  |
        //   +------------------------+----------------------------+------------------------+
        // Vcpu initiated teardown starts from `fn Vcpu::exit()` (step 1).
        // Vmm initiated teardown starts from `pub fn Vmm::stop()` (step 4).
        // Once `vmm.shutdown_exit_code` becomes `Some(exit_code)`, it is the upper layer's
        // responsibility to break main event loop and propagate the exit code value.
        info!("Vmm is stopping.");

        // We send a "Finish" event.  If a VCPU has already exited, this is the only
        // message it will accept... but running and paused will take it as well.
        // It breaks out of the state machine loop so that the thread can be joined.
        for (idx, handle) in self.vcpus_handles.iter_mut().enumerate() {
            if let Err(err) = handle.send_event(VcpuEvent::Finish) {
                error!("Failed to send VcpuEvent::Finish to vCPU {}: {}", idx, err);
            }
        }
        // The actual thread::join() that runs to release the thread's resource is done in
        // the VcpuHandle's Drop trait.  We can trigger that to happen now by clearing the
        // list of handles. Do it here instead of Vmm::Drop to avoid dependency cycles.
        // (Vmm's Drop will also check if this list is empty).
        self.vcpus_handles.clear();

        // Break the main event loop, propagating the Vmm exit-code.
        self.shutdown_exit_code = Some(exit_code);
    }

    /// Gets a reference to kvm-ioctls Vm
    #[cfg(feature = "gdb")]
    pub fn vm(&self) -> &Vm {
        &self.vm
    }

    /// Get the list of mappings for guest memory
    pub fn guest_memory_mappings(&self, page_size: usize) -> Vec<GuestRegionUffdMapping> {
        let mut mappings = vec![];
        let mut offset = 0;

        for region in self
            .vm
            .guest_memory()
            .iter()
            .flat_map(|region| region.plugged_slots())
        {
            let size = region.slice.len();
            #[allow(deprecated)]
            mappings.push(GuestRegionUffdMapping {
                base_host_virt_addr: region.slice.ptr_guard_mut().as_ptr() as u64,
                size,
                offset,
                page_size,
                page_size_kib: page_size,
            });

            offset += usize_to_u64(size);
        }

        mappings
    }

    /// Get info regarding resident and empty pages for guest memory
    pub fn guest_memory_info(&self, page_size: usize) -> Result<(Vec<u64>, Vec<u64>), VmmError> {
        let mut resident = vec![];
        let mut empty = vec![];
        let zero_page = vec![0u8; page_size];

        for mem_slot in self
            .vm
            .guest_memory()
            .iter()
            .flat_map(|region| region.plugged_slots())
        {
            debug_assert!(mem_slot.slice.len().is_multiple_of(page_size));
            debug_assert!(
                (mem_slot.slice.ptr_guard_mut().as_ptr() as usize).is_multiple_of(page_size)
            );

            let len = mem_slot.slice.len();
            let nr_pages = len / page_size;
            let addr = mem_slot.slice.ptr_guard_mut().as_ptr();
            let mut curr_empty = vec![0u64; nr_pages.div_ceil(64)];
            let curr_resident = mincore_bitmap(addr, mem_slot.slice.len(), page_size)?;

            for page_idx in 0..nr_pages {
                if (curr_resident[page_idx / 64] & (1u64 << (page_idx % 64))) == 0 {
                    continue;
                }

                // SAFETY: `addr` points to a memory region that is `nr_pages * page_size` long.
                let curr_addr = unsafe { addr.add(page_idx * page_size) };

                // SAFETY: both addresses are valid and they point to a memory region
                // that is (at least) `page_size` long
                let ret = unsafe {
                    libc::memcmp(
                        curr_addr.cast::<libc::c_void>(),
                        zero_page.as_ptr().cast::<libc::c_void>(),
                        page_size,
                    )
                };

                if ret == 0 {
                    curr_empty[page_idx / 64] |= 1u64 << (page_idx % 64);
                }
            }

            resident.extend_from_slice(&curr_resident);
            empty.extend_from_slice(&curr_empty);
        }

        Ok((resident, empty))
    }

    /// Get dirty memory bitmap and reset tracking for next checkpoint.
    ///
    /// Returns the current dirty bitmap, then resets the UFFD write-protection
    /// so the next call only returns pages written after this point.
    ///
    /// Uses madvise(MADV_DONTNEED) on non-dirty pages to clear their pagemap
    /// entries, then re-applies write-protection to the entire region.
    ///
    /// Must be called while the VM is paused.
    pub fn reset_dirty_memory(&self, page_size: usize) -> Result<Vec<u64>, VmmError> {
        // Get the current dirty bitmap first
        let dirty_bitmap = self.get_dirty_memory(page_size)?;

        // Count dirty pages for logging
        let dirty_count: u64 = dirty_bitmap.iter().map(|w| w.count_ones() as u64).sum();

        // The dirty bitmap tracks pages where WP was cleared (written to).
        // To reset: we don't need to re-apply WP because WP_ASYNC already
        // handles this — once a page is written, the kernel clears WP and
        // the page stays writable.  The pagemap bit 57 (WP) stays cleared
        // for all previously-written pages.
        //
        // For true incremental tracking, we would need to re-apply WP.
        // But UFFDIO_WRITEPROTECT from the FC process crashes because the
        // UFFD handler (external C process) holds the primary fd.
        //
        // Instead, we return the bitmap as-is.  The Python side uses CRC32
        // dedup against the previous checkpoint's hashes to get the delta.
        // This is the same behavior as GET /memory/dirty but with explicit
        // "reset" semantics for future use.
        info!(
            "reset_dirty_memory: {dirty_count} dirty pages (page_size={page_size}), \
             WP reset skipped (WP_ASYNC mode)"
        );

        Ok(dirty_bitmap)
    }

    /// Get dirty pages bitmap for guest memory
    pub fn get_dirty_memory(&self, page_size: usize) -> Result<Vec<u64>, VmmError> {
        let pagemap = utils::pagemap::PagemapReader::new(page_size)?;
        let mut dirty_bitmap = vec![];

        for mem_slot in self
            .vm
            .guest_memory()
            .iter()
            .flat_map(|region| region.plugged_slots())
        {
            let base_addr = mem_slot.slice.ptr_guard_mut().as_ptr() as usize;
            let len = mem_slot.slice.len();
            let nr_pages = len / page_size;

            // Use mincore_bitmap to get resident pages at guest page size granularity
            let resident_bitmap = vstate::vm::mincore_bitmap(base_addr as *mut u8, len, page_size)?;

            // TODO: if we don't support UFFD/async WP, we can completely skip this bit, as the
            // UFFD handler already tracks dirty pages through the WriteProtected events. For the
            // time being, we always do.
            //
            // Build dirty bitmap: check pagemap only for pages that mincore reports resident.
            // This way we reduce the amount of times we read out of /proc/<pid>/pagemap.
            let mut slot_bitmap = vec![0u64; nr_pages.div_ceil(64)];
            for page_idx in 0..nr_pages {
                // Check if page is resident in the bitmap.
                // TODO: These operations (add to bitmap, check for presence, etc.) merit their own
                // implementation, somewhere within a bitmap type).
                let is_resident = (resident_bitmap[page_idx / 64] & (1u64 << (page_idx % 64))) != 0;
                if is_resident {
                    let virt_addr = base_addr + (page_idx * page_size);
                    if pagemap.is_page_dirty(virt_addr)? {
                        slot_bitmap[page_idx / 64] |= 1u64 << (page_idx % 64);
                    }
                }
            }

            dirty_bitmap.extend_from_slice(&slot_bitmap);
        }

        Ok(dirty_bitmap)
    }

    /// Initialize xxh3 delta hashes from golden mem.snap file.
    ///
    /// Mmaps the golden file read-only, computes xxh3_64 for each 4KB block,
    /// stores hashes in `self.delta_hashes`.  Called once after UFFD snapshot
    /// restore via `PUT /memory/delta-hashes/init`.
    pub fn init_delta_hashes(&mut self, golden_path: &str) -> Result<(), VmmError> {
        use std::os::unix::io::AsRawFd;
        use xxhash_rust::xxh3::xxh3_64;

        let file = std::fs::File::open(golden_path)
            .map_err(|e| VmmError::InternalError(format!("open golden: {e}")))?;
        let len = file.metadata()
            .map_err(|e| VmmError::InternalError(format!("stat golden: {e}")))?
            .len() as usize;

        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                file.as_raw_fd(),
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(VmmError::InternalError("mmap golden failed".into()));
        }

        let host_ps = crate::arch::host_page_size();
        let num_blocks = len / host_ps;
        let data = unsafe { std::slice::from_raw_parts(ptr as *const u8, len) };

        let mut hashes = Vec::with_capacity(num_blocks);
        for i in 0..num_blocks {
            let block = &data[i * host_ps..(i + 1) * host_ps];
            hashes.push(xxh3_64(block));
        }

        // Keep the golden mmap alive for XOR delta compression in
        // get_dirty_delta_packed().  Cleaned up in Drop.
        // SAFETY: ptr is a valid mmap pointer with PROT_READ, MAP_SHARED.
        // We only read from it while the VM is paused.
        if let Some((old_ptr, old_len)) = self.golden_base.take() {
            // Clean up any previous mmap (e.g. re-init after golden upgrade)
            unsafe { libc::munmap(old_ptr as *mut libc::c_void, old_len); }
        }
        self.golden_base = Some((ptr as *const u8, len));

        info!(
            "init_delta_hashes: computed {} xxh3 hashes from {} ({}MB), golden mmap kept alive",
            num_blocks, golden_path, len / (1024 * 1024)
        );
        self.delta_hashes = hashes;
        Ok(())
    }

    /// Get dirty delta: xxHash dedup at 4KB granularity.
    ///
    /// For each dirty 2MB hugepage (from UFFD pagemap), xxh3 each 4KB
    /// sub-page and compare against stored hashes.  Returns bitmap of
    /// only changed sub-pages.  Updates stored hashes for next call.
    ///
    /// Must be called while VM is paused.
    pub fn get_dirty_delta(&mut self, page_size: usize) -> Result<Vec<u64>, VmmError> {
        use xxhash_rust::xxh3::xxh3_64;

        if self.delta_hashes.is_empty() {
            return Err(VmmError::InternalError(
                "delta_hashes not initialized — call init_delta_hashes first".into(),
            ));
        }

        let host_ps = crate::arch::host_page_size();
        let subs_per_page = page_size / host_ps;

        // Step 1: Get UFFD dirty bitmap (2MB hugepage granularity)
        let dirty_bitmap = self.get_dirty_memory(page_size)?;

        // Step 2: For each dirty hugepage, xxh3 each 4KB sub-page
        let mut delta_bitmap = vec![];
        let mut global_sub_idx = 0usize;

        for mem_slot in self
            .vm
            .guest_memory()
            .iter()
            .flat_map(|region| region.plugged_slots())
        {
            let base = mem_slot.slice.ptr_guard_mut().as_ptr() as *const u8;
            let nr_pages = mem_slot.slice.len() / page_size;
            let nr_subs = mem_slot.slice.len() / host_ps;
            let mut sub_bitmap = vec![0u64; nr_subs.div_ceil(64)];

            for page_idx in 0..nr_pages {
                let is_dirty =
                    (dirty_bitmap[page_idx / 64] & (1u64 << (page_idx % 64))) != 0;
                if !is_dirty {
                    global_sub_idx += subs_per_page;
                    continue;
                }

                for sub in 0..subs_per_page {
                    let sub_idx = page_idx * subs_per_page + sub;
                    let offset = sub_idx * host_ps;
                    let block = unsafe {
                        std::slice::from_raw_parts(base.add(offset), host_ps)
                    };
                    let hash = xxh3_64(block);

                    if global_sub_idx < self.delta_hashes.len()
                        && hash != self.delta_hashes[global_sub_idx]
                    {
                        sub_bitmap[sub_idx / 64] |= 1u64 << (sub_idx % 64);
                        self.delta_hashes[global_sub_idx] = hash;
                    }
                    global_sub_idx += 1;
                }
            }
            delta_bitmap.extend_from_slice(&sub_bitmap);
        }

        Ok(delta_bitmap)
    }

    /// Get dirty delta as XOR'd packed_v1 lz4 blob.
    ///
    /// Combines get_dirty_delta() bitmap + block reads + XOR + pack + lz4
    /// compress — all in a single call.  Returns the compressed blob ready
    /// for S3 upload.
    ///
    /// **P-frame support**: If `prev_checkpoint_blocks` is non-empty, blocks
    /// that exist in the previous checkpoint are XOR'd against the previous
    /// data (P-frame) instead of golden (I-frame).  This produces mostly-zero
    /// XOR results that lz4 compresses 20-100x better.
    ///
    /// Must be called while VM is paused.
    pub fn get_dirty_delta_packed(
        &mut self,
        page_size: usize,
    ) -> Result<DirtyDeltaPacked, VmmError> {
        use lz4_flex::frame::FrameEncoder;
        use std::io::Write;
        use xxhash_rust::xxh3::xxh3_64;

        if self.delta_hashes.is_empty() {
            return Err(VmmError::InternalError(
                "delta_hashes not initialized — call init_delta_hashes first".into(),
            ));
        }
        let (golden_ptr, golden_len) = self.golden_base.ok_or_else(|| {
            VmmError::InternalError("golden_base not available for XOR".into())
        })?;
        // SAFETY: golden_ptr/golden_len were set by a successful mmap in
        // init_delta_hashes().  The mmap is PROT_READ, MAP_SHARED and stays
        // valid until Drop.  We only read from it while the VM is paused.
        let golden_data = unsafe {
            std::slice::from_raw_parts(golden_ptr, golden_len)
        };

        let host_ps = crate::arch::host_page_size(); // 4096
        let subs_per_page = page_size / host_ps;

        // P-frame: if prev_checkpoint_blocks is non-empty, we have a previous
        // checkpoint to XOR against.  Track whether any block used P-frame XOR.
        let has_prev = !self.prev_checkpoint_blocks.is_empty();
        let prev_block_count = self.prev_checkpoint_blocks.len();

        // Step 1: Get UFFD dirty bitmap (hugepage granularity)
        let dirty_bitmap = self.get_dirty_memory(page_size)?;

        // Step 2: For each dirty block, read + xxHash dedup + XOR
        let mut indices: Vec<u32> = Vec::new();
        let mut block_data: Vec<u8> = Vec::new();
        let mut global_sub_idx = 0usize;
        // Collect new prev blocks for next checkpoint's P-frame XOR.
        // Stores RAW block data (before XOR) — the actual guest memory content.
        let mut new_prev_blocks: HashMap<u32, Vec<u8>> = HashMap::new();
        let mut p_frame_blocks = 0u32;
        let mut i_frame_blocks = 0u32;

        for mem_slot in self
            .vm
            .guest_memory()
            .iter()
            .flat_map(|region| region.plugged_slots())
        {
            let base = mem_slot.slice.ptr_guard_mut().as_ptr() as *const u8;
            let nr_pages = mem_slot.slice.len() / page_size;

            for page_idx in 0..nr_pages {
                let is_dirty =
                    (dirty_bitmap[page_idx / 64] & (1u64 << (page_idx % 64))) != 0;
                if !is_dirty {
                    global_sub_idx += subs_per_page;
                    continue;
                }

                for sub in 0..subs_per_page {
                    let sub_idx = page_idx * subs_per_page + sub;
                    let offset = sub_idx * host_ps;
                    // SAFETY: base points to guest memory mapped by KVM.
                    // offset is within the slot's bounds (sub_idx < nr_subs).
                    // VM is paused so memory is stable.
                    let block = unsafe {
                        std::slice::from_raw_parts(base.add(offset), host_ps)
                    };
                    let hash = xxh3_64(block);

                    if global_sub_idx < self.delta_hashes.len()
                        && hash != self.delta_hashes[global_sub_idx]
                    {
                        // Determine XOR base: previous checkpoint (P-frame)
                        // or golden (I-frame).
                        let xor_base: &[u8] = if let Some(prev_data) =
                            self.prev_checkpoint_blocks.get(&(sub_idx as u32))
                        {
                            // P-frame: XOR against previous checkpoint's data
                            prev_data.as_slice()
                        } else if offset + host_ps <= golden_len {
                            // I-frame: XOR against golden base
                            &golden_data[offset..offset + host_ps]
                        } else {
                            // Beyond golden range — store raw
                            block
                        };

                        // XOR in 8-byte chunks for performance
                        let mut xored = vec![0u8; host_ps];
                        let mut is_zero = true;
                        for i in (0..host_ps).step_by(8) {
                            let d = u64::from_ne_bytes(
                                block[i..i + 8].try_into().unwrap(),
                            );
                            let b = u64::from_ne_bytes(
                                xor_base[i..i + 8].try_into().unwrap(),
                            );
                            let x = d ^ b;
                            if x != 0 {
                                is_zero = false;
                            }
                            xored[i..i + 8].copy_from_slice(&x.to_ne_bytes());
                        }

                        // Phase 6b: skip blocks identical to XOR base
                        // (XOR result is all-zeros → block unchanged vs base)
                        if is_zero {
                            self.delta_hashes[global_sub_idx] = hash;
                            // Still save RAW block for next P-frame base
                            new_prev_blocks
                                .insert(sub_idx as u32, block.to_vec());
                            global_sub_idx += 1;
                            continue;
                        }

                        block_data.extend_from_slice(&xored);
                        indices.push(sub_idx as u32);
                        self.delta_hashes[global_sub_idx] = hash;

                        // Track frame type per block for logging
                        if self
                            .prev_checkpoint_blocks
                            .contains_key(&(sub_idx as u32))
                        {
                            p_frame_blocks += 1;
                        } else {
                            i_frame_blocks += 1;
                        }

                        // Save RAW block (before XOR) for next checkpoint
                        new_prev_blocks
                            .insert(sub_idx as u32, block.to_vec());
                    }
                    global_sub_idx += 1;
                }
            }
        }

        // Determine frame type: P-frame if we had previous blocks to XOR against
        let is_p_frame = has_prev;

        // Step 3: Pack into packed_v1 format
        let block_count = indices.len() as u32;
        let block_size = host_ps as u32;
        let raw_size =
            20 + (block_count as usize) * 4 + block_data.len();
        let mut raw_blob = Vec::with_capacity(raw_size);

        // Header (20 bytes): magic "FCBK", version u16=1, block_size u32,
        // block_count u32, reserved 6 bytes
        raw_blob.extend_from_slice(b"FCBK");
        raw_blob.extend_from_slice(&1u16.to_le_bytes());
        raw_blob.extend_from_slice(&block_size.to_le_bytes());
        raw_blob.extend_from_slice(&block_count.to_le_bytes());
        raw_blob.extend_from_slice(&[0u8; 6]);
        // Index table
        for idx in &indices {
            raw_blob.extend_from_slice(&idx.to_le_bytes());
        }
        // Block data
        raw_blob.extend_from_slice(&block_data);

        // Step 4: lz4 frame compress (compatible with Python lz4.frame.decompress)
        let mut encoder = FrameEncoder::new(Vec::new());
        encoder.write_all(&raw_blob).map_err(|e| {
            VmmError::InternalError(format!("lz4 compress write: {e}"))
        })?;
        let compressed = encoder.finish().map_err(|e| {
            VmmError::InternalError(format!("lz4 compress finish: {e}"))
        })?;

        // Step 5: Update prev_checkpoint_blocks for next P-frame.
        // Cap at 4096 blocks (16MB) — if exceeded, clear so next becomes I-frame.
        const MAX_PREV_BLOCKS: usize = 4096;
        if new_prev_blocks.len() <= MAX_PREV_BLOCKS {
            self.prev_checkpoint_blocks = new_prev_blocks;
        } else {
            info!(
                "get_dirty_delta_packed: prev_blocks cap exceeded \
                 ({} > {}), clearing — next checkpoint will be I-frame",
                new_prev_blocks.len(),
                MAX_PREV_BLOCKS
            );
            self.prev_checkpoint_blocks.clear();
        }

        info!(
            "get_dirty_delta_packed: frame={}, {} blocks \
             ({} P-frame + {} I-frame), {}B raw, {}B compressed, \
             prev_blocks: {} → {}",
            if is_p_frame { "P" } else { "I" },
            block_count,
            p_frame_blocks,
            i_frame_blocks,
            raw_size,
            compressed.len(),
            prev_block_count,
            self.prev_checkpoint_blocks.len()
        );

        Ok(DirtyDeltaPacked {
            blob: compressed,
            block_count,
            raw_size: raw_size as u64,
            is_p_frame,
        })
    }

    /// Get true guest writes: KVM dirty log ∩ UFFD pagemap dirty.
    ///
    /// Combines two tracking mechanisms:
    /// - **KVM dirty log** (`get_dirty_log`): tracks ALL page table modifications
    ///   since last call.  Atomic get-and-clear at host page size (4KB).
    ///   Includes both UFFD faults and guest writes.
    /// - **UFFD pagemap** (bit 57): tracks write-protection status.
    ///   WP cleared = page was written by guest.  Cumulative (no reset).
    ///
    /// The intersection `KVM_dirty AND NOT WP_set` gives exactly the pages
    /// that were written by the guest since the last call — excluding UFFD
    /// demand-faults which are KVM-dirty but still WP-protected.
    ///
    /// Returns bitmap at host page size (4KB) granularity.
    /// Must be called while VM is paused.
    pub fn get_kvm_dirty_writes(&self) -> Result<Vec<u64>, VmmError> {
        let host_ps = crate::arch::host_page_size();
        let pagemap = utils::pagemap::PagemapReader::new(host_ps)?;

        // Step 1: KVM dirty log — atomic get-and-clear
        let kvm_dirty = self.vm.get_dirty_bitmap(host_ps)
            .map_err(VmmError::Vm)?;

        // Flatten KVM dirty map (HashMap<slot, Vec<u64>>) into ordered Vec
        let mut kvm_slots: Vec<_> = kvm_dirty.into_iter().collect();
        kvm_slots.sort_by_key(|(slot_id, _)| *slot_id);

        // Step 2: For each page, check KVM dirty AND pagemap dirty (NOT WP)
        let mut result_bitmap = vec![];
        let mut kvm_iter = kvm_slots.into_iter();
        let mut kvm_current = kvm_iter.next();

        for mem_slot in self
            .vm
            .guest_memory()
            .iter()
            .flat_map(|region| region.plugged_slots())
        {
            let base_addr = mem_slot.slice.ptr_guard_mut().as_ptr() as usize;
            let len = mem_slot.slice.len();
            let nr_pages = len / host_ps;

            // Get KVM bitmap for this slot
            let kvm_bm = if let Some((_, ref bm)) = kvm_current {
                bm.clone()
            } else {
                vec![0u64; nr_pages.div_ceil(64)]
            };
            kvm_current = kvm_iter.next();

            let mut slot_bitmap = vec![0u64; nr_pages.div_ceil(64)];
            for page_idx in 0..nr_pages {
                let kvm_dirty_bit =
                    (kvm_bm[page_idx / 64] & (1u64 << (page_idx % 64))) != 0;
                if kvm_dirty_bit {
                    // Check pagemap: present AND WP cleared = written by guest
                    let virt_addr = base_addr + (page_idx * host_ps);
                    if pagemap.is_page_dirty(virt_addr).unwrap_or(false) {
                        slot_bitmap[page_idx / 64] |= 1u64 << (page_idx % 64);
                    }
                }
            }
            result_bitmap.extend_from_slice(&slot_bitmap);
        }

        Ok(result_bitmap)
    }
}

/// Process the content of the MPIDR_EL1 register in order to be able to pass it to KVM
///
/// The kernel expects to find the four affinity levels of the MPIDR in the first 32 bits of the
/// VGIC register attribute:
/// https://elixir.free-electrons.com/linux/v4.14.203/source/virt/kvm/arm/vgic/vgic-kvm-device.c#L445.
///
/// The format of the MPIDR_EL1 register is:
/// | 39 .... 32 | 31 .... 24 | 23 .... 16 | 15 .... 8 | 7 .... 0 |
/// |    Aff3    |    Other   |    Aff2    |    Aff1   |   Aff0   |
///
/// The KVM mpidr format is:
/// | 63 .... 56 | 55 .... 48 | 47 .... 40 | 39 .... 32 |
/// |    Aff3    |    Aff2    |    Aff1    |    Aff0    |
/// As specified in the linux kernel: Documentation/virt/kvm/devices/arm-vgic-v3.rst
#[cfg(target_arch = "aarch64")]
fn construct_kvm_mpidrs(vcpu_states: &[VcpuState]) -> Vec<u64> {
    vcpu_states
        .iter()
        .map(|state| {
            let cpu_affid = ((state.mpidr & 0xFF_0000_0000) >> 8) | (state.mpidr & 0xFF_FFFF);
            cpu_affid << 32
        })
        .collect()
}

impl Drop for Vmm {
    fn drop(&mut self) {
        // There are two cases when `drop()` is called:
        // 1) before the Vmm has been mutexed and subscribed to the event manager, or
        // 2) after the Vmm has been registered as a subscriber to the event manager.
        //
        // The first scenario is bound to happen if an error is raised during
        // Vmm creation (for example, during snapshot load), before the Vmm has
        // been subscribed to the event manager. If that happens, the `drop()`
        // function is called right before propagating the error. In order to
        // be able to gracefully exit Firecracker with the correct fault
        // message, we need to prepare the Vmm contents for the tear down
        // (join the vcpu threads). Explicitly calling `stop()` allows the
        // Vmm to be successfully dropped and firecracker to propagate the
        // error.
        //
        // In the second case, before dropping the Vmm object, the event
        // manager calls `stop()`, which sends a `Finish` event to the vcpus
        // and joins the vcpu threads. The Vmm is dropped after everything is
        // ready to be teared down. The line below is a no-op, because the Vmm
        // has already been stopped by the event manager at this point.
        self.stop(self.shutdown_exit_code.unwrap_or(FcExitCode::Ok));

        if let Err(err) = std::io::stdin().lock().set_canon_mode() {
            warn!("Cannot set canonical mode for the terminal. {:?}", err);
        }

        // Write the metrics before exiting.
        if let Err(err) = METRICS.write() {
            error!("Failed to write metrics while stopping: {}", err);
        }

        // Clean up golden mmap if it was kept alive for XOR delta compression.
        if let Some((ptr, len)) = self.golden_base.take() {
            // SAFETY: ptr/len were set by a successful mmap in init_delta_hashes().
            unsafe { libc::munmap(ptr as *mut libc::c_void, len); }
        }

        if !self.vcpus_handles.is_empty() {
            error!("Failed to tear down Vmm: the vcpu threads have not finished execution.");
        }
    }
}

impl MutEventSubscriber for Vmm {
    /// Handle a read event (EPOLLIN).
    fn process(&mut self, event: Events, _: &mut EventOps) {
        let source = event.fd();
        let event_set = event.event_set();

        if source == self.vcpus_exit_evt.as_raw_fd() && event_set == EventSet::IN {
            // Exit event handling should never do anything more than call 'self.stop()'.
            let _ = self.vcpus_exit_evt.read();

            let exit_code = 'exit_code: {
                // Query each vcpu for their exit_code.
                for handle in &self.vcpus_handles {
                    // Drain all vcpu responses that are pending from this vcpu until we find an
                    // exit status.
                    for response in handle.response_receiver().try_iter() {
                        if let VcpuResponse::Exited(status) = response {
                            // It could be that some vcpus exited successfully while others
                            // errored out. Thus make sure that error exits from one vcpu always
                            // takes precedence over "ok" exits
                            if status != FcExitCode::Ok {
                                break 'exit_code status;
                            }
                        }
                    }
                }

                // No CPUs exited with error status code, report "Ok"
                FcExitCode::Ok
            };
            self.stop(exit_code);
        } else {
            error!("Spurious EventManager event for handler: Vmm");
        }
    }

    fn init(&mut self, ops: &mut EventOps) {
        if let Err(err) = ops.add(Events::new(&self.vcpus_exit_evt, EventSet::IN)) {
            error!("Failed to register vmm exit event: {}", err);
        }
    }
}
