//! Typed SCMI performance records decoded from FDT.

extern crate alloc;

use alloc::vec::Vec;

/// One CPU-physical shared-memory resource used by an SCMI transport.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ScmiSharedMemory { pub base_pa: u64, pub size: u64 }

/// The calling convention for an SCMI SMC transport.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ScmiSmcTransport { Direct, PageAndOffset }

/// The FDT-resolved GIC completion line for an asynchronous SMC channel.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ScmiCompletionIrq { pub intid: u32, pub level: bool }

/// One CPU's firmware performance-domain selector.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ScmiCpuDomain { pub cpu_mpidr: u64, pub domain_id: u32 }

/// One SCMI performance protocol, its controller channel, and CPU consumers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScmiPerfProtocol {
    pub protocol_phandle: u32,
    pub smc_id: u32,
    pub transport: ScmiSmcTransport,
    pub completion_irq: Option<ScmiCompletionIrq>,
    pub shmem: ScmiSharedMemory,
    pub cpu_domains: Vec<ScmiCpuDomain>,
}
