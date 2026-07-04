use super::*;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VirtioResources {
    pub cfg_va: u64,
    pub device_cfg_va: u64,
    pub hhdm: u64,
    queues: [Option<VirtQueueResource>; MAX_RESOURCE_QUEUES],
}

impl VirtioResources {
    pub const fn new(cfg_va: u64, hhdm: u64) -> Self {
        Self { cfg_va, device_cfg_va: 0, hhdm, queues: [None; MAX_RESOURCE_QUEUES] }
    }

    pub const fn with_device_cfg_va(mut self, device_cfg_va: u64) -> Self {
        self.device_cfg_va = device_cfg_va;
        self
    }

    pub fn from_queues(cfg_va: u64, hhdm: u64, queues: &[VirtQueueResource]) -> Self {
        let mut resources = Self::new(cfg_va, hhdm);
        for queue in queues {
            resources.set_queue(*queue);
        }
        resources
    }

    pub fn set_queue(&mut self, queue: VirtQueueResource) {
        let index = queue.index as usize;
        if index < MAX_RESOURCE_QUEUES {
            self.queues[index] = Some(queue);
        }
    }

    pub const fn queue(&self, index: u16) -> Option<VirtQueueResource> {
        let index = index as usize;
        if index < MAX_RESOURCE_QUEUES { self.queues[index] } else { None }
    }

    pub const fn require_queue(&self, index: u16) -> Option<VirtQueueResource> {
        let Some(queue) = self.queue(index) else { return None };
        if queue.index == index && queue.is_runtime_valid() { Some(queue) } else { None }
    }

    pub const fn common_cfg_valid(&self) -> bool {
        self.cfg_va != 0 && self.hhdm != 0
    }

    pub fn require_common_and_queues(&self, queues: &[u16]) -> bool {
        if !self.common_cfg_valid() {
            return false;
        }
        for queue in queues {
            if self.require_queue(*queue).is_none() {
                return false;
            }
        }
        true
    }
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct VirtioTransportLocation {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl VirtioTransportLocation {
    pub const fn new(bus: u8, device: u8, function: u8) -> Self {
        Self { bus, device, function }
    }
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct VirtioNetRxBuffer {
    pub desc_id: u16,
    pub pa: u64,
    pub len: u16,
}

pub const VIRTIO_NET_RX_BOOT_POOL: usize = 8;

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct VirtioNetBootPayloads {
    pub rx_bufs: [VirtioNetRxBuffer; VIRTIO_NET_RX_BOOT_POOL],
    pub rx_bufs_len: usize,
    pub tx_buf_pa: u64,
}

impl VirtioNetBootPayloads {
    pub const fn new(rx_buf_pa: u64, rx_buf_len: u16, tx_buf_pa: u64) -> Self {
        let mut rx_bufs = [VirtioNetRxBuffer { desc_id: 0, pa: 0, len: 0 }; VIRTIO_NET_RX_BOOT_POOL];
        let rx_bufs_len = if rx_buf_pa != 0 && rx_buf_len != 0 {
            rx_bufs[0] = VirtioNetRxBuffer { desc_id: 0, pa: rx_buf_pa, len: rx_buf_len };
            1
        } else {
            0
        };
        Self { rx_bufs, rx_bufs_len, tx_buf_pa }
    }

    pub const fn from_rx_pool(
        rx_bufs: [VirtioNetRxBuffer; VIRTIO_NET_RX_BOOT_POOL],
        rx_bufs_len: usize,
        tx_buf_pa: u64,
    ) -> Self {
        Self { rx_bufs, rx_bufs_len, tx_buf_pa }
    }

    pub const fn is_present(&self) -> bool {
        self.rx_bufs_len != 0 && self.rx_bufs_valid() && self.tx_buf_pa != 0
    }

    pub const fn rx_bufs_valid(&self) -> bool {
        let mut i = 0;
        while i < self.rx_bufs_len {
            if i >= VIRTIO_NET_RX_BOOT_POOL || self.rx_bufs[i].pa == 0 || self.rx_bufs[i].len == 0 {
                return false;
            }
            i += 1;
        }
        true
    }
}
