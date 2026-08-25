use alloc::vec::Vec;
use core::alloc::Layout;
use core::sync::atomic::AtomicI32;
use sync::{Spinlock, Modules as ModulesLockClass};
use super::{client, connector};

pub(crate) struct DeviceAllocation {
    pub(crate) dev: usize,
    pub(crate) base: usize,
    pub(crate) layout: Layout,
    pub(crate) refs: usize,
    pub(crate) mode_config: bool,
    pub(crate) objects: Vec<ModeObjectRecord>,
    pub(crate) planes: Vec<PlaneRecord>,
    pub(crate) crtcs: Vec<CrtcRecord>,
    pub(crate) encoders: Vec<EncoderRecord>,
    pub(crate) connectors: Vec<connector::ConnectorRecord>,
    pub(crate) clients: Vec<client::ClientRecord>,
    pub(crate) vblank: Option<(usize, Layout)>,
    /// The current primary-node master file. Linux keeps this relationship in
    /// `drm_device::master`; the module ABI needs the same ownership decision
    /// before it may admit `DRM_MASTER` ioctls.
    pub(crate) primary_master: Option<usize>,
    pub(crate) put_pending: bool,
    pub(crate) unplugged: bool,
}

#[derive(Copy, Clone)]
pub(crate) struct ModeObjectRecord { pub(crate) ptr: usize, pub(crate) id: u32 }

pub(crate) struct PlaneRecord { pub(crate) ptr: usize, pub(crate) formats: usize, pub(crate) layout: Layout }

#[derive(Copy, Clone)]
pub(crate) struct CrtcRecord { pub(crate) ptr: usize, pub(crate) name: usize, pub(crate) layout: Layout }

#[derive(Copy, Clone)]
pub(crate) struct EncoderRecord { pub(crate) ptr: usize, pub(crate) name: usize, pub(crate) layout: Layout }

pub(crate) static DEVICES: Spinlock<Vec<DeviceAllocation>, ModulesLockClass> = Spinlock::new(Vec::new());
pub(crate) static GUARDS: Spinlock<Vec<(i32, usize)>, ModulesLockClass> = Spinlock::new(Vec::new());
pub(crate) static NEXT_GUARD: AtomicI32 = AtomicI32::new(1);
pub(crate) static DRAIN_WAIT: sched::live::WaitList = sched::live::WaitList::new();

pub(crate) const DRM_DEVICE_REF_OFF: usize = 4;
pub(crate) const DRM_DEVICE_DEV_OFF: usize = 8;
pub(crate) const DRM_DEVICE_DMA_DEV_OFF: usize = 16;
pub(crate) const DRM_DEVICE_FINAL_KFREE_OFF: usize = 40;
pub(crate) const DRM_DEVICE_DRIVER_OFF: usize = 56;
pub(crate) const DRM_DEVICE_FEATURES_OFF: usize = 112;
pub(crate) const DRM_DEVICE_CLIENTLIST_OFF: usize = 272;
pub(crate) const DRM_DEVICE_FILELIST_INTERNAL_OFF: usize = 224;
pub(crate) const DRM_DRIVER_FEATURES_OFF: usize = 168;
pub(crate) const INITIAL_REFERENCE_COUNT: i32 = 1;
pub(crate) const LINUX_ENODEV: i32 = 19;
pub(crate) const LINUX_EBUSY: i32 = 16;
pub(crate) const LINUX_EINVAL: i32 = 22;
pub(crate) const DRM_MODE_CONFIG_OFF: usize = 360;
pub(crate) const DRM_DEVICE_VBLANK_OFF: usize = 312;
pub(crate) const DRM_DEVICE_NUM_CRTCS_OFF: usize = 356;
pub(crate) const DRM_VBLANK_CRTC_SIZE: usize = 400;
pub(crate) const DRM_VBLANK_CRTC_DEV_OFF: usize = 0;
pub(crate) const DRM_VBLANK_CRTC_PIPE_OFF: usize = 112;
pub(crate) const DRM_DEVICE_SIZE: usize = 1584;
pub(crate) const MODE_CONFIG_FB_LIST_OFF: usize = 216;
pub(crate) const MODE_CONFIG_CONNECTOR_LIST_OFF: usize = 256;
pub(crate) const MODE_CONFIG_ENCODER_LIST_OFF: usize = 320;
pub(crate) const MODE_CONFIG_PLANE_LIST_OFF: usize = 344;
pub(crate) const MODE_CONFIG_COLOROP_LIST_OFF: usize = 368;
pub(crate) const MODE_CONFIG_CRTC_LIST_OFF: usize = 392;
pub(crate) const MODE_CONFIG_PROPERTY_LIST_OFF: usize = 408;
pub(crate) const MODE_CONFIG_PRIVOBJ_LIST_OFF: usize = 424;
pub(crate) const MODE_CONFIG_BLOB_LIST_OFF: usize = 592;
pub(crate) const MODE_CONFIG_LISTS: [usize; 9] = [
    MODE_CONFIG_FB_LIST_OFF, MODE_CONFIG_CONNECTOR_LIST_OFF, MODE_CONFIG_ENCODER_LIST_OFF,
    MODE_CONFIG_PLANE_LIST_OFF, MODE_CONFIG_COLOROP_LIST_OFF, MODE_CONFIG_CRTC_LIST_OFF,
    MODE_CONFIG_PROPERTY_LIST_OFF, MODE_CONFIG_PRIVOBJ_LIST_OFF, MODE_CONFIG_BLOB_LIST_OFF,
];
pub(crate) const DRM_MODE_OBJECT_ID_OFF: usize = 0;
pub(crate) const DRM_MODE_OBJECT_TYPE_OFF: usize = 4;
pub(crate) const MODE_CONFIG_NUM_ENCODER_OFF: usize = 312;
pub(crate) const MODE_CONFIG_NUM_TOTAL_PLANE_OFF: usize = 336;
pub(crate) const MODE_CONFIG_NUM_CRTC_OFF: usize = 384;
pub(crate) const DRM_PLANE_HEAD_OFF: usize = 8;
pub(crate) const DRM_PLANE_BASE_OFF: usize = 80;
pub(crate) const DRM_PLANE_POSSIBLE_CRTCS_OFF: usize = 112;
pub(crate) const DRM_PLANE_FORMATS_OFF: usize = 120;
pub(crate) const DRM_PLANE_FORMAT_COUNT_OFF: usize = 128;
pub(crate) const DRM_PLANE_FUNCS_OFF: usize = 176;
pub(crate) const DRM_PLANE_TYPE_OFF: usize = 1216;
pub(crate) const DRM_PLANE_INDEX_OFF: usize = 1220;
pub(crate) const DRM_CRTC_HEAD_OFF: usize = 16;
pub(crate) const DRM_CRTC_BASE_OFF: usize = 96;
pub(crate) const DRM_CRTC_PRIMARY_OFF: usize = 128;
pub(crate) const DRM_CRTC_CURSOR_OFF: usize = 136;
pub(crate) const DRM_CRTC_INDEX_OFF: usize = 144;
pub(crate) const DRM_CRTC_FUNCS_OFF: usize = 408;
pub(crate) const DRM_CRTC_COMMIT_LIST_OFF: usize = 1496;
pub(crate) const DRM_CRTC_COMMIT_LOCK_OFF: usize = 1512;
pub(crate) const DRM_MODE_OBJECT_CRTC: u32 = 0xcccc_cccc;
pub(crate) const DRM_MODE_OBJECT_ENCODER: u32 = 0xe0e0_e0e0;
pub(crate) const DRM_MODE_OBJECT_PLANE: u32 = 0xeeee_eeee;
pub(crate) const DRM_ENCODER_HEAD_OFF: usize = 8;
pub(crate) const DRM_ENCODER_BASE_OFF: usize = 24;
pub(crate) const DRM_ENCODER_NAME_OFF: usize = 56;
pub(crate) const DRM_ENCODER_TYPE_OFF: usize = 64;
pub(crate) const DRM_ENCODER_INDEX_OFF: usize = 68;
pub(crate) const DRM_ENCODER_FUNCS_OFF: usize = 104;
pub(crate) const MAX_KMS_OBJECTS: i32 = 32;
