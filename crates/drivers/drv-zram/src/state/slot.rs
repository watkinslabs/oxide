use alloc::boxed::Box;

use crate::zsmalloc::Handle;

use super::Compression;

/// Canonical Linux zram table entry value and post-processing flags.
pub(crate) enum Slot {
    Empty,
    /// Linux ZRAM_SAME stores the native machine word repeated throughout the
    /// page. Zero is live data, never the Empty sentinel.
    Same(usize),
    Packed { algorithm: Compression, handle: Handle, priority: u8 },
    /// ZRAM_HUGE is raw page storage. Incompressible records an unsuccessful
    /// secondary-compressor pass independently from huge-page classification.
    Raw { handle: Handle, incompressible: bool, priority: u8 },
    Backed { page: usize, format: BackingFormat },
    Loading { page: usize, format: BackingFormat },
    Writeback { page: usize, data: Box<Slot> },
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub(crate) enum BackingFormat {
    FullPage,
    Packed { algorithm: Compression, len: usize, priority: u8 },
}

impl Slot {
    pub(crate) fn bytes(&self) -> usize {
        match self {
            Self::Empty | Self::Same(_) | Self::Backed { .. } | Self::Loading { .. } => 0,
            Self::Packed { handle, .. } | Self::Raw { handle, .. } => handle.len(),
            Self::Writeback { data, .. } => data.bytes(),
        }
    }

    /// # C: O(1)
    pub(crate) fn is_huge(&self) -> bool {
        match self {
            Self::Raw { .. } => true,
            Self::Writeback { data, .. } => data.is_huge(),
            Self::Empty | Self::Same(_) | Self::Packed { .. } | Self::Backed { .. } | Self::Loading { .. } => false,
        }
    }

    /// # C: O(1)
    pub(crate) fn is_incompressible(&self) -> bool {
        match self {
            Self::Raw { incompressible, .. } => *incompressible,
            Self::Writeback { data, .. } => data.is_incompressible(),
            Self::Empty | Self::Same(_) | Self::Packed { .. } | Self::Backed { .. } | Self::Loading { .. } => false,
        }
    }

    /// # C: O(1)
    pub(crate) fn compression_priority(&self) -> Option<u8> {
        match self {
            Self::Packed { priority, .. } | Self::Raw { priority, .. } => Some(*priority),
            Self::Writeback { data, .. } => data.compression_priority(),
            Self::Empty | Self::Same(_) | Self::Backed { .. } | Self::Loading { .. } => None,
        }
    }

    /// # C: O(1)
    pub(crate) fn mark_incompressible(&mut self) {
        match self {
            Self::Raw { incompressible, .. } => *incompressible = true,
            Self::Writeback { data, .. } => data.mark_incompressible(),
            Self::Empty | Self::Same(_) | Self::Packed { .. } | Self::Backed { .. } | Self::Loading { .. } => {}
        }
    }
}
