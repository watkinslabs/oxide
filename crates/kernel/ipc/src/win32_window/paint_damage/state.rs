use super::{PaintRegion, WindowError, WindowRect};
pub const RDW_INVALIDATE: u32 = 0x0001;
pub const RDW_INTERNALPAINT: u32 = 0x0002;
pub const RDW_ERASE: u32 = 0x0004;
pub const RDW_VALIDATE: u32 = 0x0008;
pub const RDW_NOINTERNALPAINT: u32 = 0x0010;
pub const RDW_NOERASE: u32 = 0x0020;
pub const RDW_NOCHILDREN: u32 = 0x0040;
pub const RDW_ALLCHILDREN: u32 = 0x0080;
pub const RDW_UPDATENOW: u32 = 0x0100;
pub const RDW_ERASENOW: u32 = 0x0200;
pub const RDW_FRAME: u32 = 0x0400;
pub const RDW_NOFRAME: u32 = 0x0800;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PaintDamage {
    pub region: PaintRegion,
    pub internal: bool,
    pub erase: bool,
    pub nonclient: bool,
    pub delayed_erase: bool,
}

impl PaintDamage {
    /// Paint message readiness excludes erase-only state. # C: O(1)
    pub fn pending(&self) -> bool { self.internal || !self.region.is_empty() }
    /// Snapshot without infallible allocation. # C: O(N_rects)
    pub fn try_copy(&self) -> Result<Self, WindowError> {
        Ok(Self { region: self.region.try_copy()?, internal: self.internal,
            erase: self.erase, nonclient: self.nonclient, delayed_erase: self.delayed_erase })
    }
    /// Apply already-coordinate-mapped coverage atomically; None means entire applicable area.
    /// Frame/client bounds are both expressed in client coordinates. # C: O(N_rects²)
    pub fn apply(&mut self, input: Option<&PaintRegion>, client: WindowRect, frame: WindowRect,
        flags: u32, nested: bool) -> Result<(), WindowError> {
        let mut next = self.try_copy()?;
        if flags & RDW_INVALIDATE != 0 {
            let bounds = if flags & RDW_FRAME != 0 { frame } else { client };
            let coverage = match input { Some(region) => region.clipped(bounds)?, None => PaintRegion::from_rect(bounds)? };
            next.region.union(&coverage)?;
            if flags & RDW_FRAME != 0 { next.nonclient = true; }
            if flags & RDW_ERASE != 0 { next.erase = true; }
        } else if flags & RDW_VALIDATE != 0 {
            if input.is_none() && flags & RDW_NOFRAME != 0 {
                next.region = PaintRegion::default();
                next.erase = false; next.delayed_erase = false; next.nonclient = false;
            } else if !next.region.is_empty() {
                let bounds = if nested { frame } else { client };
                let coverage = match input { Some(region) => region.clipped(bounds)?, None => PaintRegion::from_rect(bounds)? };
                next.region.subtract(&coverage)?;
                if flags & RDW_NOFRAME != 0 { next.region = next.region.clipped(client)?; next.nonclient = false; }
                if flags & RDW_NOERASE != 0 { next.erase = false; next.delayed_erase = false; }
            }
        }
        if flags & RDW_INTERNALPAINT != 0 { next.internal = true; }
        else if flags & RDW_NOINTERNALPAINT != 0 { next.internal = false; }
        if next.region.is_empty() { next.erase = false; next.delayed_erase = false; next.nonclient = false; }
        *self = next; Ok(())
    }
}
