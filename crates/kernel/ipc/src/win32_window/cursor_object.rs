//! Cursor and icon objects: the frames, hotspot and resource identity behind
//! one HCURSOR/HICON.
//!
//! A handle is allocated empty, then filled once with a frame description.
//! A second fill of the same handle is refused, an animated object owns one
//! child handle per sequence step, and a shared object loaded from a module
//! resource answers the same handle to a later lookup of the same resource.

use alloc::vec::Vec;
use super::WindowError;

/// First handle handed out for a cursor or icon object. Cursor handles share
/// no numbering with window handles, so a stray HCURSOR can never name a window.
pub const OEM_CURSOR_BASE: u64 = 0x0001_0000;
const MAX_OBJECTS: usize = 4096;
/// Sequence steps one animated object may own.
pub const MAX_ANI_STEPS: usize = 256;
/// LR_SHARED: the object joins the module/resource cache and survives destroy.
pub const LR_SHARED: u32 = 0x8000;

/// One frame's bitmaps and hotspot, in the layout the icon drawing path reads.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CursorFrame {
    pub width: i32, pub height: i32,
    pub hotspot_x: i32, pub hotspot_y: i32,
    pub color: u64, pub mask: u64, pub alpha: u64,
}

/// One fill request: a static object carries exactly one frame; an animated
/// object carries `num_frames` distinct frames replayed over `num_steps` steps.
pub struct CursorIconDesc<'a> {
    pub delay: u32,
    pub num_steps: u32,
    pub num_frames: u32,
    pub frames: &'a [CursorFrame],
    pub frame_seq: &'a [u32],
    pub frame_rates: &'a [u32],
    pub flags: u32,
    pub rsrc: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Object {
    handle: u64,
    is_icon: bool,
    is_shared: bool,
    is_ani: bool,
    filled: bool,
    delay: u32,
    param: u64,
    module: Vec<u16>,
    /// Resource name for a string resource; `res_id` carries an integer one.
    resname: Vec<u16>,
    res_id: Option<u16>,
    rsrc: u64,
    frame: CursorFrame,
    frames: Vec<u64>,
    num_frames: u32,
    /// OEM resource id when this object was loaded by `shared_oem_cursor`.
    oem: Option<u32>,
}

/// Per-process cursor and icon object table.
#[derive(Default)]
pub struct CursorIcons { objects: Vec<Object>, next: u64 }

/// What `NtUserGetIconInfo` answers about one object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IconInfo { pub is_icon: bool, pub hotspot_x: i32, pub hotspot_y: i32, pub color: u64, pub mask: u64 }

/// What `NtUserGetCursorFrameInfo` answers: the frame handle for one step,
/// its display rate in jiffies, and the sequence length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameInfo { pub cursor: u64, pub rate_jiffies: u32, pub num_steps: u32 }

/// A single-frame sequence reports itself as endless rather than as one step.
const ENDLESS_STEPS: u32 = u32::MAX;

impl CursorIcons {
    /// # C: O(1)
    pub const fn new() -> Self { Self { objects: Vec::new(), next: OEM_CURSOR_BASE } }

    fn index(&self, handle: u64) -> Option<usize> { self.objects.iter().position(|object| object.handle == handle) }

    /// Allocate an empty object; the caller fills it with `set_data`. # C: O(1)
    pub fn alloc(&mut self, is_icon: bool) -> Result<u64, WindowError> {
        if self.objects.len() >= MAX_OBJECTS { return Err(WindowError::NoMemory); }
        self.objects.try_reserve(1).map_err(|_| WindowError::NoMemory)?;
        let handle = self.next;
        self.next = self.next.checked_add(1).ok_or(WindowError::NoMemory)?;
        self.objects.push(Object { handle, is_icon, is_shared: false, is_ani: false, filled: false,
            delay: 0, param: 0, module: Vec::new(), resname: Vec::new(), res_id: None, rsrc: 0,
            frame: CursorFrame::default(), frames: Vec::new(), num_frames: 0, oem: None });
        Ok(handle)
    }

    /// # C: O(N_objects)
    pub fn contains(&self, handle: u64) -> bool { self.index(handle).is_some() }

    /// # C: O(N_objects)
    pub fn is_icon(&self, handle: u64) -> Option<bool> { self.index(handle).map(|index| self.objects[index].is_icon) }

    /// Object holding the frame data for one sequence step: the object itself
    /// when static, its step child when animated, and nothing when the step is
    /// past the sequence. # C: O(N_objects)
    fn frame_index(&self, handle: u64, step: u32) -> Option<usize> {
        let index = self.index(handle)?;
        let object = &self.objects[index];
        if !object.is_ani { return Some(index); }
        let child = *object.frames.get(step as usize)?;
        self.index(child)
    }

    /// Fill one empty object. A second fill is refused, matching the reference's
    /// invalid-cursor-handle rejection of an already initialized object.
    /// # C: O(N_objects * N_steps)
    pub fn set_data(&mut self, handle: u64, module: &[u16], res_name: Option<&[u16]>, res_id: Option<u16>,
        desc: &CursorIconDesc<'_>) -> Result<(), WindowError> {
        let index = self.index(handle).ok_or(WindowError::NoSuchWindow)?;
        if self.objects[index].is_ani || self.objects[index].filled { return Err(WindowError::InvalidParent); }
        if desc.num_steps as usize > MAX_ANI_STEPS { return Err(WindowError::NoMemory); }
        if desc.num_steps == 0 && desc.frames.is_empty() { return Err(WindowError::InvalidParent); }
        if desc.num_steps != 0 && desc.num_frames == 0 { return Err(WindowError::InvalidParent); }
        let is_icon = self.objects[index].is_icon;
        let children = self.build_steps(is_icon, desc)?;
        let object = &mut self.objects[index];
        object.delay = desc.delay;
        object.filled = true;
        if children.is_empty() { object.frame = desc.frames[0]; } else {
            object.is_ani = true;
            object.num_frames = desc.num_frames;
            object.frames = children;
        }
        object.module.try_reserve_exact(module.len()).map_err(|_| WindowError::NoMemory)?;
        object.module.extend_from_slice(module);
        object.res_id = res_id;
        if let Some(name) = res_name {
            object.resname.try_reserve_exact(name.len()).map_err(|_| WindowError::NoMemory)?;
            object.resname.extend_from_slice(name);
        }
        if desc.flags & LR_SHARED != 0 {
            object.is_shared = true;
            if !object.module.is_empty() { object.rsrc = desc.rsrc; }
        }
        Ok(())
    }

    /// Materialize one child object per sequence step, resolving the sequence
    /// table and the per-step rate. Empty for a static object. # C: O(N_steps²)
    fn build_steps(&mut self, is_icon: bool, desc: &CursorIconDesc<'_>) -> Result<Vec<u64>, WindowError> {
        if desc.num_steps == 0 { return Ok(Vec::new()); }
        let mut children = Vec::new();
        children.try_reserve_exact(desc.num_steps as usize).map_err(|_| WindowError::NoMemory)?;
        for step in 0..desc.num_steps as usize {
            // A sequence entry past the frame list names the last frame, as the
            // reference does for a corrupt sequence table.
            let requested = desc.frame_seq.get(step).copied().unwrap_or(step as u32);
            let frame_id = requested.min(desc.num_frames.saturating_sub(1)) as usize;
            let frame = *desc.frames.get(frame_id).ok_or(WindowError::InvalidParent)?;
            let rate = desc.frame_rates.get(step).copied().unwrap_or(desc.delay);
            let child = self.alloc(is_icon)?;
            let child_index = self.index(child).ok_or(WindowError::NoSuchWindow)?;
            let object = &mut self.objects[child_index];
            object.frame = frame;
            object.delay = rate;
            object.filled = true;
            children.push(child);
        }
        Ok(children)
    }

    /// Shared object previously loaded from the same module and resource.
    /// # C: O(N_objects * N_module)
    pub fn find_existing(&self, module: &[u16], rsrc: u64) -> Option<u64> {
        self.objects.iter().find(|object| object.is_shared && object.module == module && object.rsrc == rsrc)
            .map(|object| object.handle)
    }

    /// # C: O(N_objects)
    pub fn icon_info(&self, handle: u64) -> Option<IconInfo> {
        let index = self.index(handle)?;
        let frame = &self.objects[self.frame_index(handle, 0)?].frame;
        Some(IconInfo { is_icon: self.objects[index].is_icon, hotspot_x: frame.hotspot_x,
            hotspot_y: frame.hotspot_y, color: frame.color, mask: frame.mask })
    }

    /// Module name and resource identity of one object. # C: O(N_objects)
    pub fn resource(&self, handle: u64) -> Option<(&[u16], &[u16], Option<u16>)> {
        let object = self.objects.get(self.index(handle)?)?;
        Some((&object.module, &object.resname, object.res_id))
    }

    /// The reference answers the mask height, which stacks the AND and XOR
    /// halves, so an icon reports twice its frame height. # C: O(N_objects)
    pub fn icon_size(&self, handle: u64, step: u32) -> Option<(i32, i32)> {
        let frame = &self.objects[self.frame_index(handle, step)?].frame;
        Some((frame.width, frame.height.saturating_mul(2)))
    }

    /// # C: O(N_objects)
    pub fn frame(&self, handle: u64, step: u32) -> Option<CursorFrame> {
        Some(self.objects[self.frame_index(handle, step)?].frame)
    }

    /// # C: O(N_objects)
    pub fn frame_info(&self, handle: u64, step: u32) -> Option<FrameInfo> {
        let index = self.index(handle)?;
        let object = &self.objects[index];
        let icon_steps = if object.is_ani { object.frames.len() as u32 } else { 1 };
        if object.is_ani && step >= icon_steps { return None; }
        let icon_frames = if object.is_ani { object.num_frames } else { 1 };
        let cursor = if object.is_ani && icon_frames > 1 { object.frames[step as usize] } else { handle };
        if icon_frames == 1 { return Some(FrameInfo { cursor, rate_jiffies: 0, num_steps: 1 }); }
        if icon_steps == 1 { return Some(FrameInfo { cursor, rate_jiffies: object.delay, num_steps: ENDLESS_STEPS }); }
        let child = self.index(object.frames[step as usize])?;
        Some(FrameInfo { cursor, rate_jiffies: self.objects[child].delay, num_steps: icon_steps })
    }

    /// Free one object and every step child it owns. A shared object is kept.
    /// # C: O(N_objects * N_steps)
    pub fn destroy(&mut self, handle: u64) -> bool {
        let Some(index) = self.index(handle) else { return false; };
        if self.objects[index].is_shared { return true; }
        let children = core::mem::take(&mut self.objects[index].frames);
        for child in children { if let Some(position) = self.index(child) { self.objects.remove(position); } }
        if let Some(position) = self.index(handle) { self.objects.remove(position); }
        true
    }

    /// # C: O(N_objects)
    pub fn param(&self, handle: u64) -> u64 { self.index(handle).map_or(0, |index| self.objects[index].param) }

    /// Install the opaque client parameter and answer the previous one.
    /// # C: O(N_objects)
    pub fn set_param(&mut self, handle: u64, param: u64) -> u64 {
        let Some(index) = self.index(handle) else { return 0; };
        core::mem::replace(&mut self.objects[index].param, param)
    }

    /// Handle a previous shared load of the same OEM resource id produced.
    /// # C: O(N_objects)
    pub fn oem(&self, id: u32) -> Option<u64> {
        self.objects.iter().find(|object| object.oem == Some(id)).map(|object| object.handle)
    }

    /// # C: O(N_objects)
    pub fn oem_id(&self, handle: u64) -> Option<u32> { self.objects.get(self.index(handle)?)?.oem }

    /// Record one object as the shared load of an OEM resource id. # C: O(N_objects)
    pub fn mark_oem(&mut self, handle: u64, id: u32) -> Result<(), WindowError> {
        let index = self.index(handle).ok_or(WindowError::NoSuchWindow)?;
        self.objects[index].oem = Some(id);
        self.objects[index].is_shared = true;
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/cursor_object.rs"]
mod tests;
