use std::collections::{BTreeMap, VecDeque};
use std::ffi::CString;
use std::ptr;

use crate::ffi;
use crate::geometry::{MonitorSnapshot, Rect};
use crate::keyboard::{evdev_x11_scan, key_flags, keysym_to_vk};
use crate::protocol::{validate_title, BridgeCommand, BridgeEvent, Frame, InputEvent, NativeTransport, TransportError};

pub type Xid = u32;
#[path = "caret/x11.rs"]
mod caret;
#[path = "visibility.rs"]
mod visibility;

#[derive(Debug)]
pub enum BackendError { DisplayUnavailable, X11, InvalidCommand, Transport(TransportError) }

struct Window { xid: Xid, parent: Xid, gc: ffi::Gcontext, rect: Rect, width: u32, height: u32, requested_visible: bool, suppress_backing_configure: bool, last_frame: Option<Frame>, caret: crate::caret::Surface }

pub struct Backend { conn: *mut ffi::Connection, keymap: *mut ffi::XkbKeymap, state: *mut ffi::XkbState, context: *mut ffi::XkbContext, max_request_bytes: usize, root: Xid, visual: ffi::Visualid, depth: u8, screen: Rect, atoms: Atoms, windows: BTreeMap<u32, Window>, xid_to_hwnd: BTreeMap<Xid, u32>, down_keys: BTreeMap<u8, bool>, pending: VecDeque<BridgeEvent> }

#[derive(Clone, Copy)] struct Atoms { wm_protocols: ffi::Atom, wm_delete: ffi::Atom, wm_transient_for: ffi::Atom, net_wm_name: ffi::Atom, utf8_string: ffi::Atom, net_workarea: ffi::Atom, net_current_desktop: ffi::Atom, net_active_window: ffi::Atom, net_wm_state: ffi::Atom, net_wm_state_above: ffi::Atom }

impl Drop for Backend { fn drop(&mut self) { if !self.state.is_null() { unsafe { ffi::xkb_state_unref(self.state); } } if !self.keymap.is_null() { unsafe { ffi::xkb_keymap_unref(self.keymap); } } if !self.context.is_null() { unsafe { ffi::xkb_context_unref(self.context); } } if !self.conn.is_null() { unsafe { ffi::xcb_disconnect(self.conn); } } } }

impl Backend {
    pub fn xid_for(&self, hwnd: u32) -> Option<Xid> { self.windows.get(&hwnd).map(|window| window.xid) }
    #[cfg(test)]
    pub(crate) fn parent_xid_for(&self, hwnd: u32) -> Option<Xid> { self.windows.get(&hwnd).map(|window| window.parent) }
    #[cfg(test)]
    pub(crate) fn transient_xid_for(&self, hwnd: u32) -> Option<Xid> {
        let xid = self.windows.get(&hwnd)?.xid;
        self.property_u32s_typed(xid, self.atoms.wm_transient_for, ffi::ATOM_WINDOW)?.first().copied()
    }
    #[cfg(test)]
    pub(crate) fn window_layout_for_test(&self, hwnd: u32) -> Option<(bool, u32, u32)> { self.windows.get(&hwnd).map(|window| (window.requested_visible, window.width, window.height)) }
    #[cfg(test)]
    pub(crate) fn map_input_for_test(&mut self, input: InputEvent) -> Option<BridgeEvent> { self.map_input(input) }
    #[cfg(test)]
    pub(crate) fn pending_event_for_test(&mut self) -> Option<BridgeEvent> { self.pending.pop_front() }
    /// Name the connect stage that is taking the time. Startup is a series of
    /// synchronous X round trips and the bridge handshake is bounded, so when
    /// it does not finish, which round trip is outstanding is the diagnosis.
    fn stage(start: std::time::Instant, name: &str) {
        eprintln!("windows-compositor: connect stage {name} at {}ms", start.elapsed().as_millis());
    }

    pub fn connect(display: Option<&str>) -> Result<Self, BackendError> {
        let started = std::time::Instant::now();
        Self::stage(started, "begin");
        let display = display.map(CString::new).transpose().map_err(|_| BackendError::DisplayUnavailable)?;
        let mut screen_no = 0;
        let conn = unsafe { ffi::xcb_connect(display.as_ref().map_or(ptr::null(), |v| v.as_ptr()), &mut screen_no) };
        if conn.is_null() || unsafe { ffi::xcb_connection_has_error(conn) } != 0 { if !conn.is_null() { unsafe { ffi::xcb_disconnect(conn); } } return Err(BackendError::DisplayUnavailable); }
        Self::stage(started, "xcb-connected");
        let setup = unsafe { ffi::xcb_get_setup(conn) };
        let mut it = unsafe { ffi::xcb_setup_roots_iterator(setup) };
        for _ in 0..screen_no { unsafe { ffi::xcb_screen_next(&mut it); } }
        if it.data.is_null() { unsafe { ffi::xcb_disconnect(conn); } return Err(BackendError::X11); }
        let screen = unsafe { &*it.data };
        let atoms = Atoms {
            wm_protocols: intern(conn, "WM_PROTOCOLS")?, wm_delete: intern(conn, "WM_DELETE_WINDOW")?, wm_transient_for: intern(conn, "WM_TRANSIENT_FOR")?,
            net_wm_name: intern(conn, "_NET_WM_NAME")?, utf8_string: intern(conn, "UTF8_STRING")?,
            net_workarea: intern(conn, "_NET_WORKAREA")?, net_current_desktop: intern(conn, "_NET_CURRENT_DESKTOP")?,
            net_active_window: intern(conn, "_NET_ACTIVE_WINDOW")?, net_wm_state: intern(conn, "_NET_WM_STATE")?, net_wm_state_above: intern(conn, "_NET_WM_STATE_ABOVE")?,
        };
        Self::stage(started, "atoms-interned");
        let root = screen.root;
        let screen_rect = Rect { left: 0, top: 0, right: screen.width_in_pixels as i32, bottom: screen.height_in_pixels as i32 };
        let root_events = [ffi::EVENT_PROPERTY_CHANGE];
        unsafe { ffi::xcb_change_window_attributes(conn, root, ffi::CW_EVENT_MASK, root_events.as_ptr()); ffi::xcb_flush(conn); }
        let context = unsafe { ffi::xkb_context_new(0) }; if context.is_null() { unsafe { ffi::xcb_disconnect(conn); } return Err(BackendError::X11); }
        let mut major = 0; let mut minor = 0; let mut base_event = 0; let mut base_error = 0;
        if unsafe { ffi::xkb_x11_setup_xkb_extension(conn, 1, 0, 0, &mut major, &mut minor, &mut base_event, &mut base_error) } == 0 { unsafe { ffi::xkb_context_unref(context); ffi::xcb_disconnect(conn); } return Err(BackendError::X11); }
        Self::stage(started, "xkb-extension");
        let device = unsafe { ffi::xkb_x11_get_core_keyboard_device_id(conn) }; if device < 0 { unsafe { ffi::xkb_context_unref(context); ffi::xcb_disconnect(conn); } return Err(BackendError::X11); }
        let keymap = unsafe { ffi::xkb_x11_keymap_new_from_device(context, conn, device, 0) }; if keymap.is_null() { unsafe { ffi::xkb_context_unref(context); ffi::xcb_disconnect(conn); } return Err(BackendError::X11); }
        let state = unsafe { ffi::xkb_x11_state_new_from_device(keymap, conn, device) };
        if state.is_null() { unsafe { ffi::xkb_keymap_unref(keymap); ffi::xkb_context_unref(context); ffi::xcb_disconnect(conn); } return Err(BackendError::X11); }
        Self::stage(started, "keymap-ready");
        let max_request_bytes = (unsafe { ffi::xcb_get_maximum_request_length(conn) } as usize).saturating_mul(4).min(64 * 1024);
        Ok(Self { conn, keymap, state, context, max_request_bytes, root, visual: screen.root_visual, depth: screen.root_depth, screen: screen_rect, atoms, windows: BTreeMap::new(), xid_to_hwnd: BTreeMap::new(), down_keys: BTreeMap::new(), pending: VecDeque::new() })
    }

    /// `_NET_CURRENT_DESKTOP` and `_NET_WORKAREA` are published by a window
    /// manager and are optional. GNOME's XWayland server exposes neither, so
    /// requiring them made the bridge unusable on the very desktop it targets.
    /// With no published work area the whole screen is the work area, which is
    /// the answer X itself always has. Only a screen with no geometry at all
    /// is a real absence.
    pub fn monitor_snapshot(&self) -> Option<MonitorSnapshot> {
        if self.screen.right <= self.screen.left || self.screen.bottom <= self.screen.top { return None; }
        let desktop = self.property_u32(self.root, self.atoms.net_current_desktop).unwrap_or(0);
        let work_area = match self.property_u32s(self.root, self.atoms.net_workarea) {
            // A published work area must decode. A window manager emitting a
            // malformed one is a real fault and is not papered over.
            Some(values) => crate::geometry::decode_work_area(&values, desktop)?,
            // Publishing none is normal, and a later property change replaces
            // this with the real one the moment a window manager sets it.
            None => self.screen,
        };
        Some(MonitorSnapshot { desktop, monitor: self.screen, work_area })
    }
    #[cfg(test)]
    pub(crate) fn seed_test_ewmh(&self) { let desktop = [0u32]; let area = [0u32, 0, 320, 220]; unsafe { ffi::xcb_change_property(self.conn, ffi::PROP_MODE_REPLACE, self.root, self.atoms.net_current_desktop, ffi::ATOM_CARDINAL, 32, 1, desktop.as_ptr() as *const _); ffi::xcb_change_property(self.conn, ffi::PROP_MODE_REPLACE, self.root, self.atoms.net_workarea, ffi::ATOM_CARDINAL, 32, 4, area.as_ptr() as *const _); ffi::xcb_flush(self.conn); } }
    pub fn handle_command(&mut self, command: BridgeCommand) -> Result<Vec<BridgeEvent>, BackendError> {
        match command {
            BridgeCommand::Create { hwnd, title, rect, parent, style, ex_style } => { validate_title(&title).map_err(BackendError::Transport)?; self.create(hwnd, &title, rect, parent, style, ex_style)?; Ok(self.snapshot_event().into_iter().collect()) }
            BridgeCommand::Show { hwnd } => { self.show(hwnd)?; Ok(Vec::new()) }
            BridgeCommand::Hide { hwnd } => { let window = self.windows.get_mut(&hwnd).ok_or(BackendError::InvalidCommand)?; window.requested_visible = false; unsafe { ffi::xcb_unmap_window(self.conn, window.xid); ffi::xcb_flush(self.conn); } Ok(Vec::new()) }
            BridgeCommand::SetTitle { hwnd, title } => { validate_title(&title).map_err(BackendError::Transport)?; let window = self.windows.get(&hwnd).ok_or(BackendError::InvalidCommand)?; let text = String::from_utf16_lossy(&title); unsafe { ffi::xcb_change_property(self.conn, ffi::PROP_MODE_REPLACE, window.xid, self.atoms.net_wm_name, self.atoms.utf8_string, 8, text.len() as u32, text.as_ptr() as *const _); ffi::xcb_flush(self.conn); } Ok(Vec::new()) }
            BridgeCommand::Configure { hwnd, rect } => { let window = self.windows.get_mut(&hwnd).ok_or(BackendError::InvalidCommand)?; let width = u32::try_from(rect.right - rect.left).map_err(|_| BackendError::InvalidCommand)?; let height = u32::try_from(rect.bottom - rect.top).map_err(|_| BackendError::InvalidCommand)?; let x_width = width.max(1); let x_height = height.max(1); let values = [rect.left as u32, rect.top as u32, x_width, x_height]; unsafe { ffi::xcb_configure_window(self.conn, window.xid, ffi::CONFIGURE_X | ffi::CONFIGURE_Y | ffi::CONFIGURE_WIDTH | ffi::CONFIGURE_HEIGHT, values.as_ptr()); if width == 0 || height == 0 || !window.requested_visible { ffi::xcb_unmap_window(self.conn, window.xid); } else { ffi::xcb_map_window(self.conn, window.xid); } ffi::xcb_flush(self.conn); } window.rect = rect; window.width = width; window.height = height; window.suppress_backing_configure = width == 0 || height == 0; Ok(Vec::new()) }
            BridgeCommand::Frame { hwnd, frame } => { self.present(hwnd, &frame)?; Ok(Vec::new()) }
            BridgeCommand::Position { hwnd, insertion, activate } => { self.position(hwnd, insertion, activate)?; Ok(Vec::new()) }
            BridgeCommand::Caret { hwnd, snapshot } => { self.update_caret(hwnd, snapshot)?; Ok(Vec::new()) }
            BridgeCommand::Destroy { hwnd } => { self.destroy(hwnd)?; Ok(Vec::new()) }
        }
    }

    /// Apply Curie's canonical insertion value: None=no reorder, 0=Top,
    /// 1=Bottom, MAX=Topmost, MAX-1=NotTopmost, otherwise an HWND sibling.
    /// Activation is an EWMH request; success means X accepted the request,
    /// not that a window manager has already granted focus.
    pub fn position(&mut self, hwnd: u32, insertion: Option<u64>, activate: bool) -> Result<(), BackendError> {
        let (xid, parent) = { let window = self.windows.get(&hwnd).ok_or(BackendError::InvalidCommand)?; (window.xid, window.parent) };
        if let Some(order) = insertion {
            match order {
                0 => self.restack(xid, None, ffi::STACK_ABOVE)?,
                1 => self.restack(xid, None, ffi::STACK_BELOW)?,
                u64::MAX => { self.set_topmost(xid, parent == self.root, true)?; self.restack(xid, None, ffi::STACK_ABOVE)?; },
                value if value == u64::MAX - 1 => { self.set_topmost(xid, parent == self.root, false)?; self.restack(xid, None, ffi::STACK_ABOVE)?; },
                sibling_hwnd => {
                    let sibling = u32::try_from(sibling_hwnd).map_err(|_| BackendError::InvalidCommand)?;
                    let sibling_xid = self.windows.get(&sibling).ok_or(BackendError::InvalidCommand)?.xid;
                    if self.windows.get(&sibling).map(|window| window.parent) != Some(parent) { return Err(BackendError::InvalidCommand); }
                    self.restack(xid, Some(sibling_xid), ffi::STACK_ABOVE)?;
                }
            }
        }
        if activate && parent == self.root { self.request_activation(xid)?; }
        unsafe { ffi::xcb_flush(self.conn); }
        Ok(())
    }

    fn restack(&self, xid: Xid, sibling: Option<Xid>, mode: u32) -> Result<(), BackendError> {
        let mut values = [0u32; 2]; let mask = if let Some(sibling) = sibling { values[0] = sibling; values[1] = mode; ffi::CONFIGURE_SIBLING | ffi::CONFIGURE_STACK_MODE } else { values[0] = mode; ffi::CONFIGURE_STACK_MODE };
        let error = unsafe { ffi::xcb_request_check(self.conn, ffi::xcb_configure_window_checked(self.conn, xid, mask, values.as_ptr())) };
        if error.is_null() { Ok(()) } else { unsafe { libc::free(error as *mut _); } Err(BackendError::X11) }
    }

    fn set_topmost(&self, xid: Xid, top_level: bool, enabled: bool) -> Result<(), BackendError> {
        if !top_level { return Ok(()); }
        let mut event = [0u8; 32]; event[0] = ffi::CLIENT_MESSAGE; event[1] = 32; event[4..8].copy_from_slice(&xid.to_ne_bytes()); event[8..12].copy_from_slice(&self.atoms.net_wm_state.to_ne_bytes()); event[12..16].copy_from_slice(&(if enabled { 1u32 } else { 0u32 }).to_ne_bytes()); event[16..20].copy_from_slice(&self.atoms.net_wm_state_above.to_ne_bytes());
        let error = unsafe { ffi::xcb_request_check(self.conn, ffi::xcb_send_event(self.conn, 0, self.root, ffi::SUBSTRUCTURE_REDIRECT | ffi::SUBSTRUCTURE_NOTIFY, event.as_ptr() as *const i8)) };
        if error.is_null() { Ok(()) } else { unsafe { libc::free(error as *mut _); } Err(BackendError::X11) }
    }

    fn request_activation(&self, xid: Xid) -> Result<(), BackendError> {
        let mut event = [0u8; 32]; event[0] = ffi::CLIENT_MESSAGE; event[1] = 32; event[4..8].copy_from_slice(&xid.to_ne_bytes()); event[8..12].copy_from_slice(&self.atoms.net_active_window.to_ne_bytes()); event[12..16].copy_from_slice(&2u32.to_ne_bytes());
        let error = unsafe { ffi::xcb_request_check(self.conn, ffi::xcb_send_event(self.conn, 0, self.root, ffi::SUBSTRUCTURE_REDIRECT | ffi::SUBSTRUCTURE_NOTIFY, event.as_ptr() as *const i8)) };
        if error.is_null() { Ok(()) } else { unsafe { libc::free(error as *mut _); } Err(BackendError::X11) }
    }

    pub fn poll_event(&mut self) -> Option<BridgeEvent> {
        if let Some(event) = self.pending.pop_front() { return Some(event); }
        let raw = unsafe { ffi::xcb_poll_for_event(self.conn) };
        if raw.is_null() { return None; }
        let bytes = unsafe { std::slice::from_raw_parts(raw as *const u8, 32) };
        let expose = if bytes[0] & 0x7f == ffi::EXPOSE { Some((u32::from_ne_bytes(bytes[4..8].try_into().ok()?), Rect { left: u16::from_ne_bytes([bytes[8], bytes[9]]) as i32, top: u16::from_ne_bytes([bytes[10], bytes[11]]) as i32, right: u16::from_ne_bytes([bytes[8], bytes[9]]) as i32 + u16::from_ne_bytes([bytes[12], bytes[13]]) as i32, bottom: u16::from_ne_bytes([bytes[10], bytes[11]]) as i32 + u16::from_ne_bytes([bytes[14], bytes[15]]) as i32 })) } else { None };
        let event = if bytes[0] & 0x7f == ffi::CLIENT_MESSAGE {
            let type_atom = u32::from_ne_bytes(bytes[8..12].try_into().ok()?);
            let protocol = u32::from_ne_bytes(bytes[12..16].try_into().ok()?);
            if type_atom == self.atoms.wm_protocols && protocol == self.atoms.wm_delete { decode_event(bytes) } else { None }
        } else { decode_event(bytes) };
        unsafe { libc::free(raw as *mut libc::c_void); }
        if let Some((xid, rect)) = expose {
            if let Some(hwnd) = self.xid_to_hwnd.get(&xid).copied() { let _ = self.repaint(hwnd, rect); }
            return None;
        }
        match event {
            Some(BridgeEvent::Close { hwnd: xid }) => self.xid_to_hwnd.get(&xid).copied().map(|hwnd| BridgeEvent::Close { hwnd }),
            Some(BridgeEvent::Configure { hwnd: xid, rect }) => {
                let hwnd = self.xid_to_hwnd.get(&xid).copied()?;
                let window = self.windows.get_mut(&hwnd)?;
                if window.suppress_backing_configure && rect.right - rect.left <= 1 && rect.bottom - rect.top <= 1 { window.suppress_backing_configure = false; None } else { Some(BridgeEvent::Configure { hwnd, rect }) }
            }
            Some(BridgeEvent::Input(input)) => self.map_input(input),
            Some(BridgeEvent::WorkArea(_)) => self.snapshot_event(),
            other => other,
        }
    }

    pub fn run_once<T: NativeTransport>(&mut self, transport: &mut T) -> Result<bool, BackendError> {
        if let Some(event) = self.poll_event() { self.send_event(transport, event)?; return Ok(true); }
        let Some(inbound) = transport.recv().map_err(BackendError::Transport)? else { return Ok(false); };
        let result = self.handle_command(inbound.command);
        match result {
            Ok(events) => { for event in events { self.send_event(transport, event)?; } self.send_event(transport, BridgeEvent::Ack { sequence: inbound.sequence, hwnd: inbound.hwnd, status: 0 })?; }
            Err(_) => { self.send_event(transport, BridgeEvent::Ack { sequence: inbound.sequence, hwnd: inbound.hwnd, status: 1 })?; }
        }
        Ok(true)
    }

    fn send_event<T: NativeTransport>(&self, transport: &mut T, event: BridgeEvent) -> Result<(), BackendError> {
        transport.send(event).map_err(BackendError::Transport)
    }

    fn create(&mut self, hwnd: u32, title: &[u16], rect: Rect, parent: u64, style: u32, _ex_style: u32) -> Result<(), BackendError> {
        const WS_CHILD: u32 = 0x4000_0000; const WS_POPUP: u32 = 0x8000_0000; const WS_VISIBLE: u32 = 0x1000_0000;
        let width = u32::try_from(rect.right - rect.left).map_err(|_| BackendError::InvalidCommand)?; let height = u32::try_from(rect.bottom - rect.top).map_err(|_| BackendError::InvalidCommand)?;
        if self.windows.contains_key(&hwnd) || width > u16::MAX as u32 || height > u16::MAX as u32 { return Err(BackendError::InvalidCommand); }
        // WS_POPUP takes precedence when both bits are present.  Such a
        // window is an owned top-level surface, not an X child; the owner is
        // represented by WM_TRANSIENT_FOR below.
        let is_child = style & (WS_CHILD | WS_POPUP) == WS_CHILD;
        let (x_parent, x, y) = if is_child { let parent_hwnd = u32::try_from(parent).map_err(|_| BackendError::InvalidCommand)?; let parent_window = self.windows.get(&parent_hwnd).ok_or(BackendError::InvalidCommand)?; (parent_window.xid, rect.left, rect.top) } else { (self.root, rect.left, rect.top) };
        let xid = unsafe { ffi::xcb_generate_id(self.conn) }; let gc = unsafe { ffi::xcb_generate_id(self.conn) };
        let values = [ffi::EVENT_KEY_PRESS | ffi::EVENT_KEY_RELEASE | ffi::EVENT_BUTTON_PRESS | ffi::EVENT_BUTTON_RELEASE | ffi::EVENT_POINTER_MOTION | ffi::EVENT_EXPOSURE | ffi::EVENT_STRUCTURE_NOTIFY | ffi::EVENT_FOCUS_CHANGE];
        unsafe { ffi::xcb_create_window(self.conn, self.depth, xid, x_parent, x as i16, y as i16, width.max(1) as u16, height.max(1) as u16, 0, ffi::WINDOW_CLASS_INPUT_OUTPUT, self.visual, 0, ptr::null()); ffi::xcb_create_gc(self.conn, gc, xid, 0, ptr::null()); ffi::xcb_change_window_attributes(self.conn, xid, ffi::CW_EVENT_MASK, values.as_ptr()); }
        let title = String::from_utf16_lossy(title); let bytes = title.as_bytes();
        unsafe { ffi::xcb_change_property(self.conn, ffi::PROP_MODE_REPLACE, xid, self.atoms.net_wm_name, self.atoms.utf8_string, 8, bytes.len() as u32, bytes.as_ptr() as *const _); ffi::xcb_change_property(self.conn, ffi::PROP_MODE_REPLACE, xid, self.atoms.wm_protocols, ffi::ATOM_ATOM, 32, 1, &self.atoms.wm_delete as *const _ as *const _); ffi::xcb_flush(self.conn); }
        if !is_child && style & WS_POPUP != 0 && parent != 0 { let owner = self.windows.get(&u32::try_from(parent).map_err(|_| BackendError::InvalidCommand)?).ok_or(BackendError::InvalidCommand)?.xid; unsafe { ffi::xcb_change_property(self.conn, ffi::PROP_MODE_REPLACE, xid, self.atoms.wm_transient_for, ffi::ATOM_WINDOW, 32, 1, &owner as *const _ as *const _); ffi::xcb_flush(self.conn); } }
        if width == 0 || height == 0 { unsafe { ffi::xcb_unmap_window(self.conn, xid); } }
        let requested_visible = style & WS_VISIBLE != 0;
        if requested_visible && width != 0 && height != 0 { unsafe { ffi::xcb_map_window(self.conn, xid); } }
        self.windows.insert(hwnd, Window { xid, parent: x_parent, gc, rect, width, height, requested_visible, suppress_backing_configure: width == 0 || height == 0, last_frame: None, caret: crate::caret::Surface::default() }); self.xid_to_hwnd.insert(xid, hwnd); Ok(())
    }

    fn present(&mut self, hwnd: u32, frame: &Frame) -> Result<(), BackendError> {
        if self.windows.get(&hwnd).ok_or(BackendError::InvalidCommand)?.width != frame.width || self.windows.get(&hwnd).ok_or(BackendError::InvalidCommand)?.height != frame.height { return Err(BackendError::InvalidCommand); }
        self.windows.get_mut(&hwnd).ok_or(BackendError::InvalidCommand)?.last_frame = Some(frame.clone());
        self.repaint(hwnd, frame.damage)
    }

    fn repaint(&mut self, hwnd: u32, damage: Rect) -> Result<(), BackendError> {
        let window = self.windows.get(&hwnd).ok_or(BackendError::InvalidCommand)?;
        let frame = window.last_frame.as_ref().ok_or(BackendError::InvalidCommand)?;
        if frame.width != window.width || frame.height != window.height { return Err(BackendError::InvalidCommand); }
        let composed = window.caret.compose(frame).map_err(BackendError::Transport)?;
        let bytes = unsafe { std::slice::from_raw_parts(composed.as_ptr() as *const u8, composed.len() * 4) };
        let damage_width = (damage.right - damage.left) as usize; let damage_height = (damage.bottom - damage.top) as usize;
        if damage.left < 0 || damage.top < 0 || damage.right > frame.width as i32 || damage.bottom > frame.height as i32 || damage_width == 0 || damage_height == 0 { return Err(BackendError::InvalidCommand); }
        let payload_limit = self.max_request_bytes.saturating_sub(32).max(4);
        let tile_width = damage_width.min(payload_limit / 4).max(1);
        let tile_height = (payload_limit / tile_width.saturating_mul(4)).max(1);
        for y in (damage.top as usize..damage.bottom as usize).step_by(tile_height) { for x in (damage.left as usize..damage.right as usize).step_by(tile_width) {
            let w = tile_width.min(damage.right as usize - x); let h = tile_height.min(damage.bottom as usize - y); let mut damaged = Vec::with_capacity(w.saturating_mul(h).saturating_mul(4));
            for row in y..y + h { let start = row.checked_mul(frame.stride as usize).and_then(|v| v.checked_add(x)).and_then(|v| v.checked_mul(4)).ok_or(BackendError::InvalidCommand)?; let end = start.checked_add(w.checked_mul(4).ok_or(BackendError::InvalidCommand)?).ok_or(BackendError::InvalidCommand)?; damaged.extend_from_slice(bytes.get(start..end).ok_or(BackendError::InvalidCommand)?); }
            let cookie = unsafe { ffi::xcb_put_image_checked(self.conn, ffi::IMAGE_FORMAT_Z_PIXMAP, window.xid, window.gc, w as u16, h as u16, x as i16, y as i16, 0, self.depth, damaged.len() as u32, damaged.as_ptr()) }; let error = unsafe { ffi::xcb_request_check(self.conn, cookie) }; if !error.is_null() { unsafe { libc::free(error as *mut _); } return Err(BackendError::X11); }
        }
        }
        unsafe { ffi::xcb_flush(self.conn); } Ok(())
    }

    fn destroy(&mut self, hwnd: u32) -> Result<(), BackendError> { let window = self.windows.remove(&hwnd).ok_or(BackendError::InvalidCommand)?; self.xid_to_hwnd.remove(&window.xid); unsafe { ffi::xcb_destroy_window(self.conn, window.xid); ffi::xcb_flush(self.conn); } Ok(()) }
    fn snapshot_event(&self) -> Option<BridgeEvent> { self.monitor_snapshot().map(BridgeEvent::WorkArea) }
    fn property_u32(&self, window: Xid, atom: ffi::Atom) -> Option<u32> { let values = self.property_u32s(window, atom)?; crate::geometry::decode_cardinals(&values) }
    fn property_u32s(&self, window: Xid, atom: ffi::Atom) -> Option<Vec<u32>> { self.property_u32s_typed(window, atom, ffi::ATOM_CARDINAL) }
    fn property_u32s_typed(&self, window: Xid, atom: ffi::Atom, type_: ffi::Atom) -> Option<Vec<u32>> { let cookie = unsafe { ffi::xcb_get_property(self.conn, 0, window, atom, type_, 0, 4) }; let mut error = ptr::null_mut(); let reply = unsafe { ffi::xcb_get_property_reply(self.conn, cookie, &mut error) }; if reply.is_null() { return None; } if unsafe { (*reply).format } != 32 { unsafe { libc::free(reply as *mut _); } return None; } let len = unsafe { ffi::xcb_get_property_value_length(reply) }; if len < 0 || len % 4 != 0 { unsafe { libc::free(reply as *mut _); } return None; } let ptr = unsafe { ffi::xcb_get_property_value(reply) as *const u32 }; let values = unsafe { std::slice::from_raw_parts(ptr, len as usize / 4) }.to_vec(); unsafe { libc::free(reply as *mut _); } Some(values) }
    fn map_input(&mut self, input: InputEvent) -> Option<BridgeEvent> {
        if let InputEvent::Key { hwnd, press, virtual_key: _, scan_code: keycode, modifiers: _state } = input {
            let alt_name = CString::new("Alt").map_err(|_| ()).ok()?;
            let alt = unsafe { ffi::xkb_state_mod_name_is_active(self.state, alt_name.as_ptr(), 1 << 3) } == 1;
            unsafe { ffi::xkb_state_update_key(self.state, keycode as u32, if press { 1 } else { 0 }); }
            let keysym = unsafe { ffi::xkb_state_key_get_one_sym(self.state, keycode as u32) };
            let scan = evdev_x11_scan(keycode as u32)?;
            let layout = unsafe { ffi::xkb_state_key_get_layout(self.state, keycode as u32) };
            let mut base_syms = ptr::null();
            let base_count = unsafe { ffi::xkb_keymap_key_get_syms_by_level(self.keymap, keycode as u32, layout, 0, &mut base_syms) };
            let base_keysym = if base_count > 0 && !base_syms.is_null() { unsafe { *base_syms } } else { keysym };
            let virtual_key = keysym_to_vk(base_keysym).or_else(|| keysym_to_vk(keysym))?;
            let was_down = self.down_keys.get(&keycode).copied().unwrap_or(false);
            let modifiers = key_flags(scan, press, was_down, alt);
            if press { self.down_keys.insert(keycode, true); } else { self.down_keys.remove(&keycode); }
            if press {
                let mut text = [0i8; 32]; let n = unsafe { ffi::xkb_state_key_get_utf8(self.state, keycode as u32, text.as_mut_ptr(), text.len()) };
                if n > 0 { let bytes = unsafe { std::slice::from_raw_parts(text.as_ptr() as *const u8, (n as usize).saturating_add(1).min(text.len())) }; if let Ok(Some(value)) = crate::keyboard::state_utf8(bytes, n, true) { self.pending.push_back(BridgeEvent::Input(InputEvent::Text { hwnd, utf8: value.as_bytes().to_vec() })); } }
            }
            Some(BridgeEvent::Input(InputEvent::Key { hwnd, press, virtual_key, scan_code: scan.code, modifiers }))
        } else { Some(BridgeEvent::Input(input)) }
    }
}

fn intern(conn: *mut ffi::Connection, name: &str) -> Result<ffi::Atom, BackendError> { let name = CString::new(name).map_err(|_| BackendError::X11)?; let cookie = unsafe { ffi::xcb_intern_atom(conn, 0, name.as_bytes().len() as u16, name.as_ptr()) }; let mut error = ptr::null_mut(); let reply = unsafe { ffi::xcb_intern_atom_reply(conn, cookie, &mut error) }; if reply.is_null() { return Err(BackendError::X11); } let atom = unsafe { (*reply).atom }; unsafe { libc::free(reply as *mut _); } Ok(atom) }

pub fn decode_event(raw: &[u8]) -> Option<BridgeEvent> {
    if raw.len() < 32 { return None; }
    let kind = raw[0] & 0x7f;
    let xid = |offset| u32::from_ne_bytes(raw[offset..offset + 4].try_into().ok().unwrap());
    match kind {
        ffi::CLIENT_MESSAGE => Some(BridgeEvent::Close { hwnd: xid(4) }),
        ffi::CONFIGURE_NOTIFY => Some(BridgeEvent::Configure { hwnd: xid(8), rect: Rect { left: i16::from_ne_bytes([raw[16], raw[17]]) as i32, top: i16::from_ne_bytes([raw[18], raw[19]]) as i32, right: i16::from_ne_bytes([raw[16], raw[17]]) as i32 + u16::from_ne_bytes([raw[20], raw[21]]) as i32, bottom: i16::from_ne_bytes([raw[18], raw[19]]) as i32 + u16::from_ne_bytes([raw[22], raw[23]]) as i32 } }),
        ffi::KEY_PRESS | ffi::KEY_RELEASE => Some(BridgeEvent::Input(InputEvent::Key { hwnd: xid(12), press: kind == ffi::KEY_PRESS, virtual_key: 0, scan_code: raw[1], modifiers: u16::from_ne_bytes([raw[28], raw[29]]) as u32 })),
        ffi::BUTTON_PRESS | ffi::BUTTON_RELEASE => Some(BridgeEvent::Input(InputEvent::Button { hwnd: xid(12), press: kind == ffi::BUTTON_PRESS, button: raw[1], x: i16::from_ne_bytes([raw[24], raw[25]]), y: i16::from_ne_bytes([raw[26], raw[27]]), state: u16::from_ne_bytes([raw[28], raw[29]]) })),
        ffi::MOTION_NOTIFY => Some(BridgeEvent::Input(InputEvent::Motion { hwnd: xid(12), x: i16::from_ne_bytes([raw[24], raw[25]]), y: i16::from_ne_bytes([raw[26], raw[27]]), state: u16::from_ne_bytes([raw[28], raw[29]]) })),
        ffi::FOCUS_IN | ffi::FOCUS_OUT => Some(BridgeEvent::Input(InputEvent::Focus { hwnd: xid(4), focused: kind == ffi::FOCUS_IN })),
        ffi::PROPERTY_NOTIFY => Some(BridgeEvent::WorkArea(MonitorSnapshot { desktop: 0, monitor: Rect { left: 0, top: 0, right: 0, bottom: 0 }, work_area: Rect { left: 0, top: 0, right: 0, bottom: 0 } })),
        ffi::EXPOSE => None,
        _ => None,
    }
}
