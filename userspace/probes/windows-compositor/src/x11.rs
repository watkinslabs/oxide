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
#[path = "x11/decode.rs"]
mod decode;
#[path = "x11/position.rs"]
mod position;
#[path = "x11/reparent.rs"]
mod reparent;
#[path = "x11/readback.rs"]
mod readback;
#[path = "x11/retention.rs"]
mod retention;
#[path = "x11/requests.rs"]
pub(crate) mod requests;
pub use decode::decode_event;

#[derive(Debug)]
pub enum BackendError { DisplayUnavailable, X11, InvalidCommand, Transport(TransportError), Wait(std::io::Error) }

struct Window { xid: Xid, parent: Xid, gc: ffi::Gcontext, rect: Rect, width: u32, height: u32, requested_visible: bool, configure_sequence: Option<u32>, surface: Option<crate::retained::Retained>, caret: crate::caret::Surface }

pub struct Backend { readback: readback::State, conn: *mut ffi::Connection, keymap: *mut ffi::XkbKeymap, state: *mut ffi::XkbState, context: *mut ffi::XkbContext, max_request_bytes: usize, root: Xid, visual: ffi::Visualid, depth: u8, screen: Rect, atoms: Atoms, windows: BTreeMap<u32, Window>, xid_to_hwnd: BTreeMap<Xid, u32>, down_keys: BTreeMap<u8, bool>, extra_buttons: u32, pending: VecDeque<BridgeEvent> }

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
    pub(crate) fn retained_for_test(&self, hwnd: u32) -> Option<(Vec<u32>, Vec<Rect>)> { self.windows.get(&hwnd)?.surface.as_ref().map(|s| (s.pixels_for_test(), s.held_for_test())) }
    #[cfg(test)]
    pub(crate) fn pending_event_for_test(&mut self) -> Option<BridgeEvent> { self.pending.pop_front() }
    /// The X connection's socket, so a caller can block on it instead of
    /// asking for events that have not arrived. Events already decoded and
    /// queued inside the library do not make it readable, so a caller drains
    /// `poll_event` to empty before waiting on it.
    ///
    /// # C: O(1)
    pub fn connection_fd(&self) -> std::os::fd::RawFd { unsafe { ffi::xcb_get_file_descriptor(self.conn) } }
    /// Whether the connection can still carry requests. A broken one never
    /// produces another event, so a wait on its descriptor would never end.
    ///
    /// # C: O(1)
    pub fn connected(&self) -> bool { unsafe { ffi::xcb_connection_has_error(self.conn) == 0 } }
    /// Pushes queued requests to the server. A caller that blocks without
    /// doing this waits for a reply to a request still sitting in the
    /// library's output buffer.
    ///
    /// # C: O(1) amortised
    pub fn flush(&self) { unsafe { ffi::xcb_flush(self.conn); } }
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
        Ok(Self { readback: readback::State::default(), conn, keymap, state, context, max_request_bytes, root, visual: screen.root_visual, depth: screen.root_depth, screen: screen_rect, atoms, windows: BTreeMap::new(), xid_to_hwnd: BTreeMap::new(), down_keys: BTreeMap::new(), extra_buttons: 0, pending: VecDeque::new() })
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
            BridgeCommand::Reparent { hwnd, parent, rect } => { self.reparent(hwnd,parent,rect)?; Ok(Vec::new()) }
            BridgeCommand::Show { hwnd } => { self.show(hwnd)?; Ok(Vec::new()) }
            BridgeCommand::Hide { hwnd } => { let window = self.windows.get_mut(&hwnd).ok_or(BackendError::InvalidCommand)?; window.requested_visible = false; unsafe { ffi::xcb_unmap_window(self.conn, window.xid); ffi::xcb_flush(self.conn); } Ok(Vec::new()) }
            BridgeCommand::SetTitle { hwnd, title } => { validate_title(&title).map_err(BackendError::Transport)?; let xid = self.windows.get(&hwnd).ok_or(BackendError::InvalidCommand)?.xid; self.publish_title(xid, &title); Ok(Vec::new()) }
            BridgeCommand::Configure { hwnd, rect } => { let window = self.windows.get_mut(&hwnd).ok_or(BackendError::InvalidCommand)?; let width = u32::try_from(rect.right - rect.left).map_err(|_| BackendError::InvalidCommand)?; let height = u32::try_from(rect.bottom - rect.top).map_err(|_| BackendError::InvalidCommand)?; let (x_width, x_height) = crate::extent::backing((width, height)); let values = [rect.left as u32, rect.top as u32, x_width, x_height]; unsafe { window.configure_sequence = Some(ffi::xcb_configure_window(self.conn, window.xid, ffi::CONFIGURE_X | ffi::CONFIGURE_Y | ffi::CONFIGURE_WIDTH | ffi::CONFIGURE_HEIGHT, values.as_ptr()).sequence); if width == 0 || height == 0 || !window.requested_visible { ffi::xcb_unmap_window(self.conn, window.xid); } else { ffi::xcb_map_window(self.conn, window.xid); } ffi::xcb_flush(self.conn); } window.rect = rect; window.width = width; window.height = height; Ok(Vec::new()) }
            BridgeCommand::Frame { hwnd, frame } => { self.present(hwnd, &frame)?; Ok(Vec::new()) }
            BridgeCommand::Position { hwnd, insertion, activate } => { self.position(hwnd, insertion, activate)?; Ok(Vec::new()) }
            BridgeCommand::Caret { hwnd, snapshot } => { self.update_caret(hwnd, snapshot)?; Ok(Vec::new()) }
            BridgeCommand::Destroy { hwnd } => { self.destroy(hwnd)?; Ok(Vec::new()) }
        }
    }

    /// Publish one window's name under both the conventional single-byte
    /// property and the extended UTF-8 one, and under the icon-name property
    /// beside it, which is what a window manager reads when it has no
    /// extended name to read. Publishing only the extended name leaves every
    /// manager that reads the conventional one with a nameless window.
    /// # C: O(N_units)
    fn publish_title(&self, xid: ffi::Window, title: &[u16]) {
        let text = String::from_utf16_lossy(title);
        let utf8 = text.as_bytes();
        let (kind, bytes) = match crate::protocol::encode_wm_name(title) {
            crate::protocol::TitleEncoding::Latin1(bytes) => (ffi::ATOM_STRING, bytes),
            crate::protocol::TitleEncoding::Utf8(bytes) => (self.atoms.utf8_string, bytes),
        };
        unsafe {
            ffi::xcb_change_property(self.conn, ffi::PROP_MODE_REPLACE, xid, self.atoms.net_wm_name, self.atoms.utf8_string, 8, utf8.len() as u32, utf8.as_ptr() as *const _);
            ffi::xcb_change_property(self.conn, ffi::PROP_MODE_REPLACE, xid, ffi::ATOM_WM_NAME, kind, 8, bytes.len() as u32, bytes.as_ptr() as *const _);
            ffi::xcb_change_property(self.conn, ffi::PROP_MODE_REPLACE, xid, ffi::ATOM_WM_ICON_NAME, kind, 8, bytes.len() as u32, bytes.as_ptr() as *const _);
            ffi::xcb_flush(self.conn);
        }
    }

    pub fn poll_event(&mut self) -> Option<BridgeEvent> {
        if let Some(event) = self.pending.pop_front() { return Some(event); }
        let raw = unsafe { ffi::xcb_poll_for_event(self.conn) };
        if raw.is_null() { return None; }
        let bytes = unsafe { std::slice::from_raw_parts(raw as *const u8, 32) };
        let synthetic = bytes[0] & 0x80 != 0;
        let sequence = unsafe { (*raw).full_sequence };
        let event = if bytes[0] & 0x7f == ffi::CLIENT_MESSAGE {
            let type_atom = u32::from_ne_bytes(bytes[8..12].try_into().ok()?);
            let protocol = u32::from_ne_bytes(bytes[12..16].try_into().ok()?);
            if type_atom == self.atoms.wm_protocols && protocol == self.atoms.wm_delete { decode_event(bytes) } else { None }
        } else { decode_event(bytes) };
        unsafe { libc::free(raw as *mut libc::c_void); }
        match event {
            // The display asks for pixels it no longer holds. The surface this
            // backend retains for the window is the same pixels the
            // application last drew, so an exposure it can serve from that
            // copy is served here and costs the application nothing. Only what
            // the copy cannot answer - a window that has never presented, or
            // one whose surface no longer describes its extent - travels on as
            // damage the window itself must repaint.
            Some(BridgeEvent::Damage { hwnd: xid, rect }) => {
                if rect.right <= rect.left || rect.bottom <= rect.top { return None; }
                let hwnd = self.xid_to_hwnd.get(&xid).copied()?;
                if self.repaint(hwnd, rect).is_ok() { return None; }
                Some(BridgeEvent::Damage { hwnd, rect })
            }
            Some(BridgeEvent::Close { hwnd: xid }) => self.xid_to_hwnd.get(&xid).copied().map(|hwnd| BridgeEvent::Close { hwnd }),
            Some(BridgeEvent::Configure { hwnd: xid, rect }) => {
                let hwnd = self.xid_to_hwnd.get(&xid).copied()?;
                let window = self.windows.get_mut(&hwnd)?;
                if window.configure_sequence.is_some_and(|expected| crate::extent::obsolete_configure(sequence, expected)) { return None; }
                window.configure_sequence = None;
                if crate::extent::is_empty_backing((window.width, window.height), (rect.right - rect.left, rect.bottom - rect.top)) { return None; }
                let xid = window.xid;
                // The server has just stated the window's real extent. The
                // canonical owner sizes its next frame from the same
                // notification, so a stale extent here refuses that frame and
                // every one after it: the window keeps its last pixels for the
                // rest of its life. A surface captured for the old extent
                // describes nothing on this window and is dropped rather than
                // read at the new one's coordinates.
                let reported = (u32::try_from(rect.right - rect.left).unwrap_or(0), u32::try_from(rect.bottom - rect.top).unwrap_or(0));
                if let Some(extent) = crate::extent::notified((window.width, window.height), reported) {
                    (window.width, window.height) = extent;
                    window.rect = Rect { left: window.rect.left, top: window.rect.top,
                        right: window.rect.left + extent.0 as i32, bottom: window.rect.top + extent.1 as i32 };
                    if !window.surface.as_ref().is_none_or(|s| crate::extent::surface_survives((s.width, s.height), extent)) { window.surface = None; }
                }
                // A child's ConfigureNotify states its position inside its
                // parent's X window, which is the parent's window rectangle;
                // the canonical owner takes the parent's client origin back
                // off it. Translating it to the screen instead would offset
                // the child by wherever its top level happens to sit.
                let toplevel = window.parent == self.root;
                // A real ConfigureNotify reports a position in the parent's
                // coordinates. A window manager that decorates a top-level
                // window reparents it into a frame, so that position is an
                // offset inside the frame and not where the window is; only
                // the synthetic notification a window manager sends is
                // already root-relative.
                let rect = if synthetic || !toplevel { rect } else { self.root_position(xid).map_or(rect, |(left, top)| Rect { left, top, right: left + (rect.right - rect.left), bottom: top + (rect.bottom - rect.top) }) };
                self.windows.get_mut(&hwnd)?.rect=rect;
                Some(BridgeEvent::Configure { hwnd, rect })
            }
            Some(BridgeEvent::Input(input)) => { let input = self.retarget_input(input)?; self.map_input(input) }
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
            Err(error) => { eprintln!("windows-compositor: refused sequence={} hwnd={:#x} error={error:?}", inbound.sequence, inbound.hwnd); self.send_event(transport, BridgeEvent::Ack { sequence: inbound.sequence, hwnd: inbound.hwnd, status: 1 })?; }
        }
        Ok(true)
    }

    fn send_event<T: NativeTransport>(&self, transport: &mut T, event: BridgeEvent) -> Result<(), BackendError> {
        if crate::trace_events() && !matches!(event, BridgeEvent::Ack { .. }) {
            eprintln!("windows-compositor: event {event:?}");
        }
        transport.send(event).map_err(BackendError::Transport)
    }

    fn create(&mut self, hwnd: u32, title: &[u16], rect: Rect, parent: u64, style: u32, ex_style: u32) -> Result<(), BackendError> {
        use crate::styles::{WS_CHILD, WS_POPUP, WS_VISIBLE};
        let width = u32::try_from(rect.right - rect.left).map_err(|_| BackendError::InvalidCommand)?; let height = u32::try_from(rect.bottom - rect.top).map_err(|_| BackendError::InvalidCommand)?;
        if self.windows.contains_key(&hwnd) || width > u16::MAX as u32 || height > u16::MAX as u32 { return Err(BackendError::InvalidCommand); }
        // WS_POPUP takes precedence when both bits are present.  Such a
        // window is an owned top-level surface, not an X child; the owner is
        // represented by WM_TRANSIENT_FOR below.
        let is_child = style & (WS_CHILD | WS_POPUP) == WS_CHILD;
        let (x_parent, x, y) = if is_child { let parent_hwnd = u32::try_from(parent).map_err(|_| BackendError::InvalidCommand)?; let parent_window = self.windows.get(&parent_hwnd).ok_or(BackendError::InvalidCommand)?; (parent_window.xid, rect.left, rect.top) } else { (self.root, rect.left, rect.top) };
        let xid = unsafe { ffi::xcb_generate_id(self.conn) }; let gc = unsafe { ffi::xcb_generate_id(self.conn) };
        // A window the window manager does not manage is override-redirect: no
        // frame, no placement of the manager's choosing, no focus taken from
        // whoever holds it. A dropdown menu is exactly that window, and the
        // attribute is settled before the window is mapped because a manager
        // reads it when the map request arrives. The value list is ordered by
        // its mask bit, override-redirect before the event mask.
        let values = [u32::from(!crate::managed::at_creation(style, ex_style)), ffi::EVENT_KEY_PRESS | ffi::EVENT_KEY_RELEASE | ffi::EVENT_BUTTON_PRESS | ffi::EVENT_BUTTON_RELEASE | ffi::EVENT_POINTER_MOTION | ffi::EVENT_EXPOSURE | ffi::EVENT_STRUCTURE_NOTIFY | ffi::EVENT_FOCUS_CHANGE];
        let (x_width, x_height) = crate::extent::backing((width, height));
        let configure_sequence;
        unsafe { configure_sequence = Some(ffi::xcb_create_window(self.conn, self.depth, xid, x_parent, x as i16, y as i16, x_width as u16, x_height as u16, 0, ffi::WINDOW_CLASS_INPUT_OUTPUT, self.visual, ffi::CW_OVERRIDE_REDIRECT | ffi::CW_EVENT_MASK, values.as_ptr()).sequence); ffi::xcb_create_gc(self.conn, gc, xid, ffi::GC_SUBWINDOW_MODE, &ffi::INCLUDE_INFERIORS); }
        self.publish_title(xid, title);
        unsafe { ffi::xcb_change_property(self.conn, ffi::PROP_MODE_REPLACE, xid, self.atoms.wm_protocols, ffi::ATOM_ATOM, 32, 1, &self.atoms.wm_delete as *const _ as *const _); ffi::xcb_flush(self.conn); }
        // The owner travels in the parent field for a window that is not an X
        // child, whatever its style: an owned window names its owner here, not
        // only a popup.
        if !is_child && parent != 0 { let owner = self.windows.get(&u32::try_from(parent).map_err(|_| BackendError::InvalidCommand)?).ok_or(BackendError::InvalidCommand)?.xid; unsafe { ffi::xcb_change_property(self.conn, ffi::PROP_MODE_REPLACE, xid, self.atoms.wm_transient_for, ffi::ATOM_WINDOW, 32, 1, &owner as *const _ as *const _); ffi::xcb_flush(self.conn); } }
        if width == 0 || height == 0 { unsafe { ffi::xcb_unmap_window(self.conn, xid); } }
        let requested_visible = style & WS_VISIBLE != 0;
        if requested_visible && width != 0 && height != 0 { unsafe { ffi::xcb_map_window(self.conn, xid); } }
        self.windows.insert(hwnd, Window { xid, parent: x_parent, gc, rect, width, height, requested_visible, configure_sequence, surface: None, caret: crate::caret::Surface::default() }); self.xid_to_hwnd.insert(xid, hwnd); Ok(())
    }

    /// Apply one frame's sub-rectangle to the surface this backend retains for
    /// the window, then put that sub-rectangle on the display.
    fn present(&mut self, hwnd: u32, frame: &Frame) -> Result<(), BackendError> {
        {
            let Some(window) = self.windows.get_mut(&hwnd) else {
                eprintln!("windows-compositor: frame-refused hwnd={hwnd:#x} step=window frame={}x{} damage={:?}", frame.width, frame.height, frame.damage);
                return Err(BackendError::InvalidCommand);
            };
            if window.width != frame.width || window.height != frame.height {
                eprintln!("windows-compositor: frame-refused hwnd={hwnd:#x} step=extent frame={}x{} window={}x{} damage={:?}", frame.width, frame.height, window.width, window.height, frame.damage);
                return Err(BackendError::InvalidCommand);
            }
        }
        self.retain_frame(hwnd,frame)?;
        self.repaint_mode(hwnd, frame.damage, ffi::INCLUDE_INFERIORS).inspect_err(|error| {
            eprintln!("windows-compositor: frame-refused hwnd={hwnd:#x} step=repaint frame={}x{} damage={:?} held={} error={error:?}", frame.width, frame.height, frame.damage,
                self.windows.get(&hwnd).and_then(|w| w.surface.as_ref()).is_some_and(|s| s.holds(frame.damage)));
        })?;
        self.observe_frame(hwnd, frame.damage);
        Ok(())
    }

    fn repaint(&self, hwnd: u32, damage: Rect) -> Result<(), BackendError> {
        self.repaint_mode(hwnd,damage,ffi::CLIP_BY_CHILDREN)
    }

    fn repaint_mode(&self, hwnd: u32, damage: Rect, mode:u32) -> Result<(), BackendError> {
        let window = self.windows.get(&hwnd).ok_or(BackendError::InvalidCommand)?;
        let surface = window.surface.as_ref().ok_or(BackendError::InvalidCommand)?;
        if surface.width != window.width || surface.height != window.height { return Err(BackendError::InvalidCommand); }
        if !damage.is_inside(surface.width, surface.height) { return Err(BackendError::InvalidCommand); }
        // A surface holds only what has been presented into it. Its storage
        // covers the window from the moment it is allocated, and reading a
        // never-presented part of it back onto the display puts the colour of
        // empty storage over pixels the window owns and this backend has
        // never seen. Those pixels are the window's to state, so an exposure
        // reaching past what the surface holds belongs to the window.
        if !surface.holds(damage) { return Err(BackendError::InvalidCommand); }
        // The overlay is applied while the damaged pixels are assembled, so
        // the retained surface keeps what the application drew and no second
        // copy of the window exists to hold a composite.
        let overlay = window.caret.covered();
        let damage_width = (damage.right - damage.left) as usize;
        let payload_limit = self.max_request_bytes.saturating_sub(32).max(4);
        let tile_width = damage_width.min(payload_limit / 4).max(1);
        let tile_height = (payload_limit / tile_width.saturating_mul(4)).max(1);
        // Restore one drawable without overwriting independently retained
        // descendants. New drawing explicitly includes its child coverage.
        // SAFETY: the live window GC and mode value survive this checked request.
        let mut cookies = vec![unsafe { ffi::xcb_change_gc_checked(self.conn,window.gc,ffi::GC_SUBWINDOW_MODE,&mode) }];
        for y in (damage.top as usize..damage.bottom as usize).step_by(tile_height) { for x in (damage.left as usize..damage.right as usize).step_by(tile_width) {
            let w = tile_width.min(damage.right as usize - x); let h = tile_height.min(damage.bottom as usize - y); let mut damaged = Vec::with_capacity(w.saturating_mul(h).saturating_mul(4));
            for row in y..y + h {
                let line = surface.run(row, x, w).ok_or(BackendError::InvalidCommand)?;
                let touched = overlay.is_some_and(|o| (row as i32) >= o.top && (row as i32) < o.bottom && (x as i32) < o.right && ((x + w) as i32) > o.left);
                if touched { for (index, pixel) in line.iter().enumerate() { damaged.extend_from_slice(&(pixel ^ window.caret.xor_at((x + index) as i32, row as i32)).to_le_bytes()); } }
                else { for pixel in line { damaged.extend_from_slice(&pixel.to_le_bytes()); } }
            }
            // Submit every tile before checking the batch, retaining each error cookie.
            // SAFETY: connection, window and graphics context are live for the backend, and the tile buffer covers data_len bytes.
            cookies.push(unsafe { ffi::xcb_put_image_checked(self.conn, ffi::IMAGE_FORMAT_Z_PIXMAP, window.xid, window.gc, w as u16, h as u16, x as i16, y as i16, 0, self.depth, damaged.len() as u32, damaged.as_ptr()) });
        }
        }
        requests::finish(self.conn, hwnd, cookies)
    }

    /// Every window this backend holds below one X window, deepest first. The
    /// server destroys a window's whole subtree with it, so these records
    /// describe windows that no longer exist the moment their root is gone.
    /// # C: O(N_windows^2)
    fn subtree(&self, root: Xid) -> Vec<u32> {
        let mut generation = vec![root];
        let mut found = Vec::new();
        // The window tree is finite and acyclic; the bound answers rather than
        // spinning if a parent link is ever wrong.
        for _ in 0..self.windows.len() {
            let next: Vec<(u32, Xid)> = self.windows.iter().filter(|(_, window)| generation.contains(&window.parent)).map(|(hwnd, window)| (*hwnd, window.xid)).collect();
            if next.is_empty() { break; }
            generation = next.iter().map(|(_, xid)| *xid).collect();
            found.extend(next.into_iter().map(|(hwnd, _)| hwnd));
        }
        found.reverse();
        found
    }

    /// Destroy one window. One request destroys its descendants in the server
    /// too, so their records go with it: a record left behind names a window
    /// that no longer exists, refuses every frame for the rest of its life,
    /// and refuses the next creation that draws the same handle.
    /// # C: O(N_windows^2)
    fn destroy(&mut self, hwnd: u32) -> Result<(), BackendError> {
        let window = self.windows.remove(&hwnd).ok_or(BackendError::InvalidCommand)?;
        self.xid_to_hwnd.remove(&window.xid);
        for descendant in self.subtree(window.xid) {
            if let Some(gone) = self.windows.remove(&descendant) { self.xid_to_hwnd.remove(&gone.xid); }
        }
        unsafe { ffi::xcb_destroy_window(self.conn, window.xid); ffi::xcb_flush(self.conn); }
        Ok(())
    }
    fn snapshot_event(&self) -> Option<BridgeEvent> { self.monitor_snapshot().map(BridgeEvent::WorkArea) }
    fn property_u32(&self, window: Xid, atom: ffi::Atom) -> Option<u32> { let values = self.property_u32s(window, atom)?; crate::geometry::decode_cardinals(&values) }
    fn property_u32s(&self, window: Xid, atom: ffi::Atom) -> Option<Vec<u32>> { self.property_u32s_typed(window, atom, ffi::ATOM_CARDINAL) }
    fn property_u32s_typed(&self, window: Xid, atom: ffi::Atom, type_: ffi::Atom) -> Option<Vec<u32>> { let cookie = unsafe { ffi::xcb_get_property(self.conn, 0, window, atom, type_, 0, 4) }; let mut error = ptr::null_mut(); let reply = unsafe { ffi::xcb_get_property_reply(self.conn, cookie, &mut error) }; if reply.is_null() { return None; } if unsafe { (*reply).format } != 32 { unsafe { libc::free(reply as *mut _); } return None; } let len = unsafe { ffi::xcb_get_property_value_length(reply) }; if len < 0 || len % 4 != 0 { unsafe { libc::free(reply as *mut _); } return None; } let ptr = unsafe { ffi::xcb_get_property_value(reply) as *const u32 }; let values = unsafe { std::slice::from_raw_parts(ptr, len as usize / 4) }.to_vec(); unsafe { libc::free(reply as *mut _); } Some(values) }
    /// Where a top-level window sits on the screen, which is not what a real
    /// ConfigureNotify reports once a window manager has reparented it.
    fn root_position(&self, xid: Xid) -> Option<(i32, i32)> {
        let cookie = unsafe { ffi::xcb_translate_coordinates(self.conn, xid, self.root, 0, 0) };
        let mut error = ptr::null_mut();
        let reply = unsafe { ffi::xcb_translate_coordinates_reply(self.conn, cookie, &mut error) };
        if reply.is_null() { return None; }
        let position = unsafe { ((*reply).dst_x as i32, (*reply).dst_y as i32) };
        // SAFETY: xcb hands the reply to the caller to release exactly once.
        unsafe { libc::free(reply as *mut _); }
        Some(position)
    }
    /// X events name an X window; every layer above this one names an HWND.
    /// An event on a window this bridge does not own is not a window event at
    /// all and is dropped, which is the same answer the translation gives for
    /// a window destroyed between the server's dispatch and this poll.
    fn retarget_input(&self, input: InputEvent) -> Option<InputEvent> {
        let xid = match input { InputEvent::Key { hwnd, .. } | InputEvent::Text { hwnd, .. } | InputEvent::Button { hwnd, .. } | InputEvent::Motion { hwnd, .. } | InputEvent::Pointer { hwnd, .. } | InputEvent::Focus { hwnd, .. } => hwnd };
        let hwnd = self.xid_to_hwnd.get(&xid).copied()?;
        Some(match input {
            InputEvent::Key { press, virtual_key, scan_code, modifiers, .. } => InputEvent::Key { hwnd, press, virtual_key, scan_code, modifiers },
            InputEvent::Text { utf8, .. } => InputEvent::Text { hwnd, utf8 },
            InputEvent::Button { press, button, x, y, state, .. } => InputEvent::Button { hwnd, press, button, x, y, state },
            InputEvent::Motion { x, y, state, .. } => InputEvent::Motion { hwnd, x, y, state },
            InputEvent::Pointer { x, y, buttons, wheel, hwheel, .. } => InputEvent::Pointer { hwnd, x, y, buttons, wheel, hwheel },
            InputEvent::Focus { focused, .. } => InputEvent::Focus { hwnd, focused },
        })
    }
    fn map_input(&mut self, input: InputEvent) -> Option<BridgeEvent> {
        if let InputEvent::Key { hwnd, press, virtual_key: _, scan_code: keycode, modifiers: _state } = input {
            unsafe { ffi::xkb_state_update_key(self.state, keycode as u32, if press { 1 } else { 0 }); }
            let keysym = unsafe { ffi::xkb_state_key_get_one_sym(self.state, keycode as u32) };
            let scan = evdev_x11_scan(keycode as u32)?;
            let layout = unsafe { ffi::xkb_state_key_get_layout(self.state, keycode as u32) };
            let mut base_syms = ptr::null();
            let base_count = unsafe { ffi::xkb_keymap_key_get_syms_by_level(self.keymap, keycode as u32, layout, 0, &mut base_syms) };
            let base_keysym = if base_count > 0 && !base_syms.is_null() { unsafe { *base_syms } } else { keysym };
            let virtual_key = keysym_to_vk(base_keysym).or_else(|| keysym_to_vk(keysym))?;
            let was_down = self.down_keys.get(&keycode).copied().unwrap_or(false);
            let modifiers = key_flags(scan, press, was_down);
            if press { self.down_keys.insert(keycode, true); } else { self.down_keys.remove(&keycode); }
            if press {
                let mut text = [0u8; 32]; let n = unsafe { ffi::xkb_state_key_get_utf8(self.state, keycode as u32, text.as_mut_ptr() as *mut libc::c_char, text.len()) };
                if n > 0 { let bytes = &text[..(n as usize).saturating_add(1).min(text.len())]; if let Ok(Some(value)) = crate::keyboard::state_utf8(bytes, n, true) { self.pending.push_back(BridgeEvent::Input(InputEvent::Text { hwnd, utf8: value.as_bytes().to_vec() })); } }
            }
            Some(BridgeEvent::Input(InputEvent::Key { hwnd, press, virtual_key, scan_code: scan.code, modifiers }))
        } else { self.map_pointer(input) }
    }

    /// X reports the modifier state in effect before the event's own
    /// transition and names buttons by number; a window message carries a
    /// complete Win32 button mask and a wheel axis. X publishes no state bit
    /// for the fourth and fifth buttons, so their mask is carried here.
    fn map_pointer(&mut self, input: InputEvent) -> Option<BridgeEvent> {
        let (hwnd, x, y, state, transition) = match input {
            InputEvent::Motion { hwnd, x, y, state } => (hwnd, x, y, state, None),
            InputEvent::Button { hwnd, press, button, x, y, state } => (hwnd, x, y, state, Some((press, button))),
            other => return Some(BridgeEvent::Input(other)),
        };
        const TRACKED: u32 = crate::pointer::MK_XBUTTON1 | crate::pointer::MK_XBUTTON2;
        let mut wheel = 0; let mut hwheel = 0; let mut transitioned = 0; let mut released = 0;
        if let Some((press, button)) = transition {
            match (crate::pointer::button_mask(button), crate::pointer::wheel_for(button)) {
                // The state X reports predates this event's own transition, so
                // a press is not yet held there and a release still is.
                (Some(mask), _) => { if press { transitioned = mask; } else { released = mask; }
                    if mask & TRACKED != 0 { if press { self.extra_buttons |= mask; } else { self.extra_buttons &= !mask; } } }
                // A wheel is a button press in X, and its release stands for
                // no motion at all rather than for a second notch.
                (None, Some((delta, horizontal))) => { if !press { return None; } if horizontal { hwheel = delta; } else { wheel = delta; } }
                (None, None) => return None,
            }
        }
        let buttons = ((crate::pointer::buttons_from_state(state) | (self.extra_buttons & TRACKED)) | transitioned) & !released;
        Some(BridgeEvent::Input(InputEvent::Pointer { hwnd, x, y, buttons, wheel, hwheel }))
    }
}

fn intern(conn: *mut ffi::Connection, name: &str) -> Result<ffi::Atom, BackendError> { let name = CString::new(name).map_err(|_| BackendError::X11)?; let cookie = unsafe { ffi::xcb_intern_atom(conn, 0, name.as_bytes().len() as u16, name.as_ptr()) }; let mut error = ptr::null_mut(); let reply = unsafe { ffi::xcb_intern_atom_reply(conn, cookie, &mut error) }; if reply.is_null() { return Err(BackendError::X11); } let atom = unsafe { (*reply).atom }; unsafe { libc::free(reply as *mut _); } Ok(atom) }

