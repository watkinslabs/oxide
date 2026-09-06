use libc::{c_char, c_int, c_uint, c_void};

#[repr(C)] pub struct Connection { _private: [u8; 0] }
#[repr(C)] pub struct Setup { _private: [u8; 0] }
pub type Window = u32;
pub type Atom = u32;
pub type Gcontext = u32;
pub type Visualid = u32;
#[repr(C)] pub struct XkbContext { _private: [u8; 0] }
#[repr(C)] pub struct XkbKeymap { _private: [u8; 0] }
#[repr(C)] pub struct XkbState { _private: [u8; 0] }

#[repr(C)]
pub struct Screen { pub root: Window, pub default_colormap: u32, pub white_pixel: u32, pub black_pixel: u32, pub current_input_masks: u32, pub width_in_pixels: u16, pub height_in_pixels: u16, pub width_in_millimeters: u16, pub height_in_millimeters: u16, pub min_installed_maps: u16, pub max_installed_maps: u16, pub root_visual: Visualid, pub backing_stores: u8, pub save_unders: u8, pub root_depth: u8, pub allowed_depths: u8 }

#[repr(C)] pub struct ScreenIterator { pub data: *mut Screen, pub rem: c_int, pub index: c_int }
#[repr(C)] pub struct InternAtomCookie { pub sequence: c_uint }
#[repr(C)] pub struct GetPropertyCookie { pub sequence: c_uint }
#[repr(C)] pub struct InternAtomReply { pub response_type: u8, pub pad0: u8, pub sequence: u16, pub length: u32, pub atom: Atom }
#[repr(C)] pub struct GetPropertyReply { pub response_type: u8, pub format: u8, pub sequence: u16, pub length: u32, pub type_: Atom, pub bytes_after: u32, pub value_len: u32, pub pad0: [u8; 12] }

#[repr(C)] pub struct GenericEvent { pub response_type: u8, pub pad0: u8, pub sequence: u16, pub pad: [u8; 28] }
#[repr(C)] pub struct GetImageCookie { pub sequence: c_uint }
#[repr(C)] pub struct GetImageReply { pub response_type: u8, pub depth: u8, pub sequence: u16, pub length: u32, pub visual: Visualid, pub pad0: [u8; 20] }
#[repr(C)] pub struct VoidCookie { pub sequence: c_uint }
#[repr(C)] pub struct QueryTreeCookie { pub sequence: c_uint }
#[repr(C)] pub struct QueryTreeReply { pub response_type: u8, pub pad0: u8, pub sequence: u16, pub length: u32, pub root: Window, pub parent: Window, pub children_len: u16, pub pad1: [u8; 14] }
#[repr(C)] pub struct GenericError { pub response_type: u8, pub error_code: u8, pub sequence: u16, pub resource_id: u32, pub minor_code: u16, pub major_code: u8, pub pad0: u8, pub pad: [u8; 20] }

pub const KEY_PRESS: u8 = 2; pub const KEY_RELEASE: u8 = 3; pub const BUTTON_PRESS: u8 = 4; pub const BUTTON_RELEASE: u8 = 5; pub const MOTION_NOTIFY: u8 = 6; pub const FOCUS_IN: u8 = 9; pub const FOCUS_OUT: u8 = 10; pub const EXPOSE: u8 = 12; pub const CONFIGURE_NOTIFY: u8 = 22; pub const PROPERTY_NOTIFY: u8 = 28; pub const CLIENT_MESSAGE: u8 = 33;
pub const PROP_MODE_REPLACE: u8 = 0; pub const ATOM_NONE: Atom = 0; pub const ATOM_ATOM: Atom = 4; pub const ATOM_CARDINAL: Atom = 6; pub const ATOM_WINDOW: Atom = 33;
pub const WINDOW_CLASS_INPUT_OUTPUT: u16 = 1; pub const IMAGE_FORMAT_Z_PIXMAP: u8 = 2;
pub const CW_EVENT_MASK: u32 = 1 << 11;
pub const EVENT_KEY_PRESS: u32 = 1; pub const EVENT_KEY_RELEASE: u32 = 1 << 1; pub const EVENT_BUTTON_PRESS: u32 = 1 << 2; pub const EVENT_BUTTON_RELEASE: u32 = 1 << 3; pub const EVENT_POINTER_MOTION: u32 = 1 << 6; pub const EVENT_EXPOSURE: u32 = 1 << 15; pub const EVENT_STRUCTURE_NOTIFY: u32 = 1 << 17; pub const EVENT_FOCUS_CHANGE: u32 = 1 << 21; pub const EVENT_PROPERTY_CHANGE: u32 = 1 << 22;
pub const CONFIGURE_X: u16 = 1; pub const CONFIGURE_Y: u16 = 2; pub const CONFIGURE_WIDTH: u16 = 4; pub const CONFIGURE_HEIGHT: u16 = 8; pub const CONFIGURE_SIBLING: u16 = 32; pub const CONFIGURE_STACK_MODE: u16 = 64; pub const STACK_ABOVE: u32 = 0; pub const STACK_BELOW: u32 = 1; pub const SUBSTRUCTURE_NOTIFY: u32 = 1 << 19; pub const SUBSTRUCTURE_REDIRECT: u32 = 1 << 20;

#[link(name = ":libxcb.so.1")]
#[link(name = ":libxkbcommon.so.0")]
#[link(name = ":libxkbcommon-x11.so.0")]
extern "C" {
    pub fn xcb_connect(displayname: *const c_char, screenp: *mut c_int) -> *mut Connection;
    pub fn xcb_connection_has_error(c: *mut Connection) -> c_int;
    pub fn xcb_disconnect(c: *mut Connection);
    pub fn xcb_get_setup(c: *mut Connection) -> *const Setup;
    pub fn xcb_setup_roots_iterator(r: *const Setup) -> ScreenIterator;
    pub fn xcb_screen_next(i: *mut ScreenIterator);
    pub fn xcb_generate_id(c: *mut Connection) -> u32;
    pub fn xcb_create_window(c: *mut Connection, depth: u8, wid: Window, parent: Window, x: i16, y: i16, width: u16, height: u16, border_width: u16, class: u16, visual: Visualid, value_mask: u32, value_list: *const u32) -> u32;
    pub fn xcb_create_gc(c: *mut Connection, cid: Gcontext, drawable: Window, value_mask: u32, value_list: *const u32) -> u32;
    pub fn xcb_change_window_attributes(c: *mut Connection, window: Window, value_mask: u32, value_list: *const u32) -> u32;
    pub fn xcb_change_property(c: *mut Connection, mode: u8, window: Window, property: Atom, type_: Atom, format: u8, data_len: u32, data: *const c_void) -> u32;
    pub fn xcb_map_window(c: *mut Connection, window: Window) -> u32;
    pub fn xcb_map_window_checked(c: *mut Connection, window: Window) -> VoidCookie;
    pub fn xcb_unmap_window(c: *mut Connection, window: Window) -> u32;
    pub fn xcb_configure_window(c: *mut Connection, window: Window, value_mask: u16, value_list: *const u32) -> u32;
    pub fn xcb_configure_window_checked(c: *mut Connection, window: Window, value_mask: u16, value_list: *const u32) -> VoidCookie;
    pub fn xcb_send_event(c: *mut Connection, propagate: u8, destination: Window, event_mask: u32, event: *const c_char) -> VoidCookie;
    pub fn xcb_destroy_window(c: *mut Connection, window: Window) -> u32;
    pub fn xcb_put_image_checked(c: *mut Connection, format: u8, drawable: Window, gc: Gcontext, width: u16, height: u16, dst_x: i16, dst_y: i16, left_pad: u8, depth: u8, data_len: u32, data: *const u8) -> VoidCookie;
    pub fn xcb_request_check(c: *mut Connection, cookie: VoidCookie) -> *mut GenericError;
    pub fn xcb_get_maximum_request_length(c: *mut Connection) -> u32;
    pub fn xcb_flush(c: *mut Connection) -> c_int;
    pub fn xcb_poll_for_event(c: *mut Connection) -> *mut GenericEvent;
    pub fn xkb_context_new(flags: u32) -> *mut XkbContext;
    pub fn xkb_context_unref(context: *mut XkbContext);
    pub fn xkb_keymap_unref(keymap: *mut XkbKeymap);
    pub fn xkb_state_unref(state: *mut XkbState);
    pub fn xkb_x11_setup_xkb_extension(c: *mut Connection, major: c_int, minor: c_int, flags: u32, major_out: *mut c_int, minor_out: *mut c_int, base_event_out: *mut c_int, base_error_out: *mut c_int) -> c_int;
    pub fn xkb_x11_get_core_keyboard_device_id(c: *mut Connection) -> c_int;
    pub fn xkb_x11_keymap_new_from_device(context: *mut XkbContext, c: *mut Connection, device_id: c_int, flags: u32) -> *mut XkbKeymap;
    pub fn xkb_x11_state_new_from_device(keymap: *mut XkbKeymap, c: *mut Connection, device_id: c_int) -> *mut XkbState;
    pub fn xkb_state_update_key(state: *mut XkbState, key: u32, direction: u32) -> u32;
    pub fn xkb_state_key_get_one_sym(state: *mut XkbState, key: u32) -> u32;
    pub fn xkb_state_key_get_layout(state: *mut XkbState, key: u32) -> u32;
    pub fn xkb_keymap_key_get_syms_by_level(keymap: *mut XkbKeymap, key: u32, layout: u32, level: u32, syms_out: *mut *const u32) -> c_int;
    pub fn xkb_state_key_get_utf8(state: *mut XkbState, key: u32, buffer: *mut c_char, size: usize) -> c_int;
    pub fn xkb_keysym_to_utf8(keysym: u32, buffer: *mut c_char, size: usize) -> c_int;
    pub fn xkb_state_mod_name_is_active(state: *mut XkbState, name: *const c_char, component: u32) -> c_int;
    pub fn xcb_intern_atom(c: *mut Connection, only_if_exists: u8, name_len: u16, name: *const c_char) -> InternAtomCookie;
    pub fn xcb_intern_atom_reply(c: *mut Connection, cookie: InternAtomCookie, error: *mut *mut c_void) -> *mut InternAtomReply;
    pub fn xcb_get_property(c: *mut Connection, delete: u8, window: Window, property: Atom, type_: Atom, long_offset: u32, long_length: u32) -> GetPropertyCookie;
    pub fn xcb_get_property_reply(c: *mut Connection, cookie: GetPropertyCookie, error: *mut *mut c_void) -> *mut GetPropertyReply;
    pub fn xcb_get_property_value_length(reply: *const GetPropertyReply) -> c_int;
    pub fn xcb_get_property_value(reply: *const GetPropertyReply) -> *mut c_void;
    pub fn xcb_get_image(c: *mut Connection, format: u8, drawable: Window, x: i16, y: i16, width: u16, height: u16, plane_mask: u32) -> GetImageCookie;
    pub fn xcb_get_image_reply(c: *mut Connection, cookie: GetImageCookie, error: *mut *mut c_void) -> *mut GetImageReply;
    pub fn xcb_get_image_data(reply: *const GetImageReply) -> *mut u8;
    pub fn xcb_get_image_data_length(reply: *const GetImageReply) -> c_int;
    pub fn xcb_query_tree(c: *mut Connection, window: Window) -> QueryTreeCookie;
    pub fn xcb_query_tree_reply(c: *mut Connection, cookie: QueryTreeCookie, error: *mut *mut c_void) -> *mut QueryTreeReply;
    pub fn xcb_query_tree_children(reply: *const QueryTreeReply) -> *mut Window;
    pub fn xcb_query_tree_children_length(reply: *const QueryTreeReply) -> c_int;
}
