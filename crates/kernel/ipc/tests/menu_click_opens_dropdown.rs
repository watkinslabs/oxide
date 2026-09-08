//! A click on `File` puts the File menu on screen, and a click on one of its
//! items runs that item's command.
//!
//! Every unit around this path passes on its own; what had never been driven
//! is the path itself, from the pointer record the compositor bridge makes to
//! the `WM_COMMAND` the owner is told about. So this starts where the desktop
//! starts — a compositor pointer press at the File item's rectangle — and runs
//! the retrieval-time hit test, the nonclient press the default procedure
//! turns into `SC_MOUSEMENU`, and the whole modal tracking loop against real
//! window and menu state.
use ipc::win32_menu::chain::{self, BarChain, OpenMenu};
use ipc::win32_menu::draw::{MenuDrawOp, MenuTextHalf};
use ipc::win32_menu::popup::{popup_origin, PopupHit, TPM_BUTTONDOWN};
use ipc::win32_menu::track::{PointerEvent, TrackEffect, WM_COMMAND};
use ipc::win32_menu::track_loop::{classify, LoopAction, LoopStep, ProcCall, RetrievedMessage, TrackLoop};
use ipc::win32_menu::{MenuId, MenuItem, MenuManager, MenuRect};
use ipc::win32_window::hardware::{self, Ladder, LadderStep, MouseContext, MouseOutcome};
use ipc::win32_window::nonclient_menu::{self, MenuCommand, HTMENU};
use ipc::win32_window::{MessageFilter, WinMessage, WindowId, WindowManager, WindowRect, HTCLIENT};

/// Thread every window in the fixture belongs to.
const TID: u64 = 7;
/// The pressed left button, as a compositor pointer report carries it.
const MK_LBUTTON: u32 = 0x0001;
/// The screen rectangle the application window occupies.
const WINDOW: WindowRect = WindowRect { left: 120, top: 90, right: 760, bottom: 570 };
/// The whole screen a popup is placed inside.
const WORK: MenuRect = MenuRect { left: 0, top: 0, right: 1024, bottom: 768 };
/// The cells the menu font measures a bar and a popup with: the same owners
/// the driver reads them from.
fn bar_metrics() -> ipc::win32_gdi::MenuMetrics { ipc::win32_gdi::menu_bar_metrics() }
fn popup_metrics() -> ipc::win32_gdi::MenuMetrics { ipc::win32_gdi::menu_bar_metrics() }
/// Command identifiers of the File menu items this fixture drives.
const IDM_NEW: u32 = 1;
const IDM_OPEN: u32 = 2;
const IDM_EXIT: u32 = 4;

fn utf16(value: &str) -> Vec<u16> { value.encode_utf16().collect() }
fn rect(bounds: WindowRect) -> MenuRect { MenuRect { left: bounds.left, top: bounds.top, right: bounds.right, bottom: bounds.bottom } }

/// The five popups of the application's menu bar, in resource order.
fn notepad_menu(menus: &mut MenuManager) -> (u32, u32) {
    let bar = menus.create().unwrap();
    let popup_for = |menus: &mut MenuManager, label: &str, items: &[(u32, &str)]| {
        let popup = menus.create_popup().unwrap();
        for (position, (id, text)) in items.iter().enumerate() {
            menus.insert(popup, position, MenuItem { id: *id, state: 0, text: utf16(text), submenu: None }).unwrap();
        }
        let position = menus.count(bar).unwrap();
        menus.insert(bar, position, MenuItem { id: 0, state: 0, text: utf16(label), submenu: Some(popup.raw()) }).unwrap();
        popup.raw()
    };
    let file = popup_for(menus, "&File", &[(IDM_NEW, "&New"), (IDM_OPEN, "&Open..."), (3, "&Save"), (IDM_EXIT, "E&xit")]);
    popup_for(menus, "&Edit", &[(10, "&Undo"), (11, "Cu&t")]);
    popup_for(menus, "F&ormat", &[(20, "&Word Wrap")]);
    popup_for(menus, "&View", &[(30, "&Status Bar")]);
    popup_for(menus, "&Help", &[(40, "&About Notepad")]);
    (bar.raw(), file)
}

/// The application window as the create path leaves it: the menu attached, and
/// the client rectangle the creation-time nonclient calculation shrank by the
/// height of the bar.
struct Desktop { windows: WindowManager, menus: MenuManager, hwnd: WindowId, bar: u32, file: u32, open: Vec<OpenMenu>, posted: Vec<(u32, u64, i64)> }

impl Desktop {
    fn new() -> Self {
        let mut menus = MenuManager::new();
        let (bar, file) = notepad_menu(&mut menus);
        let mut windows = WindowManager::new();
        let hwnd = windows.create(TID, None, 0).unwrap();
        windows.set_rect(hwnd, WINDOW).unwrap();
        windows.set_menu(hwnd, Some(bar)).unwrap();
        windows.set_visible(hwnd, true).unwrap();
        let band = menus.bar_rect(MenuId::from_raw(bar).unwrap(), rect(WINDOW), &bar_metrics()).unwrap();
        let height = band.bottom - band.top;
        assert!(height > 0, "a bar with items claims a band");
        windows.set_client_rect(hwnd, WindowRect { top: WINDOW.top + height, ..WINDOW }).unwrap();
        Self { windows, menus, hwnd, bar, file, open: Vec::new(), posted: Vec::new() }
    }

    /// Screen rectangle of one item of the menu bar.
    fn bar_item(&self, position: usize) -> MenuRect {
        self.menus.bar_item_rect(MenuId::from_raw(self.bar).unwrap(), position, rect(WINDOW), &bar_metrics()).unwrap()
    }

    /// The chain resolution the tracking loop reads a point against.
    fn resolve(&self, point: (i32, i32)) -> PointerEvent {
        let bar = BarChain { menu: self.bar, bounds: rect(WINDOW), metrics: bar_metrics() };
        let (menu, hit) = chain::menu_from_point(&self.menus, &self.open, Some(&bar), point);
        let menu_is_bar = menu == Some(self.bar);
        PointerEvent { pt: point, menu, hit, menu_is_bar, right_button: false }
    }

    /// The window rectangle of one open popup.
    fn popup_rect(&self, menu: u32) -> Option<MenuRect> { self.open.iter().find(|entry| entry.menu == menu).map(|entry| entry.rect) }
}

/// The message the queue hands the retrieval, unchanged.
fn peek(windows: &mut WindowManager, remove: bool) -> Option<WinMessage> {
    windows.peek_for_thread(TID, MessageFilter { hwnd: None, first: 0, last: 0 }, remove)
}

/// Answer one `WM_NCHITTEST` the way the kernel's default window procedure
/// does for a window that carries a menu bar.
fn answer_hit_test(desktop: &Desktop, call: ProcCall) -> i32 {
    assert_eq!(call.message, ipc::win32_window::WM_NCHITTEST);
    let client = desktop.windows.client_rect_raw(desktop.hwnd).unwrap();
    let (x, y) = (call.lparam as u64 as u16 as i16 as i32, ((call.lparam as u64 >> 16) as u16 as i16) as i32);
    nonclient_menu::menu_bar_hit_test(client.left, client.top, client.right, true, x, y).unwrap_or(HTCLIENT as i16) as i32
}

/// The retrieval-time hardware stage: hit-test the queued screen point, then
/// prepare and run the ladder. Reports the message the application receives.
fn retrieve(desktop: &mut Desktop) -> WinMessage {
    let queued = peek(&mut desktop.windows, false).expect("the press is queued");
    let captured = desktop.windows.capture_window().is_some();
    let call = hardware::hit_test_call(desktop.hwnd.raw(), queued.lparam, captured).expect("an uncaptured pointer is hit-tested");
    let hit = answer_hit_test(desktop, ProcCall { hwnd: call.hwnd as u64, message: call.message, wparam: call.wparam, lparam: call.lparam });
    let client = desktop.windows.client_rect_raw(desktop.hwnd).unwrap();
    let ctx = MouseContext { hit_test: hit, client_origin: (client.left, client.top), menu_mode: false, captured,
        modal: false, class_dbl_clks: false, double_click_ms: 500, double_click_width: 4, double_click_height: 4,
        time_ms: 1_000, remove: true, filter: MessageFilter { hwnd: None, first: 0, last: 0 } };
    let prepared = hardware::prepare_mouse(queued, None, &ctx);
    assert_eq!(prepared.outcome, MouseOutcome::Ladder, "a removed button-down runs the activation ladder");
    let mut ladder = Ladder::new(ipc::win32_window::hardware::LadderContext { hwnd: desktop.hwnd.raw(), hit_test: hit,
        origin: prepared.origin, button_down: true, active: None, root: desktop.hwnd.raw(),
        root_style: 0, notify: Vec::new() });
    loop {
        match ladder.next() {
            LadderStep::Done { eat } => { assert!(!eat, "nothing eats the press that opens a menu"); break; }
            LadderStep::Send(_) => ladder.call_result(Ok(0)),
            LadderStep::Activate(_) => ladder.call_result(Ok(1)),
        }
    }
    let _ = peek(&mut desktop.windows, true);
    prepared.message
}

/// Drive the tracking loop until it needs a message or reports its command,
/// exactly as the kernel driver does: every send is answered, every effect is
/// applied to the open popup windows.
fn drive(state: &mut TrackLoop, desktop: &mut Desktop) -> Option<i32> {
    loop {
        match state.next(&mut desktop.menus) {
            LoopStep::Done(command) => return Some(command),
            LoopStep::NextMessage => return None,
            LoopStep::Send(_) | LoopStep::Dispatch(_) => state.call_result(Ok(0)),
            LoopStep::ShowTop => { state.set_current(state.top(), 0); }
            LoopStep::Effect(effect) => apply(state, desktop, effect),
            LoopStep::ShowSub { menu, position, submenu, select_first } => show_sub(state, desktop, menu, position, submenu, select_first),
            LoopStep::Close { menu } => { desktop.open.retain(|entry| entry.menu != menu); state.set_current(state.current(), 0); }
            LoopStep::PressAt { point } => { let event = desktop.resolve(point); state.press(&mut desktop.menus, &event); }
        }
    }
}

fn apply(state: &mut TrackLoop, desktop: &mut Desktop, effect: TrackEffect) {
    match effect {
        TrackEffect::Repaint { .. } | TrackEffect::MenuSelect { .. } | TrackEffect::Beep => {}
        TrackEffect::Post { message, wparam, lparam } => desktop.posted.push((message, wparam, lparam)),
        TrackEffect::HideSubPopups { menu } => {
            let closed = chain::sub_popup_chain(&mut desktop.menus, desktop.open.len(), menu);
            state.close_popups(&closed);
        }
        TrackEffect::ShowSubPopup { menu, select_first } => {
            let Some((position, submenu)) = chain::submenu_target(&desktop.menus, menu) else { return; };
            state.open_submenu(menu, position, submenu, select_first);
            let closed = chain::sub_popup_chain(&mut desktop.menus, desktop.open.len(), menu);
            state.close_popups(&closed);
        }
    }
}

/// Measure and place one submenu, the way the driver opens a popup window for
/// it. A bar item's submenu drops below the item.
fn show_sub(state: &mut TrackLoop, desktop: &mut Desktop, menu: u32, position: u32, submenu: u32, select_first: bool) {
    let id = MenuId::from_raw(submenu).unwrap();
    let layout = desktop.menus.popup_layout(id, &popup_metrics(), i32::MAX).unwrap();
    // The same two decisions the driver makes: which menu the item belongs to,
    // and where its submenu opens against it.
    let (parent, item) = match desktop.popup_rect(menu) {
        Some(window) => (chain::ParentMenu::Popup { window },
            desktop.menus.popup_layout(MenuId::from_raw(menu).unwrap(), &popup_metrics(), i32::MAX).unwrap().items[position as usize]),
        None => (chain::ParentMenu::Bar, desktop.bar_item(position as usize)),
    };
    let (origin, anchor) = chain::submenu_origin(parent, item);
    chain::mark_mouse_select(&mut desktop.menus, menu, position);
    let (x, y) = popup_origin(state.flags(), origin.0, origin.1, layout.width, layout.height, WORK, anchor.0, anchor.1);
    let bounds = MenuRect { left: x, top: y, right: x + layout.width, bottom: y + layout.height };
    desktop.open.retain(|entry| entry.menu != submenu);
    desktop.open.insert(0, OpenMenu { menu: submenu, rect: bounds, layout });
    if select_first { let _ = desktop.menus.set_focused_item(id, 0); }
    state.set_current(submenu, 1);
}

/// Hand one pointer message to the loop, resolved against the open chain.
fn pointer(state: &mut TrackLoop, desktop: &mut Desktop, message: u32, point: (i32, i32)) {
    let lparam = ((point.1 as u32 as i64) << 16) | (point.0 as u32 as i64 & 0xffff);
    let retrieved = RetrievedMessage { hwnd: desktop.hwnd.raw() as u64, message, wparam: 0, lparam };
    let event = match classify(message, 0, lparam) {
        LoopAction::ButtonDown { point, right } | LoopAction::ButtonUp { point, right } => Some(desktop.resolve_with(point, right)),
        LoopAction::Move { point } => Some(desktop.resolve(point)),
        _ => None,
    };
    state.message(&mut desktop.menus, retrieved, event);
}

impl Desktop {
    fn resolve_with(&self, point: (i32, i32), right: bool) -> PointerEvent {
        PointerEvent { right_button: right, ..self.resolve(point) }
    }
}

const WM_LBUTTONDOWN: u32 = 0x0201;
const WM_LBUTTONUP: u32 = 0x0202;
const WM_MOUSEMOVE: u32 = 0x0200;
const WM_NCLBUTTONDOWN: u32 = 0x00a1;

/// The whole path, from the compositor's pointer record to the command the
/// owner is told about.
#[test]
fn a_press_on_the_file_item_opens_its_menu_and_a_release_on_an_item_runs_its_command() {
    let mut desktop = Desktop::new();
    let file_item = desktop.bar_item(0);
    let press = ((file_item.left + file_item.right) / 2, (file_item.top + file_item.bottom) / 2);

    // The desktop delivers the press in the window's own surface coordinates.
    desktop.windows.post_compositor_pointer(desktop.hwnd, press.0 - WINDOW.left, press.1 - WINDOW.top, MK_LBUTTON, 0, 0).unwrap();
    let queued = peek(&mut desktop.windows, false).unwrap();
    assert_eq!(queued.message, WM_MOUSEMOVE, "the pointer arrives at a new point before it is pressed");
    let _ = peek(&mut desktop.windows, true);

    // The press itself, hit-tested at retrieval, is a nonclient press on the
    // menu band and carries the code that named it.
    let delivered = retrieve(&mut desktop);
    assert_eq!(delivered.message, WM_NCLBUTTONDOWN, "a press on the bar is a nonclient press");
    assert_eq!(delivered.wparam, HTMENU as u64);
    assert_eq!(delivered.lparam, ((press.1 as u32 as i64) << 16) | (press.0 as u32 as i64 & 0xffff),
        "a nonclient press is reported in screen coordinates");

    // What the default window procedure does with it.
    // A press on the bar carries no hit bits; only the window-menu icon does.
    let command = nonclient_menu::nc_button_sys_command(HTMENU).expect("the bar answers a press with a system command");
    assert_eq!(nonclient_menu::menu_sys_command(command, 0), Some(MenuCommand::Mouse { hit: 0 }));

    // Tracking, entered on the button already down.
    let mut state = TrackLoop::new(TPM_BUTTONDOWN, desktop.hwnd.raw(), desktop.bar, press);
    state.begin();
    assert_eq!(drive(&mut state, &mut desktop), None, "the loop waits for the next message with the menu open");
    assert_eq!(desktop.open.len(), 1, "the File menu has a window of its own");
    assert_eq!(desktop.open[0].menu, desktop.file);

    // The window it opened is under the item that opened it, and its paint
    // plan carries the File items.
    let bounds = desktop.popup_rect(desktop.file).unwrap();
    assert_eq!((bounds.left, bounds.top), (file_item.left, file_item.bottom), "the menu drops below its bar item");
    let plan = desktop.menus.popup_draw_plan(MenuId::from_raw(desktop.file).unwrap(), &desktop.open[0].layout).unwrap();
    let drawn: Vec<u32> = plan.iter().filter_map(|op| match op { MenuDrawOp::Text { position, half: MenuTextHalf::Name, .. } => Some(*position), _ => None }).collect();
    assert_eq!(drawn, vec![0, 1, 2, 3], "every File item is drawn");

    // A move over the last item selects it.
    let exit = desktop.open[0].layout.items[3];
    let over_exit = (bounds.left + (exit.left + exit.right) / 2, bounds.top + (exit.top + exit.bottom) / 2);
    assert_eq!(desktop.resolve(over_exit).hit, PopupHit::Item(3), "the point lands on the item it looks like");
    pointer(&mut state, &mut desktop, WM_MOUSEMOVE, over_exit);
    assert_eq!(drive(&mut state, &mut desktop), None);
    assert_eq!(desktop.menus.focused_item(MenuId::from_raw(desktop.file).unwrap()), 3, "the item under the pointer is selected");

    // The release on it ends tracking and reports its command to the owner.
    pointer(&mut state, &mut desktop, WM_LBUTTONUP, over_exit);
    assert_eq!(drive(&mut state, &mut desktop), Some(1), "tracking is over");
    assert_eq!(desktop.posted, vec![(WM_COMMAND, IDM_EXIT as u64, 0i64)], "the owner is told which command was chosen");
    assert!(desktop.open.is_empty(), "the menu window is retired with the loop");
}

/// A press that lands on the client area below the bar is an ordinary client
/// click, reported in client coordinates: the same retrieval decides both.
#[test]
fn a_press_below_the_menu_band_stays_a_client_press_in_client_coordinates() {
    let mut desktop = Desktop::new();
    let client = desktop.windows.client_rect_raw(desktop.hwnd).unwrap();
    let point = (client.left + 40, client.top + 60);
    desktop.windows.post_compositor_pointer(desktop.hwnd, point.0 - WINDOW.left, point.1 - WINDOW.top, MK_LBUTTON, 0, 0).unwrap();
    let _ = peek(&mut desktop.windows, true);
    let delivered = retrieve(&mut desktop);
    assert_eq!(delivered.message, WM_LBUTTONDOWN);
    assert_eq!(delivered.lparam, ((60u32 as i64) << 16) | 40, "a client press is reported in client coordinates");
}
