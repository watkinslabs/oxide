use std::sync::{Mutex,MutexGuard,Weak};
use ipc::win32_window::{WindowManager,WindowId};
pub(crate) struct Lock<T>(pub Mutex<T>);
impl<T> Lock<T>{pub fn lock(&self)->MutexGuard<'_,T>{self.0.lock().unwrap()}}
pub(crate) struct GuiEntry{pub group:Weak<crate::thread_group::ThreadGroup>,pub state:WindowManager}
pub(crate) static GUI:Lock<Vec<GuiEntry>>=Lock(Mutex::new(Vec::new()));
pub(crate) fn valid_window(hwnd:u64)->Option<WindowId>{u32::try_from(hwnd).ok().and_then(WindowId::from_raw)}
#[path="../../caret.rs"]mod contract;
#[path="adapter.rs"]pub(crate) mod caret;
#[path="cases.rs"]mod cases;
