//! Sizegrip input forwards through existing cursor and resumable Send owners.
use ipc::win32_window::{WindowId, IDC_SIZENESW, IDC_SIZENWSE};
use ipc::win32_window::styles::WS_EX_LAYOUTRTL;
use ipc::win32_window::nonclient_menu::WM_SYSCOMMAND;
use crate::nt_window::send;
use super::proc_abi::{SC_SIZE, WMSZ_BOTTOMLEFT, WMSZ_BOTTOMRIGHT};

/// # C: O(cursor owner work); # Sleeps: yes
pub(crate) fn sizegrip_cursor(ex_style:u32)->u64 {
    let id=if ex_style&WS_EX_LAYOUTRTL!=0 {IDC_SIZENESW}else{IDC_SIZENWSE};
    crate::nt_wine_window::cursor_raw::apply_default_step(
        crate::nt_wine_window::cursor_raw::SetCursorStep::OemCursor{id,beep:false})
}

/// # C: O(sent-message owner work); # Sleeps: yes
pub(crate) fn sizegrip_click(parent:Option<WindowId>,ex_style:u32,lparam:u64)->u64 {
    let Some(parent)=parent else{return 0;};
    let edge=if ex_style&WS_EX_LAYOUTRTL!=0 {WMSZ_BOTTOMLEFT}else{WMSZ_BOTTOMRIGHT};
    match send::send_resumable_current(parent.raw() as u64,WM_SYSCOMMAND,SC_SIZE+edge,lparam,
        send::Continuation{token:0,resume:clicked}) {
        send::SendOutcome::Pending=>crate::nt_window::STATUS_PENDING,
        _=>0,
    }
}
fn clicked(_:u64,_:Result<u64,()>)->u64 {0}
