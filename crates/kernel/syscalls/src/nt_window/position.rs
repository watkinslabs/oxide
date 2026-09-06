// Module manifest: callback wire layout, canonical transaction and callback continuation.
use crate::nt_wine_window::position::{Order,Request};
#[path="position/layout.rs"] mod layout;
#[path="position/live.rs"] mod live;
#[path="position/remote.rs"] mod remote;
#[path="position/work.rs"] mod work;
#[path="position/continuation.rs"] mod continuation;
pub(crate) use continuation::{Continuation,Outcome};
pub(crate) use work::{RemotePosition,has_remote_for_tid};
pub(crate) use remote::{queue_position_for_current,pump_position_current,pump_for_reply,has_remote_for_current,cancel_position_thread,cancel_position_window};
pub(crate) use layout::handles_callback;
pub(crate) use live::{PendingPosition,position_context_for_current,position_apply_for_current,position_apply_resumable_for_current,complete_position_callback};
