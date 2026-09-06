// Module manifest: owned preparation payload, final resource/usercopy policy, current owner adapter.
#[path="paint_prepare/policy.rs"]mod policy;
pub(crate) use policy::{Prepared,Owner,finish,whole_window_covered};
#[cfg(target_os="oxide-kernel")]
#[path="paint_prepare/live.rs"]mod live;
#[cfg(target_os="oxide-kernel")]
#[path="paint_prepare/factory.rs"]mod factory;
#[cfg(target_os="oxide-kernel")]
pub(crate) use live::{finish_for_current,discard_for_current};
#[cfg(target_os="oxide-kernel")]
pub(crate) use factory::{prepare_for_current,prepare_default_for_current};
