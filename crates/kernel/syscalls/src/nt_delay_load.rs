//! `LdrResolveDelayLoadedAPI`: bind one delay-load thunk to its export.
//!
//! Module manifest: `resolve` walks the delay descriptor, binds the import,
//! and transfers to a failure hook. Every decision belongs to
//! `nt_delay_load_policy`. Contract: `docs/31gg`.

#![cfg(target_os = "oxide-kernel")]

#[cfg(target_arch = "x86_64")]
#[path = "nt_delay_load/resolve.rs"]
mod resolve;

use syscall::nt::{NtCall, NtService};

/// Resolve one delay-loaded import and publish it in the caller's import
/// address table. The answer is the bound address, `0` when nothing can be
/// bound and no hook is installed, or `STATUS_PENDING` once the frame has been
/// redirected into a failure hook whose result becomes the answer.
/// # C: O(dependency closure on first use of a delay-loaded DLL)
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service != NtService::ResolveDelayLoadedApi { return None; }
    #[cfg(target_arch = "x86_64")]
    { Some(resolve::resolve([call.args.a0, call.args.a1, call.args.a2, call.args.a3, call.args.a4, call.args.a5])) }
    #[cfg(target_arch = "aarch64")]
    { Some(0) }
}
