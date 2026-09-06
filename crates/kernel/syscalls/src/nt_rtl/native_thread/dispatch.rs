use syscall::{nt::{NtCall, NtService}, nt_native_thread as abi};

pub(crate) fn dispatch(call: NtCall) -> Option<u64> {
    if call.service != NtService::QueryVirtualMemory || call.args.a2 != abi::INFO_CLASS { return None; }
    let Some(cur) = sched::live::current() else { return Some(abi::INVALID); };
    let a = call.args;
    Some(match a.a0 {
        abi::REGISTER => super::creation::register(cur, a.a1, a.a3, a.a4, a.a5),
        abi::PREPARE => super::lifecycle::prepare(cur, a.a1, a.a3, a.a4),
        abi::READY => if cur.nt_native_thread.lock().advance(sched::nt_native_thread::Phase::Preparing,
            sched::nt_native_thread::Phase::Ready) { abi::SUCCESS } else { abi::INVALID },
        abi::PUBLISH => super::lifecycle::publish(cur),
        abi::ENTER => super::context::enter(cur),
        abi::RETURN => super::context::return_native(cur, a.a1 as u32),
        abi::RELEASE => super::lifecycle::release(cur),
        abi::COMPLETE => super::context::complete(cur, a.a1),
        _ => abi::INVALID,
    })
}
