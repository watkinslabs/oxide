//! Dirty backing publication boundary; canonical generation ownership remains IPC, 31fk§9.
use syscall::nt_compositor::Record;
use ipc::win32_gdi::{GdiManager,OutputToken};
const BUSY_IDLE_GRACE_NS:u64=50_000_000;

#[derive(Clone,Copy,Debug,Default)]
pub(crate) struct OutputPump { last_idle_ns:u64 }
impl OutputPump {
    /// Caller holds the existing process GDI owner lock. # C: O(1)
    pub(crate) fn allow(&mut self,idle:bool,now_ns:u64)->bool{
        if idle{self.last_idle_ns=now_ns;true}else{now_ns.saturating_sub(self.last_idle_ns)>=BUSY_IDLE_GRACE_NS}
    }
}

#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub(crate) enum FlushOutcome { Clean, Presented, Retry }

#[must_use = "captured output should be submitted; dropping leaves canonical output pending"]
pub(crate) struct PreparedFrame { pub token:OutputToken,pub record:Record }
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub(crate) enum PrepareError { Invalid, Busy, Capture, Settled }

/// Explicit paint requests publication even for unchanged zero pixels. # C: O(DCs + frame pixels)
pub(crate) fn prepare_explicit(state:&mut GdiManager,hwnd:u32,dc:u32)->Result<PreparedFrame,PrepareError>{
    let token=state.request_output(hwnd,dc).map_err(|_|PrepareError::Invalid)?;
    let record=snapshot(state,token).map_err(|_|PrepareError::Capture)?;
    Ok(PreparedFrame{token,record})
}

/// Caller holds GDI continuously from pixel capture through output demand. No second frame allocation.
/// # C: O(windows + DCs + frame validation)
pub(crate) fn reserve_captured(state:&mut GdiManager,hwnd:u32,dc:u32,record:Record)->Result<PreparedFrame,PrepareError>{
    if record.header.hwnd!=u64::from(hwnd)||record.header.opcode!=syscall::nt_compositor::Opcode::Frame
        ||record.validate().is_err()||state.window_dc(hwnd)!=Some(dc){return Err(PrepareError::Invalid);}
    let (width,height,_)=state.surface(dc).ok_or(PrepareError::Invalid)?;
    let word=|offset|u32::from_le_bytes(record.payload[offset..offset+4].try_into().unwrap());
    if word(0)!=width as u32||word(4)!=height as u32{return Err(PrepareError::Invalid);}
    let token=state.request_output(hwnd,dc).map_err(|_|PrepareError::Invalid)?;
    Ok(PreparedFrame{token,record})
}

/// Acquire ownership only at submission. A stale capture is replaced, never uploaded over newer pixels.
/// # C: O(DCs + frame pixels on generation change)
pub(crate) fn reserve_prepared(state:&mut GdiManager,prepared:PreparedFrame)->Result<PreparedFrame,PrepareError>{
    if state.window_dc(prepared.token.hwnd)!=Some(prepared.token.dc){return Err(PrepareError::Invalid);}
    if !state.surface(prepared.token.dc).is_some_and(|(w,h,_)|w>0&&h>0){return Err(PrepareError::Invalid);}
    let current=state.pending_output(prepared.token.hwnd,prepared.token.dc).ok_or(PrepareError::Settled)?;
    if current!=prepared.token{
        return match reserve_snapshot(state,current).map_err(|_|PrepareError::Capture)?{
            Some((token,record))=>Ok(PreparedFrame{token,record}),None=>Err(PrepareError::Busy),
        };
    }
    if !state.reserve_output(current){return Err(PrepareError::Busy);}
    Ok(prepared)
}

/// Exactly one finish accompanies each submitted reservation, including transport failure.
/// # C: transport + completion cost
pub(crate) fn publish_prepared(prepared:PreparedFrame,publish:impl FnOnce(Record)->u64,
    finish:impl FnOnce(OutputToken,bool))->u64{
    let status=publish(prepared.record);finish(prepared.token,status==0);status
}

/// Caller owns canonical capture/reservation lock; only owned bytes escape. # C: O(DCs + frame pixels)
pub(crate) fn snapshot(state:&GdiManager,token:OutputToken)->Result<Record,()>{
    if state.pending_output(token.hwnd,token.dc)!=Some(token){return Err(());}
    let (width,height,pixels)=state.surface(token.dc).ok_or(())?;
    crate::nt_gdi_frame::snapshot(token.hwnd,1,width,height,pixels).map_err(|_|())
}

/// Reservation and serialization share one owner lock; allocation failure releases reservation.
/// # C: O(DCs + frame pixels)
pub(crate) fn reserve_snapshot(state:&mut GdiManager,token:OutputToken)->Result<Option<(OutputToken,Record)>,()>{
    if !state.reserve_output(token){return Ok(None);}
    match snapshot(state,token){Ok(frame)=>Ok(Some((token,frame))),Err(())=>{state.finish_output(token,false);Err(())}}
}

/// Closures acquire owner locks individually; publication owns its frame and holds none.
/// Capture must cancel its reservation on serialization failure. # C: capture + transport + completion cost
pub(crate) fn flush_one<T,E>(capture:impl FnOnce()->Result<Option<(T,Record)>,E>,
    publish:impl FnOnce(Record)->bool,complete:impl FnOnce(T,bool))->Result<FlushOutcome,E>{
    let Some((ticket,frame))=capture()? else{return Ok(FlushOutcome::Clean);};
    let presented=publish(frame);
    complete(ticket,presented);
    Ok(if presented{FlushOutcome::Presented}else{FlushOutcome::Retry})
}

#[cfg(target_os="oxide-kernel")]
#[path="output/transport.rs"]
mod transport;
#[cfg(target_os="oxide-kernel")]
#[path="output/kernel.rs"]
mod kernel;
#[cfg(target_os="oxide-kernel")]
pub(crate) use kernel::{flush_pending_for_current,submit_prepared_for_current};

#[cfg(test)]
#[path="output/tests/boundary.rs"]
mod tests;
