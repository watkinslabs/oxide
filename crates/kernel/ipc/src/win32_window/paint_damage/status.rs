//! Queue paint changes follow mutations of canonical region and internal obligations.
use super::super::{WindowId,WindowManager,queue_status::QS_PAINT};
impl WindowManager{
    /// Region presence and internal paint each contribute one obligation. # C: O(N_dirty)
    pub(crate) fn paint_obligations(&self,id:WindowId)->(bool,bool){
        self.dirty.iter().find(|(window,_)|*window==id).map_or((false,false),|(_,damage)|(!damage.region.is_empty(),damage.internal))
    }
    /// A count adjustment rearms remaining work; draining clears pending changes. # C: O(N_dirty * N_windows + N_queues)
    pub(crate) fn note_paint_change(&mut self,id:WindowId,before:(bool,bool)){
        if before==self.paint_obligations(id){return;}
        let Some(record)=self.get(id) else{return;};let tid=record.owner_tid;
        let pending=self.thread_has_pending_paint(tid);
        if let Some((_,queue))=self.queues.iter_mut().find(|(owner,_)|*owner==tid){
            if pending{queue.changed|=QS_PAINT;}else{queue.changed&=!QS_PAINT;}
        }
    }
}
