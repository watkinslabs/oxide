//! Canonical thread teardown has no dead-TID registry; removal itself revokes HWND lookup.
use super::*;
impl WindowManager {
    /// Snapshot resource identities before canonical HWND revocation. # C: O(windows³ + paint sessions)
    pub fn exit_thread_with_resources(&mut self,tid:u64)->(Vec<WindowId>,Vec<u16>,Vec<u32>) {
        let paints: Vec<_>=self.painting.iter().map(|(window,session)|(*window,session.dc)).collect();
        let (removed,atoms)=self.exit_thread_with_property_atoms(tid);
        let dcs=paints.into_iter().filter_map(|(window,dc)|(dc!=0&&removed.contains(&window)).then_some(dc)).collect();
        (removed,atoms,dcs)
    }
    /// Remove thread-owned windows and their dependent child/owner closure.
    /// Returns every actually removed HWND once, dependents before ancestors where possible.
    /// Caller holds exclusive GUI access and cancels external work after releasing it.
    /// # C: O(windows³ + queues + timers); # Sleeps: no
    pub fn exit_thread(&mut self,tid:u64)->Vec<WindowId> {
        self.exit_thread_with_property_atoms(tid).0
    }
    /// Return string-atom releases for the removed ownership closure. # C: O(windows³ + properties)
    pub fn exit_thread_with_property_atoms(&mut self,tid:u64)->(Vec<WindowId>,Vec<u16>) {
        let mut atoms=Vec::new();
        let mut pending:Vec<_>=self.windows.iter().filter_map(|(id,r)|(r.owner_tid==tid).then_some(*id)).collect();
        loop {
            let mut changed=false;
            for (id,r) in &self.windows {
                if !pending.contains(id)&&(r.parent.is_some_and(|p|pending.contains(&p))||r.owner.is_some_and(|p|pending.contains(&p))) {
                    pending.push(*id);changed=true;
                }
            }
            if !changed{break;}
        }
        let mut removed=Vec::new();
        while !pending.is_empty(){
            let index=pending.iter().rposition(|id|!self.windows.iter().any(|(child,r)|child!=id&&pending.contains(child)&&(r.parent==Some(*id)||r.owner==Some(*id))))
                .unwrap_or(pending.len()-1);
            let id=pending.remove(index);
            if self.get(id).is_none(){continue;}
            let descendants=self.destruction_order(id).unwrap_or_default();
            if let Ok((_,released))=self.destroy_with_property_atoms(id){
                atoms.extend(released);
                for gone in descendants.into_iter().rev(){if self.get(gone).is_none()&&!removed.contains(&gone){removed.push(gone);}}
            }
        }
        self.timers.retain(|timer|timer.owner_tid!=tid);
        self.queues.retain(|(owner,_)|*owner!=tid);
        (removed,atoms)
    }
}
#[cfg(test)]
#[path="tests/thread_exit.rs"]mod tests;
