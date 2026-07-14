extern crate alloc;

use alloc::sync::Weak;

use super::File;

/// Weak backlink callback owned by an eventpoll interest. # C: O(1)
pub trait FileEpollLink: Send + Sync {
    /// Detach the interest during final watched-file teardown. # C: O(N)
    fn release(&self);
}

impl File {
    /// Link one epitem into this open description. # C: O(N_links)
    pub fn epoll_link(&self, id: u32, link: Weak<dyn FileEpollLink>) {
        let mut links = self.epoll_links.lock();
        links.retain(|(old, weak)| *old != id && weak.upgrade().is_some());
        links.push((id, link));
    }

    /// Remove one epitem backlink. # C: O(N_links)
    pub fn epoll_unlink(&self, id: u32) {
        self.epoll_links.lock().retain(|(old, _)| *old != id);
    }

    /// Linux `eventpoll_release_file`: final fput snapshots weak backlinks and
    /// invokes detach after releasing the file-link lock. # C: O(N_links)
    pub(super) fn release_epoll_links(&self) {
        let links = {
            let mut guard = self.epoll_links.lock();
            core::mem::take(&mut *guard)
        };
        for (_, weak) in links {
            if let Some(link) = weak.upgrade() { link.release(); }
        }
    }
}
