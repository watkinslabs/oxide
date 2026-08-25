use super::*;

impl CtAccess for LiveCt<'_> {
    fn ctinfo(&self) -> u8 { self.info }
    fn attached(&self) -> bool { self.conn.is_some() }
    fn status(&self) -> u32 { self.conn.map_or(0, conntrack::Conn::status) }
    fn mark(&self) -> u32 { self.conn.map_or(0, |c| c.mark.load(core::sync::atomic::Ordering::Acquire)) }
    fn set_mark(&self, value: u32) {
        if let Some(c) = self.conn { c.mark.store(value, core::sync::atomic::Ordering::Release); }
    }
    fn secmark(&self) -> u32 { self.conn.map_or(0, |c| c.secmark.load(core::sync::atomic::Ordering::Acquire)) }
    fn set_secmark(&self, value: u32) {
        if let Some(c) = self.conn { c.secmark.store(value, core::sync::atomic::Ordering::Release); }
    }
    fn expiration_ms(&self) -> u32 {
        self.conn.map_or(0, |c| c.expires_in(self.now).saturating_mul(1000) as u32)
    }
    fn helper(&self, out: &mut [u8]) -> bool {
        let Some(c) = self.conn else { return false; };
        let helper = c.helper.lock();
        let Some(name) = helper.as_ref() else { return false; };
        let n = name.len().min(out.len());
        out[..n].copy_from_slice(&name.as_bytes()[..n]);
        true
    }
    fn labels(&self, out: &mut [u8]) -> bool {
        if let Some(c) = self.conn { c.labels_copy(out); }
        true
    }
    fn set_labels(&self, value: &[u8]) {
        let Some(c) = self.conn else { return; };
        let mut data = [0u8; conntrack::uapi::NF_CT_LABELS_MAX_SIZE];
        let len = value.len().min(data.len());
        data[..len].copy_from_slice(&value[..len]);
        let update = conntrack::entry::LabelUpdate { data, mask: None, len };
        c.labels_replace(&update);
    }
    fn counters(&self, dir: u8) -> (u64, u64) {
        self.conn.and_then(|c| c.counters.get(dir as usize)).map_or((0, 0), |x| x.read())
    }
    fn tuple(&self, dir: u8) -> Option<Tuple> {
        self.conn.map(|c| c.tuple(if dir == conntrack::uapi::IP_CT_DIR_MAX as u8 {
            self.dir
        } else { dir }))
    }
    fn zone(&self) -> u16 { self.conn.map_or(0, |c| c.orig.zone) }
    fn id(&self) -> u32 { self.conn.map_or(0, |c| c.id as u32) }
    fn offloadable(&self) -> bool {
        self.conn.is_some_and(|c| {
            let status = c.status();
            status & (conntrack::uapi::IPS_CONFIRMED | conntrack::uapi::IPS_SEEN_REPLY
                | conntrack::uapi::IPS_ASSURED | conntrack::uapi::IPS_OFFLOAD) ==
                (conntrack::uapi::IPS_CONFIRMED | conntrack::uapi::IPS_SEEN_REPLY
                    | conntrack::uapi::IPS_ASSURED)
                && c.helper.lock().is_none()
        })
    }
    fn flow(&self) -> Option<alloc::sync::Arc<conntrack::Conn>> { self.owner.clone() }
    fn set_helper(&self, name: &str, l4proto: u8) -> bool {
        match (self.net_owner.as_ref(), self.conn) {
            (Some(net), Some(conn)) => net.attach_helper_for(conn, name, l4proto),
            _ => false,
        }
    }
    fn set_timeout_policy(&self, l3num: u16, l4proto: u8, values: &[u32; 14], now: u64) -> bool {
        self.conn.is_some_and(|c| {
            let installed = c.set_timeout_policy(conntrack::TimeoutPolicy {
                l3num, l4proto, values: *values,
            });
            if installed { c.refresh(now / 1_000_000_000, values[0]); }
            installed
        })
    }
    fn set_expectation(&self, l3num: u16, l4proto: u8, dport: u16,
                       timeout_ms: u32, size: u8, now: u64) -> bool {
        match (self.net_owner.as_ref(), self.conn) {
            (Some(net), Some(_conn)) => self.owner.as_ref().is_some_and(|master| net.install_expectation(
                master, self.dir, l3num, l4proto, dport, timeout_ms, size, now)),
            _ => false,
        }
    }
}

