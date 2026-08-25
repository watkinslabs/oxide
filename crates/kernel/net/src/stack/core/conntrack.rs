#![allow(unused_imports)]
use super::super::*;

impl NetStack {
    pub fn conntrack_in(&self, net_ns: u64) -> Arc<::conntrack::CtNet> {
        let mut tables = self.conntrack.lock();
        tables.entry(net_ns).or_insert_with(|| {
            Arc::new(::conntrack::CtNet::new_with_clock(net_ns,
                (net_ns as u32).wrapping_mul(0x9e37_79b9) ^ 0xa5a5_5a5a,
                ::vfs::inode_times::realtime_now_ns))
        }).clone()
    }

    /// Read an existing conntrack namespace without materializing one merely
    /// because procfs was opened. # C: O(log N)
    pub fn conntrack_existing_in(&self, net_ns: u64) -> Option<Arc<::conntrack::CtNet>> {
        self.conntrack.lock().get(&net_ns).cloned()
    }

    /// Render the live conntrack proc body for one network namespace. # C: O(N)
    pub fn conntrack_proc_body_in(&self, net_ns: u64) -> alloc::string::String {
        let Some(ct) = self.conntrack_existing_in(net_ns) else { return alloc::string::String::new() };
        let now = crate::stack::net_now_ns() / 1_000_000_000;
        let acct = ct.sysctl.lock().acct;
        ::conntrack::procfs::render(&ct.table.snapshot(now), now, acct)
    }

    /// Encode the live entries for ctnetlink's multipart GET dump. # C: O(N)
    pub fn conntrack_dump_in(&self, net_ns: u64) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
        self.conntrack_dump_filtered_in(net_ns, ::conntrack::ctnetlink::DumpFilter::default())
    }

    /// Encode entries selected by ctnetlink's direct table filters. # C: O(N)
    pub fn conntrack_dump_filtered_in(&self, net_ns: u64,
                                      filter: ::conntrack::ctnetlink::DumpFilter)
        -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
        let Some(ct) = self.conntrack_existing_in(net_ns) else { return alloc::vec::Vec::new() };
        let now = crate::stack::net_now_ns() / 1_000_000_000;
        let acct = ct.sysctl.lock().acct;
        ct.table.snapshot(now).iter()
            .filter(|c| ::conntrack::ctnetlink::matches_filter(c, &filter))
            .map(|c| ::conntrack::ctnetlink::encode_entry(c, now, acct))
            .collect()
    }

    /// Encode the live entry selected by one ctnetlink tuple. # C: O(bucket length)
    pub fn conntrack_lookup_tuple_in(&self, net_ns: u64, tuple: ::conntrack::Tuple)
        -> Option<alloc::vec::Vec<u8>> {
        let ct = self.conntrack_existing_in(net_ns)?;
        let now = crate::stack::net_now_ns() / 1_000_000_000;
        let acct = ct.sysctl.lock().acct;
        let found = ct.table.lookup(&tuple, now)?;
        Some(::conntrack::ctnetlink::encode_entry(&found.conn, now, acct))
    }

    /// Encode one tuple-selected entry while atomically zeroing its counters.
    /// # C: O(bucket length)
    pub fn conntrack_lookup_ctrzero_tuple_in(&self, net_ns: u64,
                                              tuple: ::conntrack::Tuple)
        -> Option<alloc::vec::Vec<u8>> {
        let ct = self.conntrack_existing_in(net_ns)?;
        let now = crate::stack::net_now_ns() / 1_000_000_000;
        let acct = ct.sysctl.lock().acct;
        let found = ct.table.lookup(&tuple, now)?;
        let counters = if acct { Some(found.conn.counters_read_and_zero()) } else { None };
        Some(::conntrack::ctnetlink::encode_entry_with_counters(
            &found.conn, now, acct, counters))
    }

    /// Encode one id-selected entry while atomically zeroing its counters.
    /// # C: O(N)
    pub fn conntrack_lookup_ctrzero_id_in(&self, net_ns: u64, id: u64)
        -> Option<alloc::vec::Vec<u8>> {
        let ct = self.conntrack_existing_in(net_ns)?;
        let now = crate::stack::net_now_ns() / 1_000_000_000;
        let acct = ct.sysctl.lock().acct;
        let found = ct.table.find_id(id, now)?;
        let counters = if acct { Some(found.counters_read_and_zero()) } else { None };
        Some(::conntrack::ctnetlink::encode_entry_with_counters(
            &found, now, acct, counters))
    }

    /// Encode every entry while atomically zeroing each entry's counters.
    /// # C: O(N)
    pub fn conntrack_dump_ctrzero_in(&self, net_ns: u64)
        -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
        self.conntrack_dump_ctrzero_filtered_in(
            net_ns, ::conntrack::ctnetlink::DumpFilter::default())
    }

    /// Encode selected entries while atomically zeroing their counters.
    /// # C: O(N)
    pub fn conntrack_dump_ctrzero_filtered_in(&self, net_ns: u64,
                                              filter: ::conntrack::ctnetlink::DumpFilter)
        -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
        let Some(ct) = self.conntrack_existing_in(net_ns) else { return alloc::vec::Vec::new() };
        let now = crate::stack::net_now_ns() / 1_000_000_000;
        let acct = ct.sysctl.lock().acct;
        ct.table.snapshot(now).iter()
        .filter(|conn| ::conntrack::ctnetlink::matches_filter(conn, &filter)).map(|conn| {
            let counters = if acct { Some(conn.counters_read_and_zero()) } else { None };
            ::conntrack::ctnetlink::encode_entry_with_counters(conn, now, acct, counters)
        }).collect()
    }

    /// Set ctnetlink's namespace-local notification groups. # C: O(1)
    pub fn conntrack_set_groups_in(&self, net_ns: u64, groups: u32) {
        self.conntrack_in(net_ns).events.set_subscribed(groups & 0x3f);
    }

    /// Drain the canonical ctnetlink events as family, event mask, and entry
    /// attributes. Destruction events retain their pre-unlink entry snapshot.
    /// # C: O(N events)
    pub fn conntrack_drain_events_in(&self, net_ns: u64)
        -> alloc::vec::Vec<(u8, u32, alloc::vec::Vec<u8>)> {
        let Some(ct) = self.conntrack_existing_in(net_ns) else { return alloc::vec::Vec::new() };
        let now = crate::stack::net_now_ns() / 1_000_000_000;
        let acct = ct.sysctl.lock().acct;
        ct.events.drain().into_iter().map(|event| (
            event.conn.orig.l3num, event.events,
            ::conntrack::ctnetlink::encode_entry(&event.conn, now, acct),
        )).collect()
    }

    /// Read one live conntrack sysctl. The table is a per-net subsystem and
    /// is initialized when its sysctl namespace is first accessed. # C: O(log N)
    pub fn conntrack_sysctl_get(&self, net_ns: u64, knob: ::conntrack::sysctl::Knob) -> u64 {
        self.conntrack_in(net_ns).sysctl.lock().get(knob)
    }

    /// Update one live conntrack sysctl. # C: O(log N)
    pub fn conntrack_sysctl_set(&self, net_ns: u64,
                                knob: ::conntrack::sysctl::Knob, value: u64) -> bool {
        self.conntrack_in(net_ns).sysctl.lock().set(knob, value)
    }

    /// Delete one live conntrack entry through its owning namespace. # C: O(N)
    pub fn conntrack_delete_in(&self, net_ns: u64, id: u64) -> bool {
        let Some(ct) = self.conntrack_existing_in(net_ns) else { return false; };
        ct.delete_id(id, crate::stack::net_now_ns() / 1_000_000_000)
    }

    /// Delete the live entry selected by either conntrack tuple. # C: O(bucket length)
    pub fn conntrack_delete_tuple_in(&self, net_ns: u64, tuple: ::conntrack::Tuple) -> bool {
        let Some(ct) = self.conntrack_existing_in(net_ns) else { return false; };
        let now = crate::stack::net_now_ns() / 1_000_000_000;
        let Some(found) = ct.table.lookup(&tuple, now) else { return false; };
        if !ct.table.kill(&found.conn) { return false; }
        ct.expect.purge_master(&found.conn);
        ct.events.post(&found.conn, ::conntrack::uapi::IPCT_DESTROY);
        true
    }

    /// Return the id of the live entry selected by a tuple. # C: O(bucket length)
    pub fn conntrack_id_tuple_in(&self, net_ns: u64, tuple: ::conntrack::Tuple)
        -> Option<u64> {
        let ct = self.conntrack_existing_in(net_ns)?;
        let now = crate::stack::net_now_ns() / 1_000_000_000;
        Some(ct.table.lookup(&tuple, now)?.conn.id)
    }

    /// Create one confirmed userspace conntrack entry from its tuple. # C: O(bucket length)
    pub fn conntrack_create_tuple_in(&self, net_ns: u64, tuple: ::conntrack::Tuple,
                                     reply: Option<::conntrack::Tuple>, timeout: u32,
                                     status: u32, mark: Option<u32>,
                                     protoinfo: Option<::conntrack::entry::TcpProtoInfoUpdate>,
                                     sctp_protoinfo: Option<::conntrack::entry::SctpProtoInfoUpdate>,
                                     master: Option<::conntrack::Tuple>,
                                     helper: Option<alloc::string::String>,
                                     labels: Option<::conntrack::entry::LabelUpdate>,
                                     synproxy: Option<::conntrack::entry::SynproxyState>)
                                     -> Result<Option<u64>, i32> {
        let ct = self.conntrack_in(net_ns);
        let now = crate::stack::net_now_ns() / 1_000_000_000;
        let master = match master {
            Some(tuple) => Some(ct.table.lookup(&tuple, now).ok_or(-2)?.conn),
            None => None,
        };
        Ok(ct.create_tuple_with(tuple, reply, crate::stack::net_now_ns() / 1_000_000_000,
                             timeout, status, mark, protoinfo, sctp_protoinfo, helper, labels, synproxy,
                             master,
                             |_| true))
    }

    /// Create a ctnetlink entry with the canonical NAT allocator running
    /// before the tuple is confirmed. Missing one-sided NAT attributes still
    /// receive Linux's null binding, so both directions are initialized.
    pub fn conntrack_create_tuple_nat_in(&self, net_ns: u64, tuple: ::conntrack::Tuple,
                                         reply: Option<::conntrack::Tuple>, timeout: u32,
                                         status: u32, mark: Option<u32>,
                                         protoinfo: Option<::conntrack::entry::TcpProtoInfoUpdate>,
                                         sctp_protoinfo: Option<::conntrack::entry::SctpProtoInfoUpdate>,
                                         master: Option<::conntrack::Tuple>,
                                         helper: Option<alloc::string::String>,
                                         src: Option<::nat::NatRange>,
                                         dst: Option<::nat::NatRange>,
                                         labels: Option<::conntrack::entry::LabelUpdate>,
                                         synproxy: Option<::conntrack::entry::SynproxyState>)
                                         -> Result<Option<u64>, i32> {
        let ct = self.conntrack_in(net_ns);
        let now = crate::stack::net_now_ns() / 1_000_000_000;
        let master = match master {
            Some(tuple) => Some(ct.table.lookup(&tuple, now).ok_or(-2)?.conn),
            None => None,
        };
        Ok(ct.create_tuple_with(tuple, reply, now, timeout, status, mark, protoinfo, sctp_protoinfo, helper, labels,
            synproxy, master,
            |conn| {
                struct Env<'a> {
                    table: &'a ::conntrack::CtTable,
                    conn: &'a alloc::sync::Arc<::conntrack::Conn>,
                    now: u64,
                }
                impl ::nat::NatEnv for Env<'_> {
                    fn tuple_taken(&self, tuple: &::conntrack::Tuple) -> bool {
                        self.table.tuple_taken(tuple, Some(self.conn), self.now)
                    }
                    fn random_u16(&self) -> u16 { self.table.random_u16() }
                    fn try_evict(&self, _tuple: &::conntrack::Tuple) -> bool {
                        self.table.early_drop(self.now)
                    }
                }
                let env = Env { table: &ct.table, conn, now };
                let dst_ok = match dst {
                    Some(range) => ::nat::setup_info(conn, &range,
                        ::nat::uapi::NF_NAT_MANIP_DST, &env),
                    None => ::nat::alloc_null_binding(conn,
                        ::nat::uapi::NF_NAT_MANIP_DST, &env),
                };
                if dst_ok == ::nat::SetupResult::Drop { return false; }
                let src_ok = match src {
                    Some(range) => ::nat::setup_info(conn, &range,
                        ::nat::uapi::NF_NAT_MANIP_SRC, &env),
                    None => ::nat::alloc_null_binding(conn,
                        ::nat::uapi::NF_NAT_MANIP_SRC, &env),
                };
                src_ok == ::nat::SetupResult::Accept
            }))
    }

    /// Update one live conntrack entry through its owning namespace. # C: O(N)
    pub fn conntrack_update_in(&self, net_ns: u64, id: u64, timeout: Option<u32>,
                               status: Option<u32>, mark: Option<(u32, Option<u32>)>,
                               seqadj: [Option<::conntrack::entry::SeqAdjust>;
                               ::conntrack::uapi::IP_CT_DIR_MAX],
                               protoinfo: Option<::conntrack::entry::TcpProtoInfoUpdate>,
                               sctp_protoinfo: Option<::conntrack::entry::SctpProtoInfoUpdate>,
                               labels: Option<::conntrack::entry::LabelUpdate>,
                               synproxy: Option<::conntrack::entry::SynproxyState>) -> bool {
        let Some(ct) = self.conntrack_existing_in(net_ns) else { return false; };
        ct.update_id(id, crate::stack::net_now_ns() / 1_000_000_000,
                     timeout, status, mark, seqadj, protoinfo, sctp_protoinfo, labels, synproxy)
    }

    /// Apply ctnetlink's existing-flow helper selection through CtNet. # C: O(N)
    pub fn conntrack_update_helper_in(&self, net_ns: u64, id: u64, name: alloc::string::String)
        -> Result<(), ::conntrack::HelperChangeError> {
        let Some(ct) = self.conntrack_existing_in(net_ns) else {
            return Err(::conntrack::HelperChangeError::NotFound);
        };
        ct.update_helper_id(id, crate::stack::net_now_ns() / 1_000_000_000, name)
    }

}

