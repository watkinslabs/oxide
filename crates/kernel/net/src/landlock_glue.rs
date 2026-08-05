// Sandbox state the socket layer needs. Kept in one file so the scope check
// is the only place `net` reaches for the running task.

extern crate alloc;

use alloc::sync::Arc;

use landlock::uapi::SCOPE_ABSTRACT_UNIX_SOCKET;
use landlock::Domain;

/// Sandbox domain of the running task, or `None` when unconfined or when there
/// is no running task (the hosted test build).
/// # C: O(1)
pub fn current_domain() -> Option<Arc<Domain>> {
    #[cfg(target_os = "oxide-kernel")]
    { sched::live::current().and_then(|c| c.landlock_domain.lock().clone()) }
    #[cfg(not(target_os = "oxide-kernel"))]
    { None }
}

/// Whether the running task is isolated from an abstract-namespace socket
/// published by `owner`.
///
/// An abstract name has no filesystem object to attach a rule to, so it is
/// isolated by domain: a sandboxed client may reach only sockets published from
/// inside its own domain. A socket published by an unconfined process is
/// outside every domain.
/// # C: O(N_layers)
pub fn abstract_socket_denied(owner: Option<&Arc<Domain>>) -> bool {
    landlock::domain::scope_denied(current_domain().as_ref(), owner,
                                   SCOPE_ABSTRACT_UNIX_SOCKET)
}

/// Same question against a domain the caller already holds; lets a check that
/// has both sides in hand avoid a second lookup.
/// # C: O(N_layers)
pub fn abstract_socket_denied_for(client: Option<&Arc<Domain>>, owner: Option<&Arc<Domain>>)
    -> bool
{
    landlock::domain::scope_denied(client, owner, SCOPE_ABSTRACT_UNIX_SOCKET)
}

/// Whether the running task may reach the abstract-namespace address `addr` in
/// `namespace`. Pathname addresses are not covered: those name a filesystem
/// object, and are governed by hierarchy rules instead.
///
/// An address nobody has bound is not a denial — the connection fails on its
/// own terms, and reporting a sandbox denial for a missing name would leak
/// which names exist.
/// # C: O(log N_bindings + N_layers)
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub fn abstract_connect_denied(namespace: &network_namespace::NetworkNamespaceRef,
                               addr: &crate::UnixAddr) -> bool
{
    if addr.is_pathname() { return false; }
    let client = current_domain();
    if client.as_ref().map(|d| !d.scopes(SCOPE_ABSTRACT_UNIX_SOCKET)).unwrap_or(true) {
        return false;
    }
    let reg = crate::net_ns::unix_registry_for_addr_in(namespace, addr);
    let owner = match reg.lookup_listener_addr(addr) {
        Some(l) => l.owner_domain(),
        None => match reg.dgram_lookup_addr(addr) {
            Some(q) => q.owner_domain(),
            None => return false,
        },
    };
    abstract_socket_denied_for(client.as_ref(), owner.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use landlock::abi::RulesetAttr;
    use landlock::Ruleset;

    fn scoped() -> Arc<Domain> {
        let rs = Ruleset::new(&RulesetAttr {
            scoped: SCOPE_ABSTRACT_UNIX_SOCKET, ..Default::default() });
        Domain::merge(None, &rs).unwrap()
    }

    fn nested(parent: &Arc<Domain>) -> Arc<Domain> {
        let rs = Ruleset::new(&RulesetAttr {
            scoped: SCOPE_ABSTRACT_UNIX_SOCKET, ..Default::default() });
        Domain::merge(Some(parent), &rs).unwrap()
    }

    fn socket_file(domain: Option<Arc<Domain>>) -> (Arc<crate::sock::InetSocket>, Arc<vfs::File>) {
        let sock = Arc::new(crate::sock::InetSocket::new_unix());
        let inode = crate::sock::make_inet_socket_inode(sock.clone());
        let dentry = vfs::Dentry::new(None, alloc::string::String::from("socket"), inode.clone());
        let file = vfs::File::new_at(inode, dentry, vfs::OpenFlags::O_RDWR, 0,
            vfs::FileCred::root().with_security(domain));
        assert!(crate::bind_file(&file, &sock));
        (sock, file)
    }

    #[test]
    fn a_socket_published_by_an_unconfined_process_is_outside_every_domain() {
        // The case the scope exists for: a sandbox must not be able to reach a
        // service that was started before it.
        assert!(abstract_socket_denied_for(Some(&scoped()), None));
    }

    #[test]
    fn a_socket_published_inside_the_same_domain_stays_reachable() {
        let d = scoped();
        assert!(!abstract_socket_denied_for(Some(&d), Some(&d)));
    }

    #[test]
    fn a_socket_published_by_a_nested_domain_stays_reachable() {
        let outer = scoped();
        let inner = nested(&outer);
        assert!(!abstract_socket_denied_for(Some(&outer), Some(&inner)));
        // And a nested client cannot reach back out to the outer domain's.
        assert!(abstract_socket_denied_for(Some(&inner), Some(&outer)));
    }

    #[test]
    fn an_unconfined_client_reaches_anything() {
        assert!(!abstract_socket_denied_for(None, None));
        assert!(!abstract_socket_denied_for(None, Some(&scoped())));
    }

    #[test]
    fn an_unrelated_domain_of_equal_depth_is_outside() {
        assert!(abstract_socket_denied_for(Some(&scoped()), Some(&scoped())));
    }

    #[test]
    fn a_listener_hands_back_the_domain_that_published_it() {
        let l = crate::UnixListener::new(crate::UnixAddr::from_abstract_or_test_path(
            alloc::string::String::from("\0ll-test")));
        assert!(l.owner_domain().is_none());
        let d = scoped();
        let (sock, _file) = socket_file(Some(d.clone()));
        l.set_owner_socket(&sock);
        assert!(!abstract_socket_denied_for(Some(&d), l.owner_domain().as_ref()));
        assert!(abstract_socket_denied_for(Some(&scoped()), l.owner_domain().as_ref()));
    }

    #[test]
    fn a_datagram_queue_hands_back_the_domain_that_published_it() {
        let q = crate::UnixDgramQueue::new();
        assert!(q.owner_domain().is_none());
        let d = scoped();
        let (sock, _file) = socket_file(Some(d.clone()));
        q.set_owner_socket(&sock);
        assert!(!abstract_socket_denied_for(Some(&d), q.owner_domain().as_ref()));
        assert!(abstract_socket_denied_for(Some(&scoped()), q.owner_domain().as_ref()));
    }
}
