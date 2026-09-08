// Access masks for the NT object types this shim creates handles to. Every
// type names the rights it answers for and the four generic rights a caller
// may ask in place of them; a generic right names the specific set the type
// maps it to and reaches the handle only in that mapped form. Ungated so the
// mapping each type publishes is testable without a target build.

/// Rights every object type carries together.
pub const STANDARD_RIGHTS_REQUIRED: u32 = 0x000f_0000;
/// Read of the object's own security, which the three directional standard
/// rights all resolve to.
pub const READ_CONTROL: u32 = 0x0002_0000;
pub const STANDARD_RIGHTS_READ: u32 = READ_CONTROL;
pub const STANDARD_RIGHTS_WRITE: u32 = READ_CONTROL;
pub const STANDARD_RIGHTS_EXECUTE: u32 = READ_CONTROL;
/// Wait on the object as a synchronisation object.
pub const SYNCHRONIZE: u32 = 0x0010_0000;
/// Ask for every right the type grants, resolved at handle creation.
pub const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

pub const GENERIC_READ: u32 = 0x8000_0000;
pub const GENERIC_WRITE: u32 = 0x4000_0000;
pub const GENERIC_EXECUTE: u32 = 0x2000_0000;
pub const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_MASK: u32 = GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL;

/// One object type's access contract: the rights it answers for, and the
/// specific rights each of the four generic rights expands to.
pub struct ObjectAccess { pub valid: u32, pub read: u32, pub write: u32, pub exec: u32, pub all: u32 }

impl ObjectAccess {
    /// Expand the generic rights of a request into the specific rights this
    /// type maps them to. A request for the maximum allowed resolves to every
    /// right the type grants. No generic bit survives. # C: O(1)
    pub const fn map(&self, desired: u32) -> u32 {
        let mut access = desired;
        if access & MAXIMUM_ALLOWED != 0 { access = (access & !MAXIMUM_ALLOWED) | GENERIC_ALL; }
        if access & GENERIC_READ != 0 { access |= self.read; }
        if access & GENERIC_WRITE != 0 { access |= self.write; }
        if access & GENERIC_EXECUTE != 0 { access |= self.exec; }
        if access & GENERIC_ALL != 0 { access |= self.all; }
        access & !GENERIC_MASK
    }

    /// Whether the mapped request asks only for rights this type answers for.
    /// # C: O(1)
    pub const fn admitted(&self, desired: u32) -> bool { self.map(desired) & !self.valid == 0 }

    /// The mask a handle records for an admitted request. # C: O(1)
    pub const fn grant(&self, desired: u32) -> Option<u32> {
        if self.admitted(desired) { Some(self.map(desired)) } else { None }
    }
}

pub const EVENT_QUERY_STATE: u32 = 0x0001;
pub const EVENT_MODIFY_STATE: u32 = 0x0002;
pub const EVENT_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | EVENT_QUERY_STATE | EVENT_MODIFY_STATE;
pub static EVENT: ObjectAccess = ObjectAccess {
    valid: EVENT_ALL_ACCESS,
    read: STANDARD_RIGHTS_READ | EVENT_QUERY_STATE,
    write: STANDARD_RIGHTS_WRITE | EVENT_MODIFY_STATE,
    exec: STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE,
    all: EVENT_ALL_ACCESS,
};

pub const MUTANT_QUERY_STATE: u32 = 0x0001;
pub const MUTANT_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | MUTANT_QUERY_STATE;
pub static MUTANT: ObjectAccess = ObjectAccess {
    valid: MUTANT_ALL_ACCESS,
    read: STANDARD_RIGHTS_READ | MUTANT_QUERY_STATE,
    write: STANDARD_RIGHTS_WRITE,
    exec: STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE,
    all: MUTANT_ALL_ACCESS,
};

pub const SEMAPHORE_QUERY_STATE: u32 = 0x0001;
pub const SEMAPHORE_MODIFY_STATE: u32 = 0x0002;
pub const SEMAPHORE_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | SEMAPHORE_QUERY_STATE | SEMAPHORE_MODIFY_STATE;
pub static SEMAPHORE: ObjectAccess = ObjectAccess {
    valid: SEMAPHORE_ALL_ACCESS,
    read: STANDARD_RIGHTS_READ | SEMAPHORE_QUERY_STATE,
    write: STANDARD_RIGHTS_WRITE | SEMAPHORE_MODIFY_STATE,
    exec: STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE,
    all: SEMAPHORE_ALL_ACCESS,
};

pub const TIMER_QUERY_STATE: u32 = 0x0001;
pub const TIMER_MODIFY_STATE: u32 = 0x0002;
pub const TIMER_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | TIMER_QUERY_STATE | TIMER_MODIFY_STATE;
pub static TIMER: ObjectAccess = ObjectAccess {
    valid: TIMER_ALL_ACCESS,
    read: STANDARD_RIGHTS_READ | TIMER_QUERY_STATE,
    write: STANDARD_RIGHTS_WRITE | TIMER_MODIFY_STATE,
    exec: STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE,
    all: TIMER_ALL_ACCESS,
};

pub const IO_COMPLETION_QUERY_STATE: u32 = 0x0001;
pub const IO_COMPLETION_MODIFY_STATE: u32 = 0x0002;
pub const IO_COMPLETION_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | IO_COMPLETION_QUERY_STATE | IO_COMPLETION_MODIFY_STATE;
pub static IO_COMPLETION: ObjectAccess = ObjectAccess {
    valid: IO_COMPLETION_ALL_ACCESS,
    read: STANDARD_RIGHTS_READ | IO_COMPLETION_QUERY_STATE,
    write: STANDARD_RIGHTS_WRITE | IO_COMPLETION_MODIFY_STATE,
    exec: STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE,
    all: IO_COMPLETION_ALL_ACCESS,
};

pub const KEYEDEVENT_WAIT: u32 = 0x0001;
pub const KEYEDEVENT_WAKE: u32 = 0x0002;
pub const KEYEDEVENT_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED | KEYEDEVENT_WAIT | KEYEDEVENT_WAKE;
/// A keyed event grants no wait-object right through any generic right, yet
/// answers for one asked by name, so a handle to it is waitable only when the
/// caller named the right itself.
pub static KEYED_EVENT: ObjectAccess = ObjectAccess {
    valid: KEYEDEVENT_ALL_ACCESS | SYNCHRONIZE,
    read: STANDARD_RIGHTS_READ | KEYEDEVENT_WAIT,
    write: STANDARD_RIGHTS_WRITE | KEYEDEVENT_WAKE,
    exec: STANDARD_RIGHTS_EXECUTE,
    all: KEYEDEVENT_ALL_ACCESS,
};

pub const DIRECTORY_QUERY: u32 = 0x0001;
pub const DIRECTORY_TRAVERSE: u32 = 0x0002;
pub const DIRECTORY_CREATE_OBJECT: u32 = 0x0004;
pub const DIRECTORY_CREATE_SUBDIRECTORY: u32 = 0x0008;
pub const DIRECTORY_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED
    | DIRECTORY_QUERY | DIRECTORY_TRAVERSE | DIRECTORY_CREATE_OBJECT | DIRECTORY_CREATE_SUBDIRECTORY;
pub static DIRECTORY: ObjectAccess = ObjectAccess {
    valid: DIRECTORY_ALL_ACCESS,
    read: STANDARD_RIGHTS_READ | DIRECTORY_TRAVERSE | DIRECTORY_QUERY,
    write: STANDARD_RIGHTS_WRITE | DIRECTORY_CREATE_SUBDIRECTORY | DIRECTORY_CREATE_OBJECT,
    exec: STANDARD_RIGHTS_EXECUTE | DIRECTORY_TRAVERSE | DIRECTORY_QUERY,
    all: DIRECTORY_ALL_ACCESS,
};

/// The right one keyed-event operation needs. # C: O(1)
pub const fn keyed_event_access(release: bool) -> u32 {
    if release { KEYEDEVENT_WAKE } else { KEYEDEVENT_WAIT }
}

#[cfg(test)] #[path = "tests/nt_access.rs"] mod tests;
