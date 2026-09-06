//! Process-local NT object references and handle lifetime.
//!
//! Module manifest:
//! - object: native object identity, payloads, events, and semaphores.
//! - namespace: named-object namespace and publication.
//! - handle: process-local handle allocation and generation checks.
//! - file_share/file_delete: Windows file sharing and delete disposition.
//! - mutant/timer/completion/token/job/activation/pipe: typed object state.
//! - tests: object identity, signaling, and handle lifetime coverage.

mod activation;
mod completion;
mod desktop;
mod file_delete;
#[allow(dead_code)]
mod file_share;
mod handle;
mod job;
mod mutant;
mod namespace;
mod object;
mod pipe;
mod timer;
mod token;

pub use activation::NtActivationContext;
pub use completion::{NtCompletionPacket, NtCompletionPort};
pub use desktop::{bootstrap_desktop, DesktopBootstrap, DesktopBootstrapError, DesktopError, DesktopRoot, NtDesktop, ThreadDesktop};
pub use namespace::{publish_desktop, publish_window_station, DesktopPublishError};
pub use file_delete::NtDeleteOnClose;
pub use file_share::NtFileShare;
pub use handle::{NtHandle, NtHandleTable};
pub use job::{NtJob, NtJobLimits};
pub use mutant::NtMutant;
pub use namespace::{create_event, create_semaphore, directory_entries, directory_path,
    lookup_directory, lookup_object, make_permanent, make_temporary, object_name, publish_mutant,
    publish_named_pipe, publish_section, publish_symbolic_link, publish_timer,
    release_temporary, resolve_symbolic_links, NamedObjectState, SymbolicLinkResolutionError,
    MAX_SYMBOLIC_LINK_DEPTH};
pub use object::{NtEvent, NtFileInfo, NtObject, NtObjectType, NtSection, NtSemaphore, NtSignalError, NtSymbolicLink};
pub use pipe::{NtPipe, NtPipeConfig, NtPipeEndpoint, NtPipeIo, NtPipeListen, NtPipePeek,
    NtPipeSide, NtPipeWait};
pub use timer::{merge_wait_deadline, timer_expiry_may_have_woken, NtTimer};
pub use token::{sid_for_id, NtToken, NtTokenGroup, NtTokenPrivilege};

#[cfg(test)]
#[path = "nt_object/tests.rs"]
mod tests;
