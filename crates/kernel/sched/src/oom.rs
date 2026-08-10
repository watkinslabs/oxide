//! Out-of-memory victim selection and fatal signal delivery.
//
// Module manifest:
// - score: `oom_score_adj` ABI, the PMM-supplied memory observer, the badness
//   function, and `/proc/<pid>/oom_score`.
// - select: the selection DECISION as pure data — one scan, one policy, shared
//   by the global and control-group entries so neither can drift.
// - reap: the reaper's rules — which mappings may be torn down, when to stop
//   trying, and the queue of victims awaiting it. Ungated.
// - reaper: the kthread that consumes that queue. No policy of its own.
// - kill: the entries (`out_of_memory`, `kill_memcg`, the fault-path form),
//   candidate construction from live tasks, and kill accounting.
// - tests: hosted end-to-end selection over real tasks and a stub observer.

mod kill;
pub mod reap;
#[cfg(target_os = "oxide-kernel")]
mod reaper;
mod score;
mod select;
#[cfg(test)]
mod tests;

pub use kill::{kill_count, kill_memcg, out_of_memory, pagefault_out_of_memory, FaultOutcome, Outcome, Scope};
pub use score::{install_managed_pages, install_memory_observer, task_score, OomMemory,
                OomMemoryObserver, OOM_SCORE_ADJ_MAX, OOM_SCORE_ADJ_MIN, PSS_UNITS_PER_PAGE};
pub use reap::{install_oom_zapper, reapable, reapable_vma, OomZapper, ReapStep,
               MAX_REAP_ATTEMPTS, REAP_DELAY_NS, REAP_RETRY_NS};
#[cfg(target_os = "oxide-kernel")]
pub use reaper::spawn_oom_reaper;
pub use select::{select_victim, Candidate, Selection};
