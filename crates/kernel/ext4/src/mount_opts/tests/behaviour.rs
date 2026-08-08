// The behavioural option contract: what each key resolves to, and what each
// key REFUSES. Every refusal here was previously an accept-and-drop.

use crate::mount_opts::behaviour::*;
use crate::mount_opts::Ext4MountOpts;
use vfs::VfsError;

fn b(data: &str) -> Result<Ext4Behaviour, VfsError> {
    Ext4MountOpts::parse(data).map(|o| o.behaviour)
}
fn refused(data: &str) -> bool { b(data) == Err(VfsError::Einval) }

/// The answers a mount that writes nothing gets. Getting these wrong is not
/// visible until something goes wrong, which is the worst time to find out.
#[test]
fn the_defaults_are_the_ones_a_root_filesystem_expects() {
    let d = b("").unwrap();
    assert_eq!(d.errors, ErrorsPolicy::RemountRo);
    assert_eq!(d.data, DataMode::Ordered);
    assert_eq!(d.commit_secs, DEFAULT_COMMIT_SECS);
    assert_eq!(d.journal_ioprio, DEFAULT_JOURNAL_IOPRIO);
    assert_eq!(d.max_dir_size_bytes(), None);
    assert!(d.barrier);
    assert!(d.delalloc);
    assert!(d.block_validity);
    assert!(!d.discard);
    assert!(!d.noload);
    assert!(!d.warn_on_error);
}

#[test]
fn the_error_policy_names_are_the_three_the_filesystem_has() {
    assert_eq!(b("errors=continue").unwrap().errors, ErrorsPolicy::Continue);
    assert_eq!(b("errors=panic").unwrap().errors, ErrorsPolicy::Panic);
    assert_eq!(b("errors=remount-ro").unwrap().errors, ErrorsPolicy::RemountRo);
    assert_eq!(ErrorsPolicy::Continue.name(), "continue");
    assert_eq!(ErrorsPolicy::RemountRo.name(), "remount-ro");
    assert_eq!(ErrorsPolicy::Panic.name(), "panic");
    // A near-miss is a miss. `remount-rw` is not a value, and used to mount.
    assert!(refused("errors=remount-rw"));
    assert!(refused("errors="));
    assert!(refused("errors"));
}

#[test]
fn the_journal_data_modes_are_the_three_the_filesystem_has() {
    assert_eq!(b("data=journal").unwrap().data, DataMode::Journal);
    assert_eq!(b("data=ordered").unwrap().data, DataMode::Ordered);
    assert_eq!(b("data=writeback").unwrap().data, DataMode::Writeback);
    assert_eq!(DataMode::Writeback.name(), "writeback");
    assert!(refused("data=sideways"));
}

/// `commit=0` asks for the DEFAULT interval, not for never committing — the
/// one value where the obvious reading is the wrong one.
#[test]
fn a_zero_commit_interval_means_the_default_and_an_absurd_one_is_refused() {
    assert_eq!(b("commit=0").unwrap().commit_secs, DEFAULT_COMMIT_SECS);
    assert_eq!(b("commit=30").unwrap().commit_secs, 30);
    assert!(refused("commit=4294967295"));
    assert!(refused("commit=-1"));
    assert!(refused("commit=5s"));
}

#[test]
fn the_journal_priority_is_a_level_and_the_levels_run_out() {
    assert_eq!(b("journal_ioprio=0").unwrap().journal_ioprio, 0);
    assert_eq!(b("journal_ioprio=7").unwrap().journal_ioprio, MAX_JOURNAL_IOPRIO);
    assert!(refused("journal_ioprio=8"));
}

#[test]
fn the_directory_ceiling_is_a_size_or_no_ceiling_at_all() {
    assert_eq!(b("max_dir_size_kb=0").unwrap().max_dir_size_bytes(), None);
    assert_eq!(b("max_dir_size_kb=1").unwrap().max_dir_size_bytes(), Some(BYTES_PER_KB));
    assert_eq!(b("max_dir_size_kb=64").unwrap().max_dir_size_bytes(), Some(64 * BYTES_PER_KB));
}

/// `barrier` is written three ways and has two answers. `barrier=0` and
/// `nobarrier` are the same answer, which is why they share one field.
#[test]
fn the_three_barrier_spellings_give_two_answers() {
    assert!(b("barrier").unwrap().barrier);
    assert!(b("barrier=1").unwrap().barrier);
    assert!(!b("barrier=0").unwrap().barrier);
    assert!(!b("nobarrier").unwrap().barrier);
    assert!(refused("nobarrier=1"));
}

#[test]
fn each_on_off_pair_is_one_answer_and_the_last_one_written_wins() {
    assert!(b("discard").unwrap().discard);
    assert!(!b("discard,nodiscard").unwrap().discard);
    assert!(!b("nodelalloc").unwrap().delalloc);
    assert!(b("nodelalloc,delalloc").unwrap().delalloc);
    assert!(!b("noblock_validity").unwrap().block_validity);
    assert!(b("noblock_validity,block_validity").unwrap().block_validity);
    assert!(b("warn_on_error").unwrap().warn_on_error);
    assert!(!b("warn_on_error,nowarn_on_error").unwrap().warn_on_error);
}

/// `noload` and `norecovery` are two spellings of one answer, so they must
/// land on one field — two fields is how they come to disagree.
#[test]
fn noload_and_norecovery_are_one_answer() {
    assert!(b("noload").unwrap().noload);
    assert!(b("norecovery").unwrap().noload);
}

/// A remount naming one option keeps the answers it did not name. Re-parsing
/// from the defaults would silently re-enable the barrier a mount had turned
/// off, which is a durability change nobody asked for.
#[test]
fn a_remount_keeps_the_options_it_does_not_name() {
    let first = b("nobarrier,errors=panic,commit=30").unwrap();
    let second = Ext4MountOpts::parse_from("discard", first).unwrap().behaviour;
    assert!(second.discard, "the option the remount named");
    assert!(!second.barrier, "and the ones it did not");
    assert_eq!(second.errors, ErrorsPolicy::Panic);
    assert_eq!(second.commit_secs, 30);
}

/// A key nothing in this filesystem reads is still carried through rather than
/// failing the mount — `/` is the mount at stake.
#[test]
fn a_key_no_consumer_owns_still_does_not_fail_the_mount() {
    let o = Ext4MountOpts::parse("acl,user_xattr,errors=panic").unwrap();
    assert_eq!(o.behaviour.errors, ErrorsPolicy::Panic);
    assert_eq!(o.other.len(), 2, "the keys with no consumer, and only those");
}
