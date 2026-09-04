use super::*;
use alloc::boxed::Box;
use std::sync::{Barrier, mpsc};
use std::time::Duration;

const SOURCE: u32 = 43;
const PREFERRED: u32 = 44;
const REPAIRED: u32 = 45;

fn rq(cpu: u32) -> Runqueue {
    Runqueue::new(cpu as u16,
        Arc::new(Task::new(0xCA00 + cpu, "idle", SchedClass::Idle)))
}

#[test]
fn parked_affinity_change_is_repaired_under_task_pi_before_commit() {
    let source = rq(SOURCE);
    let preferred = rq(PREFERRED);
    let repaired = rq(REPAIRED);
    let get = |cpu| match cpu {
        SOURCE => Some(&source), PREFERRED => Some(&preferred),
        REPAIRED => Some(&repaired), _ => None,
    };
    let task = Arc::new(Task::new(8301, "parked",
        SchedClass::Normal { weight: 1024 }));
    task.cpus_allowed.store(cpu::CpuMask::of(PREFERRED as usize), Ordering::Release);
    task.cpu.store(SOURCE as u16, Ordering::Release);
    task.on_rq.begin_migration();
    assert!(park(SOURCE, &task, PREFERRED));

    // The real affinity path observes Migrating and leaves ownership with the
    // parked handoff; its mask update must be consumed by switch-tail repair.
    crate::live::ttwu::affinity::update_affinity_with(&get, &task,
        Some(cpu::CpuMask::of(REPAIRED as usize)), None);
    let mut saw_locked_commit = false;
    let placed = place_parked_with_probe(&get, SOURCE, &|cpu| cpu != SOURCE,
        &mut |point, cpu, moving| {
            if point == crate::live::migration::MovePoint::DestinationLocked {
                assert_eq!(cpu, REPAIRED);
                assert!(moving.pi_lock.try_lock().is_none(),
                    "TaskPi must span destination selection through rq commit");
                saw_locked_commit = true;
            }
        });
    assert_eq!(placed, Some(REPAIRED));
    assert!(saw_locked_commit);
    assert!(!has_parked(SOURCE));
    assert_eq!(preferred.inner.lock().nr_running(), 0);
    assert_eq!(repaired.inner.lock().nr_running(), 1);
    assert_eq!(task.cpu.load(Ordering::Acquire), REPAIRED as u16);
}

#[test]
fn parked_switch_migration_does_not_deadlock_owner_waiter_update() {
    const FROM: u32 = 46;
    const TO: u32 = 47;
    let source = Arc::new(rq(FROM));
    let destination = Arc::new(rq(TO));
    let owner = Arc::new(Task::new(8302, "parked-pi-owner",
        SchedClass::Normal { weight: 1024 }));
    owner.cpu.store(FROM as u16, Ordering::Release);
    owner.cpus_allowed.store(cpu::CpuMask::of(TO as usize), Ordering::Release);
    owner.on_cpu.store(true, Ordering::Release);
    owner.on_rq.begin_migration();
    assert!(park(FROM, &owner, TO));
    // Model the real switch interval: the outgoing task is still on_cpu and
    // the source rq remains locked across the context switch.
    let switch_rq = source.inner.lock();

    let donor = Arc::new(Task::new(8303, "rt-waiter",
        SchedClass::Rt { prio: 70, policy: crate::SchedPolicy::Fifo }));
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let (lookup_tx, lookup_rx) = mpsc::channel();
    let (updated_tx, updated_rx) = mpsc::channel();
    let (cleanup_tx, cleanup_rx) = mpsc::channel();
    let update_owner = Arc::clone(&owner);
    let update_donor = Arc::clone(&donor);
    let update_source = Arc::clone(&source);
    let update_destination = Arc::clone(&destination);
    let update_entered = Arc::clone(&entered);
    let update_release = Arc::clone(&release);
    let updater = std::thread::spawn(move || {
        let key = crate::pi_prio::PiDonorKey {
            class: update_donor.sched_class(), deadline: 0, special: false,
        };
        let mut node = Box::pin(crate::pi_prio::PiTreeNode::new(
            &update_donor, key, 1, 1, 1));
        let get = |cpu| match cpu {
            FROM => {
                let _ = lookup_tx.send(());
                Some(&*update_source)
            }
            TO => Some(&*update_destination), _ => None,
        };
        assert!(crate::live::pi_boost::update_owner_waiters_with(
            &get, &update_owner, |pi| {
                pi.insert_waiter(node.as_mut());
                update_entered.wait();
                update_release.wait();
            }));
        updated_tx.send(()).unwrap();
        cleanup_rx.recv().unwrap();
        assert!(crate::live::pi_boost::update_owner_waiters_with(
            &get, &update_owner, |pi| pi.remove_waiter(node.as_mut())));
    });

    entered.wait(); // updater owns TaskPi with its waiter edit published
    release.wait();
    lookup_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(owner.pi_lock.try_lock().is_none(),
        "updater must retain TaskPi while blocked on the switch-held source rq");
    // Linux finish_task_switch ordering: clear on_cpu under source rq, then
    // release it. PARKED remains visible for the incoming tail continuation.
    owner.on_cpu.store(false, Ordering::Release);
    let place_source = Arc::clone(&source);
    let place_destination = Arc::clone(&destination);
    let (placed_tx, placed_rx) = mpsc::channel();
    let placer = std::thread::spawn(move || {
        let get = |cpu| match cpu {
            FROM => Some(&*place_source), TO => Some(&*place_destination), _ => None,
        };
        placed_tx.send(place_parked_with(&get, FROM)).unwrap();
    });
    drop(switch_rq);
    assert!(updated_rx.recv_timeout(Duration::from_secs(1)).is_ok(),
        "owner waiter update retained TaskPi while waiting for switch-tail migration");
    assert_eq!(placed_rx.recv_timeout(Duration::from_secs(1)).unwrap(), Some(TO));
    assert!(matches!(owner.sched_class(), SchedClass::Rt { prio: 70, .. }));
    assert_eq!(owner.cpu.load(Ordering::Acquire), TO as u16);
    assert!(owner.on_rq.is_queued(Ordering::Acquire));
    cleanup_tx.send(()).unwrap();
    placer.join().unwrap();
    updater.join().unwrap();
    assert!(matches!(owner.sched_class(), SchedClass::Normal { .. }));
}

#[test]
fn positive_control_switch_tail_really_requires_parked_tasks_task_pi() {
    const FROM: u32 = 48;
    const TO: u32 = 49;
    let source = Arc::new(rq(FROM));
    let destination = Arc::new(rq(TO));
    let task = Arc::new(Task::new(8304, "parked-pi-control",
        SchedClass::Normal { weight: 1024 }));
    task.cpu.store(FROM as u16, Ordering::Release);
    task.cpus_allowed.store(cpu::CpuMask::of(TO as usize), Ordering::Release);
    task.on_rq.begin_migration();
    assert!(park(FROM, &task, TO));
    task.on_cpu.store(false, Ordering::Release);

    let pi = task.pi_lock.lock_irqsave::<RqIrq>();
    let place_source = Arc::clone(&source);
    let place_destination = Arc::clone(&destination);
    let (reached_tx, reached_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let placer = std::thread::spawn(move || {
        let get = |cpu| match cpu {
            FROM => Some(&*place_source), TO => Some(&*place_destination), _ => None,
        };
        done_tx.send(place_parked_with_lock_probe(&get, FROM,
            &|cpu| get(cpu).is_some(), &mut || reached_tx.send(()).unwrap(),
            &mut |_, _, _| {})).unwrap();
    });
    reached_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(matches!(done_rx.try_recv(), Err(mpsc::TryRecvError::Empty)),
        "positive control: switch-tail completed after its TaskPi acquisition failed");
    assert!(has_parked(FROM),
        "positive control: switch-tail cleared PARKED before acquiring TaskPi");
    drop(pi);
    assert_eq!(done_rx.recv_timeout(Duration::from_secs(1)).unwrap(), Some(TO));
    placer.join().unwrap();
}
