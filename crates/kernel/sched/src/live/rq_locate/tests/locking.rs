use super::*;
use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

#[test]
fn already_held_task_pi_waits_out_migration_and_revalidates() {
    let cpus = Arc::new(Cpus::new(&[REMOTE_CPU]));
    let task = normal_task(81);
    task.cpu.store(REMOTE_CPU as u16, Ordering::Release);
    task.on_rq.begin_migration();
    let entered = Arc::new(AtomicBool::new(false));
    let clear_task = Arc::clone(&task);
    let clear_entered = Arc::clone(&entered);
    let worker = std::thread::spawn(move || {
        while !clear_entered.load(Ordering::Acquire) { std::hint::spin_loop(); }
        clear_task.on_rq.store(true, Ordering::Release);
    });
    let pi = task.pi_lock.lock_irqsave::<RqIrq>();
    let StableTaskGuard::Owned(_guard) = __task_rq_lock_with(&|cpu| {
        entered.store(true, Ordering::Release);
        cpus.get(cpu)
    }, &task, pi) else { panic!("migrating task did not resolve its rq") };
    worker.join().unwrap();
    assert!(entered.load(Ordering::Acquire));
    assert!(task.on_rq.is_queued(Ordering::Acquire));
}

#[test]
fn full_task_rq_lock_drops_task_pi_while_waiting_for_migration() {
    let cpus = Arc::new(Cpus::new(&[REMOTE_CPU]));
    let task = normal_task(82);
    task.cpu.store(REMOTE_CPU as u16, Ordering::Release);
    task.on_rq.begin_migration();
    let entered = Arc::new(AtomicBool::new(false));
    let (done_tx, done_rx) = mpsc::channel();

    let lock_cpus = Arc::clone(&cpus);
    let lock_task = Arc::clone(&task);
    let lock_entered = Arc::clone(&entered);
    let locker = std::thread::spawn(move || {
        let StableTaskGuard::Owned(_guard) = task_rq_lock_with(&|cpu| {
            lock_entered.store(true, Ordering::Release);
            lock_cpus.get(cpu)
        }, &lock_task) else { panic!("migrating task did not resolve its rq") };
        done_tx.send(()).unwrap();
    });
    while !entered.load(Ordering::Acquire) { std::hint::spin_loop(); }

    let move_task = Arc::clone(&task);
    let mover = std::thread::spawn(move || {
        let _pi = move_task.pi_lock.lock_irqsave::<RqIrq>();
        move_task.on_rq.store(true, Ordering::Release);
    });
    assert!(done_rx.recv_timeout(Duration::from_secs(1)).is_ok(),
        "full task-rq retry retained TaskPi and blocked migration completion");
    mover.join().unwrap();
    locker.join().unwrap();
    assert!(task.on_rq.is_queued(Ordering::Acquire));
}
