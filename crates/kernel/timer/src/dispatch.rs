use super::*;

pub fn next_deadline_ns(now_ns: u64) -> Option<u64> {
    let mut earliest: Option<u64> = None;
    let mut consider = |deadline: u64| {
        let deadline = deadline.max(now_ns);
        earliest = Some(match earliest { None => deadline, Some(cur) => cur.min(deadline) });
    };
    for entry in TIMERS.lock().iter() { consider(entry.last_ns.saturating_add(entry.interval_ns)); }
    for node in ONESHOTS.lock().head.iter() {
        let mut node = node;
        loop { consider(node.timer.deadline_ns); match node.next.as_ref() { Some(next) => node = next, None => break } }
    }
    earliest
}

pub fn run_state() -> (usize, usize) { (RUN_PHASE.load(Ordering::Relaxed), RUN_FN.load(Ordering::Relaxed)) }
pub fn run_due(now_ns: u64) { while run_due_budgeted(now_ns, DISPATCH_BATCH) {} }

pub fn run_due_budgeted(now_ns: u64, budget: usize) -> bool {
    let limit = budget.min(DISPATCH_BATCH);
    if limit == 0 { return has_due(now_ns); }
    let mut due: [Option<TimerFn>; DISPATCH_BATCH] = [None; DISPATCH_BATCH];
    let mut due_len = 0;
    let mut due_ids: [Option<TimerId>; DISPATCH_BATCH] = [None; DISPATCH_BATCH];
    let mut due_id_len = 0;
    RUN_PHASE.store(PHASE_SCAN_PERIODIC, Ordering::Relaxed);
    {
        let mut g = TIMERS.lock();
        for e in g.iter_mut() {
            if due_len >= limit { break; }
            if now_ns.saturating_sub(e.last_ns) >= e.interval_ns { e.last_ns = now_ns; due[due_len] = Some(e.f); due_len += 1; }
        }
    }
    RUN_PHASE.store(PHASE_SCAN_ONESHOT, Ordering::Relaxed);
    {
        let g = ONESHOTS.lock(); let mut node = g.head.as_ref();
        while let Some(current) = node {
            if due_id_len >= limit.saturating_sub(due_len) { break; }
            if current.timer.deadline_ns <= now_ns { due_ids[due_id_len] = Some(current.timer.id); due_id_len += 1; }
            node = current.next.as_ref();
        }
    }
    let mut one: [Option<Box<OneShotNode>>; DISPATCH_BATCH] = core::array::from_fn(|_| None);
    let mut one_len = 0;
    {
        let mut g = ONESHOTS.lock();
        for id in due_ids[..due_id_len].iter().flatten() {
            let mut link = &mut g.head;
            while let Some(node) = link.as_ref() {
                if node.timer.id == *id {
                    let mut node = link.take().expect("one-shot link disappeared"); *link = node.next.take(); one[one_len] = Some(node); one_len += 1; break;
                }
                link = &mut link.as_mut().expect("one-shot link disappeared").next;
            }
        }
    }
    RUN_PHASE.store(PHASE_FIRE_PERIODIC, Ordering::Relaxed);
    for f in due[..due_len].iter().flatten() { RUN_FN.store(*f as usize, Ordering::Relaxed); (*f)(now_ns); }
    RUN_FN.store(0, Ordering::Relaxed); RUN_PHASE.store(PHASE_FIRE_ONESHOT, Ordering::Relaxed);
    for mut node in one[..one_len].iter_mut().filter_map(Option::take) {
        let id = node.timer.id; let entry = &mut node.timer;
        let cancelled = { let mut c = CANCELLED_ONESHOTS.lock(); let mut found = false;
            for pos in 0..c.len { if c.ids[pos] == id.raw() { c.ids[pos] = c.ids[c.len - 1]; c.len -= 1; found = true; break; } } found };
        if cancelled { drop_oneshot_arg(entry); }
        else if let Some(f) = entry.f { RUN_FN.store(f as usize, Ordering::Relaxed); f(entry.arg); }
        else if let Some(f) = entry.owned_f { RUN_FN.store(f as usize, Ordering::Relaxed); f(entry.arg, id); drop_oneshot_arg(entry); }
    }
    RUN_FN.store(0, Ordering::Relaxed); RUN_PHASE.store(PHASE_IDLE, Ordering::Relaxed); has_due(now_ns)
}

pub(super) fn drop_oneshot_arg(entry: &OneShot) { if let Some(drop_arg) = entry.owned_drop { drop_arg(entry.arg); } }
fn has_due(now_ns: u64) -> bool {
    if TIMERS.lock().iter().any(|e| now_ns.saturating_sub(e.last_ns) >= e.interval_ns) { return true; }
    ONESHOTS.lock().head.as_ref().is_some_and(|head| { let mut node = Some(head.as_ref()); while let Some(current) = node { if current.timer.deadline_ns <= now_ns { return true; } node = current.next.as_ref().map(Box::as_ref); } false })
}
