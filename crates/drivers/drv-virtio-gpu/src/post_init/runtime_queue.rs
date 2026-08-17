//! Runtime queue ownership: IRQ callbacks defer, workers retire commands.

use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};

use sync::{MutexGate as RuntimeQueueLockClass, Spinlock, TaskList as DriverLockClass};

use super::{ctx_lock, damage, present};

const COMMAND_CAPACITY: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RuntimeCmd {
    Create2d { res_id: u32, fmt: u32, w: u32, h: u32 },
    AttachBacking { res_id: u32, dma: u64, bytes: u32 },
    DetachBacking { res_id: u32 },
    Unref { res_id: u32 },
    Transfer { res_id: u32, x: u32, y: u32, w: u32, h: u32, off: u64 },
    SetScanout { res_id: u32, w: u32, h: u32 },
    Flush { res_id: u32, x: u32, y: u32, w: u32, h: u32 },
    QueueCursorUpdate { res_id: u32, w: u32, h: u32, x: i32, y: i32, hot_x: i32, hot_y: i32 },
    UpdateCursor { res_id: u32, w: u32, h: u32, x: i32, y: i32, hot_x: i32, hot_y: i32 },
    MoveCursor { x: i32, y: i32 },
}

impl RuntimeCmd {
    fn ctrl(self) -> bool {
        !matches!(self, Self::UpdateCursor { .. } | Self::MoveCursor { .. })
    }

    fn encode_ctrl(self, buf: &mut [u8]) -> usize {
        match self {
            Self::Create2d { res_id, fmt, w, h } => crate::encode_resource_create_2d(buf, res_id, fmt, w, h),
            Self::AttachBacking { res_id, dma, bytes } => crate::encode_resource_attach_backing_one(buf, res_id, dma, bytes),
            Self::DetachBacking { res_id } => crate::encode_resource_detach_backing(buf, res_id),
            Self::Unref { res_id } => crate::encode_resource_unref(buf, res_id),
            Self::Transfer { res_id, x, y, w, h, off } => crate::encode_transfer_to_host_2d(buf, res_id, x, y, w, h, off),
            Self::SetScanout { res_id, w, h } => crate::encode_set_scanout(buf, 0, res_id, 0, 0, w, h),
            Self::Flush { res_id, x, y, w, h } => crate::encode_resource_flush(buf, res_id, x, y, w, h),
            Self::QueueCursorUpdate { .. } | Self::UpdateCursor { .. } | Self::MoveCursor { .. } => 0,
        }
    }

    fn encode_cursor(self, buf: &mut [u8]) -> usize {
        match self {
            Self::UpdateCursor { res_id, w, h, x, y, hot_x, hot_y } =>
                crate::encode_update_cursor(buf, res_id, w, h, x, y, hot_x, hot_y),
            Self::MoveCursor { x, y } => crate::encode_move_cursor(buf, x, y),
            _ => 0,
        }
    }

    fn after_ctrl(self) -> Option<Self> {
        match self {
            Self::QueueCursorUpdate { res_id, w, h, x, y, hot_x, hot_y } =>
                Some(Self::UpdateCursor { res_id, w, h, x, y, hot_x, hot_y }),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
enum QueueKind { Ctrl, Cursor }

struct CommandRing {
    cmds: [Option<RuntimeCmd>; COMMAND_CAPACITY],
    head: usize,
    len: usize,
    running: bool,
    bound: Option<present::Binding>,
}

impl CommandRing {
    const fn new() -> Self {
        Self { cmds: [None; COMMAND_CAPACITY], head: 0, len: 0, running: false, bound: None }
    }

    fn can_push(&self, count: usize) -> bool {
        count != 0 && count <= COMMAND_CAPACITY.saturating_sub(self.len)
    }

    fn push(&mut self, cmds: &[RuntimeCmd]) {
        for cmd in cmds {
            let tail = (self.head + self.len) % COMMAND_CAPACITY;
            self.cmds[tail] = Some(*cmd);
            self.len += 1;
        }
    }

    /// Admit an entire command sequence or leave the FIFO untouched.
    fn push_if_space(&mut self, cmds: &[RuntimeCmd]) -> bool {
        if !self.can_push(cmds.len()) { return false; }
        self.push(cmds);
        true
    }

    fn pop(&mut self) -> Option<RuntimeCmd> {
        if self.len == 0 { return None; }
        let cmd = self.cmds[self.head].take();
        self.head = (self.head + 1) % COMMAND_CAPACITY;
        self.len -= 1;
        cmd
    }

    fn clear(&mut self) {
        while self.pop().is_some() {}
    }

    fn present_plan(&self, res_id: u32, w: u32, h: u32,
        rect: present::Rect) -> ([RuntimeCmd; present::MAX_STEPS], usize, Option<present::Binding>) {
        let next = present::Binding { res_id, w, h };
        let (steps, n) = present::plan(self.bound, next, rect, damage::BYTES_PER_PIXEL as u32);
        let mut cmds = [RuntimeCmd::Unref { res_id: 0 }; present::MAX_STEPS];
        for (out, step) in cmds.iter_mut().zip(steps.iter()).take(n) {
            *out = match *step {
                present::Step::Transfer { rect, offset } =>
                    RuntimeCmd::Transfer { res_id, x: rect.x, y: rect.y, w: rect.w, h: rect.h, off: offset },
                present::Step::SetScanout => RuntimeCmd::SetScanout { res_id, w, h },
                present::Step::Flush { rect } =>
                    RuntimeCmd::Flush { res_id, x: rect.x, y: rect.y, w: rect.w, h: rect.h },
            };
        }
        let bound = steps.iter().take(n).any(|step| matches!(step, present::Step::SetScanout))
            .then_some(next);
        (cmds, n, bound)
    }
}

struct RuntimeQueue {
    state: Spinlock<CommandRing, RuntimeQueueLockClass>,
    wait: sched::live::WaitList,
    completion_queued: AtomicBool,
}

impl RuntimeQueue {
    const fn new() -> Self {
        Self {
            state: Spinlock::new(CommandRing::new()),
            wait: sched::live::WaitList::new(),
            completion_queued: AtomicBool::new(false),
        }
    }

    fn schedule_if_idle(state: &mut CommandRing, key: virtio::VirtioChildDeviceKey,
        work: sched::live::workqueue::WorkFn) -> bool {
        if state.running { return true; }
        state.running = true;
        if sched::live::workqueue::queue_work(work, key.raw() as usize) { return true; }
        state.clear();
        state.running = false;
        false
    }

    fn enqueue(&self, key: virtio::VirtioChildDeviceKey, kind: QueueKind, cmds: &[RuntimeCmd]) -> bool {
        let mut state = self.state.lock_bh::<super::CtxBh>();
        Self::enqueue_locked(&mut state, key, kind, cmds)
    }

    /// Softirq half of CTRLQ admission.  The process half above excludes this
    /// softirq with `lock_bh`; the softirq itself takes the same short lock
    /// bare, exactly as the queue-lock contract requires.
    fn enqueue_from_softirq(&self, key: virtio::VirtioChildDeviceKey,
        kind: QueueKind, cmds: &[RuntimeCmd]) -> bool {
        let mut state = self.state.lock();
        Self::enqueue_locked(&mut state, key, kind, cmds)
    }

    fn enqueue_locked(state: &mut CommandRing, key: virtio::VirtioChildDeviceKey,
        kind: QueueKind, cmds: &[RuntimeCmd]) -> bool {
        if cmds.iter().any(|cmd| cmd.ctrl() != matches!(kind, QueueKind::Ctrl)) { return false; }
        let work = match kind { QueueKind::Ctrl => ctrl_work, QueueKind::Cursor => cursor_work };
        if !state.push_if_space(cmds) { return false; }
        Self::schedule_if_idle(state, key, work)
    }

    fn enqueue_present(&self, key: virtio::VirtioChildDeviceKey, res_id: u32,
        w: u32, h: u32, rect: present::Rect) -> bool {
        let mut state = self.state.lock_bh::<super::CtxBh>();
        let (cmds, n, bound) = state.present_plan(res_id, w, h, rect);
        if n == 0 { return true; }
        if !state.push_if_space(&cmds[..n]) { return false; }
        if let Some(bound) = bound { state.bound = Some(bound); }
        Self::schedule_if_idle(&mut state, key, ctrl_work)
    }

    fn enqueue_destroy(&self, key: virtio::VirtioChildDeviceKey, res_id: u32) -> bool {
        let mut state = self.state.lock_bh::<super::CtxBh>();
        if !state.push_if_space(&[RuntimeCmd::DetachBacking { res_id }, RuntimeCmd::Unref { res_id }]) {
            return false;
        }
        if state.bound.is_some_and(|binding| binding.res_id == res_id) { state.bound = None; }
        Self::schedule_if_idle(&mut state, key, ctrl_work)
    }

    fn take(&self) -> Option<RuntimeCmd> {
        let mut state = self.state.lock_bh::<super::CtxBh>();
        let cmd = state.pop();
        if cmd.is_none() { state.running = false; }
        cmd
    }

    fn cancel(&self) {
        let mut state = self.state.lock_bh::<super::CtxBh>();
        state.clear();
        state.running = false;
    }

    fn running(&self) -> bool { self.state.lock_bh::<super::CtxBh>().running }

    fn irq(&self, key: virtio::VirtioChildDeviceKey, kind: QueueKind) {
        if self.completion_queued.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return;
        }
        let work = match kind { QueueKind::Ctrl => ctrl_completion_work, QueueKind::Cursor => cursor_completion_work };
        if sched::live::workqueue::queue_work(work, key.raw() as usize) { return; }
        self.completion_queued.store(false, Ordering::Release);
        // A full bounded workqueue must not strand a device completion. The
        // generic wake path is allocation-free and safe from this callback.
        self.wait.wake_all();
    }

    fn complete_irq_work(&self) {
        self.completion_queued.store(false, Ordering::Release);
        self.wait.wake_all();
    }
}

pub(super) struct RuntimeEvents {
    key: virtio::VirtioChildDeviceKey,
    ctrl: RuntimeQueue,
    cursor: RuntimeQueue,
    cancelled: AtomicBool,
    idle_wait: sched::live::WaitList,
}

impl RuntimeEvents {
    fn idle(&self) -> bool { !self.ctrl.running() && !self.cursor.running() }
}

static RUNTIME: Spinlock<Vec<Arc<RuntimeEvents>>, DriverLockClass> = Spinlock::new(Vec::new());

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
type RuntimeIrq = hal_x86_64::X86IrqGate;
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
type RuntimeIrq = hal_aarch64::ArmIrqGate;
#[cfg(not(target_os = "oxide-kernel"))]
type RuntimeIrq = sync::NoopIrq;

fn find(key: virtio::VirtioChildDeviceKey) -> Option<Arc<RuntimeEvents>> {
    RUNTIME.lock_irqsave::<RuntimeIrq>().iter().find(|entry| entry.key == key).cloned()
}

pub(super) fn install(key: virtio::VirtioChildDeviceKey) -> bool {
    let mut entries = RUNTIME.lock_irqsave::<RuntimeIrq>();
    if entries.iter().any(|entry| entry.key == key) { return false; }
    entries.push(Arc::new(RuntimeEvents {
        key,
        ctrl: RuntimeQueue::new(),
        cursor: RuntimeQueue::new(),
        cancelled: AtomicBool::new(false),
        idle_wait: sched::live::WaitList::new(),
    }));
    true
}

pub(super) fn cancel(key: virtio::VirtioChildDeviceKey) {
    let Some(events) = find(key) else { return };
    events.cancelled.store(true, Ordering::Release);
    events.ctrl.wait.wake_all();
    events.cursor.wait.wake_all();
    // SAFETY: removal is process context; every worker observes cancelled and
    // returns its owned virtqueue before it marks itself idle.
    unsafe {
        let _ = sched::live::wait_event_uninterruptible(&events.idle_wait, || events.idle());
    }
    RUNTIME.lock_irqsave::<RuntimeIrq>().retain(|entry| !Arc::ptr_eq(entry, &events));
}

pub(super) fn enqueue_ctrl(key: virtio::VirtioChildDeviceKey, cmds: &[RuntimeCmd]) -> bool {
    let Some(events) = find(key) else { return false };
    if events.cancelled.load(Ordering::Acquire) { return false; }
    events.ctrl.enqueue(key, QueueKind::Ctrl, cmds)
}

/// CTRLQ admission from the `FbconFlush` softirq. # C: O(1)
pub(super) fn enqueue_ctrl_from_softirq(key: virtio::VirtioChildDeviceKey,
    cmds: &[RuntimeCmd]) -> bool {
    let Some(events) = find(key) else { return false };
    if events.cancelled.load(Ordering::Acquire) { return false; }
    events.ctrl.enqueue_from_softirq(key, QueueKind::Ctrl, cmds)
}

pub(super) fn enqueue_cursor(key: virtio::VirtioChildDeviceKey, cmds: &[RuntimeCmd]) -> bool {
    let Some(events) = find(key) else { return false };
    if events.cancelled.load(Ordering::Acquire) { return false; }
    events.cursor.enqueue(key, QueueKind::Cursor, cmds)
}

pub(super) fn enqueue_present(key: virtio::VirtioChildDeviceKey, res_id: u32,
    w: u32, h: u32, rect: present::Rect) -> bool {
    let Some(events) = find(key) else { return false };
    if events.cancelled.load(Ordering::Acquire) { return false; }
    events.ctrl.enqueue_present(key, res_id, w, h, rect)
}

pub(super) fn enqueue_destroy(key: virtio::VirtioChildDeviceKey, res_id: u32) -> bool {
    let Some(events) = find(key) else { return false };
    if events.cancelled.load(Ordering::Acquire) { return false; }
    events.ctrl.enqueue_destroy(key, res_id)
}

pub(super) fn ctrlq_irq(key: virtio::VirtioChildDeviceKey) {
    if let Some(events) = find(key) { events.ctrl.irq(key, QueueKind::Ctrl); }
}

pub(super) fn cursorq_irq(key: virtio::VirtioChildDeviceKey) {
    if let Some(events) = find(key) { events.cursor.irq(key, QueueKind::Cursor); }
}

fn ctrl_completion_work(raw_key: usize) { complete_irq_work(raw_key, QueueKind::Ctrl); }
fn cursor_completion_work(raw_key: usize) { complete_irq_work(raw_key, QueueKind::Cursor); }

fn complete_irq_work(raw_key: usize, kind: QueueKind) {
    let key = virtio::VirtioChildDeviceKey::from_raw(raw_key as u32);
    let Some(events) = find(key) else { return };
    match kind { QueueKind::Ctrl => events.ctrl.complete_irq_work(), QueueKind::Cursor => events.cursor.complete_irq_work() }
}

fn ctrl_work(raw_key: usize) { run_queue(raw_key, QueueKind::Ctrl); }
fn cursor_work(raw_key: usize) { run_queue(raw_key, QueueKind::Cursor); }

fn run_queue(raw_key: usize, kind: QueueKind) {
    let key = virtio::VirtioChildDeviceKey::from_raw(raw_key as u32);
    let Some(events) = find(key) else { return };
    let queue = match kind { QueueKind::Ctrl => &events.ctrl, QueueKind::Cursor => &events.cursor };
    loop {
        if events.cancelled.load(Ordering::Acquire) {
            queue.cancel();
            events.idle_wait.wake_all();
            return;
        }
        let Some(cmd) = queue.take() else {
            events.idle_wait.wake_all();
            return;
        };
        if let Some(cursor) = cmd.after_ctrl() {
            if enqueue_cursor(key, &[cursor]) { continue; }
            mark_quiesced(key);
            queue.cancel();
            events.idle_wait.wake_all();
            return;
        }
        let Some(mut owner) = take_queue(key, kind) else {
            queue.cancel();
            events.idle_wait.wake_all();
            return;
        };
        let ok = match kind {
            // SAFETY: `take_queue` above handed this worker exclusive ownership of
            // `owner`, so `buf_va`/`buf_dma` name the one 4 KiB command frame paired
            // with `owner.queue` and nothing else can submit on it concurrently; the
            // worker runs in process context holding no driver lock, which is what
            // lets `submit_one_wait` sleep on the completion.
            QueueKind::Ctrl => unsafe {
                super::probe::submit_one_wait(owner.buf_va, owner.buf_dma,
                    |buf| cmd.encode_ctrl(buf), &mut owner.queue, &super::probe::CompletionWaits {
                        wake: &queue.wait, cancelled: &events.cancelled,
                    })
            },
            // SAFETY: same exclusive `owner` ownership as the Ctrl arm; the cursor
            // path writes a disjoint offset in that frame and has no response
            // descriptor, so the frame is device-readable only.
            QueueKind::Cursor => unsafe {
                super::probe::submit_cursor_one_wait(owner.buf_va, owner.buf_dma,
                    |buf| cmd.encode_cursor(buf), &mut owner.queue, &queue.wait, &events.cancelled)
            },
        };
        let ok = ok && match kind {
            QueueKind::Ctrl => response_is_nodata(owner.buf_va),
            QueueKind::Cursor => true,
        };
        put_queue(key, kind, owner);
        if !ok {
            mark_quiesced(key);
            queue.cancel();
            events.idle_wait.wake_all();
            return;
        }
    }
}

fn response_is_nodata(buf_va: *mut u8) -> bool {
    // SAFETY: submit_one_wait observed the used entry with acquire ordering;
    // its fixed response header remains inside the worker-owned 4 KiB frame.
    let response = unsafe {
        core::slice::from_raw_parts(buf_va.add(super::probe::RESP_OFF as usize), 24)
    };
    crate::parse_nodata_resp(response).is_ok()
}

struct TakenQueue {
    queue: virtio::VirtioSplitQueue,
    buf_va: *mut u8,
    buf_dma: u64,
}

fn take_queue(key: virtio::VirtioChildDeviceKey, kind: QueueKind) -> Option<TakenQueue> {
    let mut ctxs = ctx_lock();
    let ctx = ctxs.iter_mut().find(|ctx| ctx.device_key == key)?;
    if ctx.quiesced { return None; }
    let queue = match kind { QueueKind::Ctrl => ctx.ctrlq.take(), QueueKind::Cursor => ctx.cursorq.take() }?;
    Some(TakenQueue { queue, buf_va: ctx.cmd_buf_va as *mut u8, buf_dma: ctx.cmd_buf_dma })
}

fn put_queue(key: virtio::VirtioChildDeviceKey, kind: QueueKind, owner: TakenQueue) {
    let mut ctxs = ctx_lock();
    let Some(ctx) = ctxs.iter_mut().find(|ctx| ctx.device_key == key) else { return };
    match kind {
        QueueKind::Ctrl if ctx.ctrlq.is_none() => ctx.ctrlq = Some(owner.queue),
        QueueKind::Cursor if ctx.cursorq.is_none() => ctx.cursorq = Some(owner.queue),
        _ => {}
    }
}

fn mark_quiesced(key: virtio::VirtioChildDeviceKey) {
    if let Some(ctx) = ctx_lock().iter_mut().find(|ctx| ctx.device_key == key) { ctx.quiesced = true; }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flush(id: u32) -> RuntimeCmd { RuntimeCmd::Flush { res_id: id, x: 0, y: 0, w: 1, h: 1 } }

    #[test]
    fn command_ring_keeps_fifo_order_without_allocation_on_retirement() {
        let mut ring = CommandRing::new();
        ring.push(&[flush(1), flush(2), flush(3)]);
        assert_eq!(ring.pop(), Some(flush(1)));
        assert_eq!(ring.pop(), Some(flush(2)));
        assert_eq!(ring.pop(), Some(flush(3)));
        assert_eq!(ring.pop(), None);
    }

    #[test]
    fn command_ring_refuses_a_batch_before_any_partial_enqueue() {
        let mut ring = CommandRing::new();
        for id in 0..(COMMAND_CAPACITY - 1) as u32 { assert!(ring.push_if_space(&[flush(id)])); }
        assert!(!ring.push_if_space(&[flush(COMMAND_CAPACITY as u32), flush(COMMAND_CAPACITY as u32 + 1)]));
        assert_eq!(ring.len, COMMAND_CAPACITY - 1);
        assert_eq!(ring.pop(), Some(flush(0)));
    }

    #[test]
    fn ctrl_barrier_emits_the_exact_cursor_command_after_retirement() {
        let barrier = RuntimeCmd::QueueCursorUpdate {
            res_id: 7, w: 64, h: 32, x: -3, y: 9, hot_x: 2, hot_y: 4,
        };
        assert_eq!(barrier.after_ctrl(), Some(RuntimeCmd::UpdateCursor {
            res_id: 7, w: 64, h: 32, x: -3, y: 9, hot_x: 2, hot_y: 4,
        }));
    }

    #[test]
    fn ctrl_owner_remembers_a_committed_binding_before_the_next_plan() {
        let mut ring = CommandRing::new();
        let rect = present::Rect::full(8, 4);
        let (first, n, bound) = ring.present_plan(7, 8, 4, rect);
        assert_eq!(&first[..n], &[
            RuntimeCmd::Transfer { res_id: 7, x: 0, y: 0, w: 8, h: 4, off: 0 },
            RuntimeCmd::SetScanout { res_id: 7, w: 8, h: 4 },
            RuntimeCmd::Flush { res_id: 7, x: 0, y: 0, w: 8, h: 4 },
        ]);
        ring.bound = bound;
        let (same, n, bound) = ring.present_plan(7, 8, 4, rect);
        assert_eq!(&same[..n], &[
            RuntimeCmd::Transfer { res_id: 7, x: 0, y: 0, w: 8, h: 4, off: 0 },
            RuntimeCmd::Flush { res_id: 7, x: 0, y: 0, w: 8, h: 4 },
        ]);
        assert_eq!(bound, None);
    }
}
