//! The virtual camera's transport: a list of buffers it has been handed and a
//! frame counter.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use sync::{Spinlock, TaskList};
use syscall::errno::Errno;

use v4l2::format::{Fract, FormatDesc, PixFormat};
use v4l2::ops::{InputDesc, VideoOps};

/// What the tick needs to produce one frame.
#[derive(Clone, Debug)]
pub struct Pending {
    pub index: u32,
    pub sequence: u32,
}

/// One virtual camera.
pub struct Vivid {
    state: Spinlock<VividState, TaskList>,
}

struct VividState {
    streaming: bool,
    /// Buffers the core handed over, oldest first.
    handed: VecDeque<u32>,
    format: PixFormat,
    interval: Fract,
    sequence: u32,
    /// Monotonic nanoseconds the previous frame was produced at, zero before
    /// the first.
    last_frame_ns: u64,
}

impl Vivid {
    /// # C: O(1)
    pub fn new() -> Arc<Vivid> {
        Arc::new(Vivid {
            state: Spinlock::new(VividState {
                streaming: false, handed: VecDeque::new(),
                format: PixFormat::empty(),
                interval: crate::tables::INTERVALS[0],
                sequence: 0, last_frame_ns: 0,
            }),
        })
    }

    /// Is the device producing frames? # C: O(1)
    pub fn streaming(&self) -> bool { self.state.lock().streaming }

    /// The format frames are produced in. # C: O(1)
    pub fn format(&self) -> PixFormat { self.state.lock().format }

    /// Nanoseconds between frames, from the selected interval. # C: O(1)
    pub fn frame_period_ns(&self) -> u64 {
        let interval = self.state.lock().interval;
        period_ns(interval)
    }

    /// Take the next buffer to fill, if one is waiting and `now` has reached
    /// the next frame's due time. The sequence rides with it so a dropped
    /// frame shows as a gap rather than silently renumbering the stream.
    /// # C: O(1)
    pub fn take_due(&self, now_ns: u64) -> Option<Pending> {
        let mut state = self.state.lock();
        if !state.streaming { return None; }
        let period = period_ns(state.interval);
        if !due(state.last_frame_ns, now_ns, period) { return None; }
        let index = state.handed.pop_front()?;
        // The clock advances by whole periods from the previous frame rather
        // than being reset to now, so a late tick does not push every
        // subsequent frame later and the stream keeps its nominal rate.
        state.last_frame_ns = next_deadline(state.last_frame_ns, now_ns, period);
        state.sequence = state.sequence.wrapping_add(1);
        Some(Pending { index, sequence: state.sequence })
    }
}

/// Nanoseconds one frame lasts, from its interval. A meaningless interval
/// falls back to a thirtieth of a second rather than dividing by zero.
/// # C: O(1)
pub fn period_ns(interval: Fract) -> u64 {
    if interval.denominator == 0 || interval.numerator == 0 { return 1_000_000_000 / 30; }
    (interval.numerator as u64).saturating_mul(1_000_000_000) / interval.denominator as u64
}

/// Is a frame due? The first frame of a stream is due immediately, so a
/// program that starts and waits does not sit out a whole period first.
/// # C: O(1)
pub fn due(last_ns: u64, now_ns: u64, period_ns: u64) -> bool {
    if last_ns == 0 { return true; }
    now_ns.saturating_sub(last_ns) >= period_ns
}

/// The time to book this frame against: the previous frame plus whole periods,
/// caught up to `now` if the tick fell more than one period behind.
///
/// Advancing by periods rather than to `now` is what keeps the nominal rate:
/// resetting the clock on every late tick makes each frame later than the last
/// and the stream drifts away from the rate the caller asked for.
/// # C: O(1)
pub fn next_deadline(last_ns: u64, now_ns: u64, period_ns: u64) -> u64 {
    if last_ns == 0 || period_ns == 0 { return now_ns; }
    let elapsed = now_ns.saturating_sub(last_ns);
    // More than a second behind means the tick stopped for a reason unrelated
    // to pacing; resynchronising beats crediting the stream with a second of
    // frames it never produced. The gap has to be measured BEFORE the
    // period-advance, because advancing always leaves a residual smaller than
    // one period and would hide any stall however long.
    if elapsed > 1_000_000_000 { return now_ns; }
    let whole = elapsed / period_ns;
    last_ns.saturating_add(whole.saturating_mul(period_ns))
}

impl VideoOps for Vivid {
    /// # C: O(1)
    fn formats(&self) -> &'static [FormatDesc] { crate::tables::FORMATS }
    /// # C: O(1)
    fn inputs(&self) -> &'static [InputDesc] { crate::tables::INPUTS }
    /// # C: O(1)
    fn set_format(&self, format: &PixFormat) { self.state.lock().format = *format; }
    /// # C: O(1)
    fn set_input(&self, _index: u32) -> Result<(), Errno> { Ok(()) }
    /// # C: O(1)
    fn set_interval(&self, interval: Fract) { self.state.lock().interval = interval; }

    /// # C: O(handed)
    fn start_streaming(&self, handed: &[u32]) -> Result<(), Errno> {
        let mut state = self.state.lock();
        state.streaming = true;
        state.sequence = 0;
        state.last_frame_ns = 0;
        state.handed.clear();
        state.handed.extend(handed.iter().copied());
        Ok(())
    }

    /// # C: O(1)
    fn stop_streaming(&self) {
        let mut state = self.state.lock();
        state.streaming = false;
        state.handed.clear();
    }

    /// # C: O(1)
    fn buf_queue(&self, index: u32) {
        let mut state = self.state.lock();
        if state.streaming { state.handed.push_back(index); }
    }

    /// # C: O(1)
    fn controls(&self) -> alloc::vec::Vec<v4l2::ctrl::ControlDesc> { crate::tables::controls() }
}
