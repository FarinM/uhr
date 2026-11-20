//! The interrupts that end a capture, as a terminal's Ctrl-C. Whoever owns
//! the process's signals, such as the CLI, records them here, from a signal
//! handler if need be, and each platform's recorder reads them.

use std::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};

#[derive(Debug)]
pub struct Interrupts {
    count: AtomicU32,
    first_ns: AtomicU64,
    sent: AtomicI32,
    /// The recording's clock, which a signal handler can read: it must be
    /// async-signal-safe.
    clock: fn() -> u64,
}

impl Interrupts {
    pub const fn new(clock: fn() -> u64) -> Self {
        Self {
            count: AtomicU32::new(0),
            first_ns: AtomicU64::new(0),
            sent: AtomicI32::new(0),
            clock,
        }
    }

    /// An interrupt the target got too, as a terminal's Ctrl-C reaches the
    /// whole process group. Async-signal-safe: it only reads the clock and
    /// changes atomics.
    pub fn interrupt(&self) {
        let _ =
            self.first_ns
                .compare_exchange(0, (self.clock)(), Ordering::Relaxed, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// An interrupt that another process sent to uhr alone, by the number
    /// of its signal, which is passed on to the target. Async-signal-safe.
    pub fn interrupt_sent(&self, signal: i32) {
        self.interrupt();
        self.sent.store(signal, Ordering::Relaxed);
    }

    pub fn count(&self) -> u32 {
        self.count.load(Ordering::Relaxed)
    }

    /// The number of the signal of the last one another process sent, once.
    pub fn take_sent(&self) -> Option<i32> {
        Some(self.sent.swap(0, Ordering::Relaxed)).filter(|&signal| signal != 0)
    }

    /// When the first came, on the recording's clock.
    pub fn first_ns(&self) -> Option<u64> {
        let first = self.first_ns.load(Ordering::Relaxed);
        (first != 0).then_some(first)
    }
}
