//! Turns polls of each thread's CPU time and state into CPU samples and time
//! off CPU. A waiting thread whose CPU time did not move since the last poll
//! ran none of its code, so its stack is still the one then and need not be
//! walked again: the kernel brought its count up to date as it blocked. Not
//! so one that can run: the kernel counts the time of a thread on a CPU only
//! as it enters the kernel, as much as a quantum, 10 ms, late, so it may have
//! run since. Held still, its count is up to date.

use uhr_core::recording::{Mode, OffCPUInterval, Sample, ThreadState};

/// What a poll found of one thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Poll {
    pub time_ns: u64,
    /// Its CPU time so far, in user and in kernel mode.
    pub user_ns: u64,
    pub system_ns: u64,
    pub state: RunState,
    /// Its stack, walked at this poll. `None` if it was not walked, which
    /// `Timeline::needs_stack` allows only for a waiting thread that did not
    /// run.
    pub stack: Option<u32>,
}

/// What a thread was doing when polled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RunState {
    /// On a CPU, or waiting for one.
    Running,
    /// Waiting for something other than a CPU: a lock, I/O, a timer.
    Waiting,
    /// Stopped, as by a debugger, or exiting.
    Other,
}

/// What the polls of all threads add up to.
#[derive(Debug, Default)]
pub(crate) struct Polled {
    pub samples: Vec<Sample>,
    pub off_cpu: Vec<OffCPUInterval>,
}

/// One thread's polls so far.
#[derive(Debug)]
pub(crate) struct Timeline {
    pid: u32,
    tid: u32,
    off_cpu: bool,
    last: Option<Last>,
    /// The interval in `Polled::off_cpu` that ends at the last poll, which a
    /// wait that goes on extends.
    open: Option<usize>,
}

#[derive(Debug, Clone, Copy)]
struct Last {
    time_ns: u64,
    cpu_ns: u64,
    user_ns: u64,
    system_ns: u64,
    state: RunState,
    stack: u32,
}

impl Timeline {
    /// With `off_cpu`, the time between polls that the thread did not run
    /// becomes intervals off CPU.
    pub(crate) fn new(pid: u32, tid: u32, off_cpu: bool) -> Self {
        Self {
            pid,
            tid,
            off_cpu,
            last: None,
            open: None,
        }
    }

    /// Whether a poll with this CPU time and state needs a fresh stack, and
    /// the thread's CPU time read while it is held still: the first does,
    /// and so does one of a thread that ran since the last, or can run now
    /// and so may have.
    pub(crate) fn needs_stack(&self, user_ns: u64, system_ns: u64, state: RunState) -> bool {
        self.last
            .is_none_or(|last| user_ns + system_ns != last.cpu_ns || state == RunState::Running)
    }

    /// When the thread was last polled.
    pub(crate) fn last_ns(&self) -> Option<u64> {
        self.last.map(|last| last.time_ns)
    }

    /// Adds the first poll of a thread that started since the last poll of
    /// its process, which must walk its stack. All its CPU time so far ran
    /// since then, so it is sampled at this poll, as `add` samples the time
    /// between two polls. When it started, and so how long it was off CPU
    /// before, is not known.
    pub(crate) fn started(&mut self, poll: Poll, out: &mut Polled) {
        assert!(self.last.is_none(), "a thread starts once");
        let stack = poll
            .stack
            .expect("the first poll of a thread walks its stack");
        self.last = Some(Last {
            time_ns: poll.time_ns,
            cpu_ns: 0,
            user_ns: 0,
            system_ns: 0,
            state: poll.state,
            stack,
        });
        // As no time passed since, none of it is off CPU.
        self.add(poll, out);
    }

    /// Adds a poll, which must come after the last. The first only sets
    /// where the next count from. The CPU time between two polls is
    /// sampled at the second with its stack, as a CPU-clock sampler would
    /// at the end of its period. The rest of the time between them the
    /// thread was off CPU: all of it where its CPU time did not move, with
    /// the stack it had and its state at the second poll, or where it ran,
    /// for as long as it did not. A wait it was in at the first poll then
    /// most likely lasted until it ran, so that time goes to the wait;
    /// otherwise it waited between running, where and why not known.
    pub(crate) fn add(&mut self, poll: Poll, out: &mut Polled) {
        let cpu_ns = poll.user_ns + poll.system_ns;
        let Some(last) = self.last else {
            let stack = poll
                .stack
                .expect("the first poll of a thread walks its stack");
            self.last = Some(Last {
                time_ns: poll.time_ns,
                cpu_ns,
                user_ns: poll.user_ns,
                system_ns: poll.system_ns,
                state: poll.state,
                stack,
            });
            return;
        };
        let ran = cpu_ns != last.cpu_ns;
        let stack = match poll.stack {
            Some(stack) => stack,
            None if !ran => last.stack,
            None => panic!("a poll of a thread that ran walks its stack"),
        };
        let elapsed_ns = poll.time_ns.saturating_sub(last.time_ns);
        for (mode, ns) in [
            (Mode::User, poll.user_ns.saturating_sub(last.user_ns)),
            (Mode::Kernel, poll.system_ns.saturating_sub(last.system_ns)),
        ] {
            if ns > 0 {
                out.samples.push(Sample {
                    time_ns: poll.time_ns,
                    pid: self.pid,
                    tid: self.tid,
                    cpu: None,
                    mode,
                    stack,
                    cpu_ns: ns,
                });
            }
        }
        // The kernel counts CPU time in microseconds, so a thread that ran
        // the whole time can show a little more than passed.
        let off_ns = elapsed_ns.saturating_sub(cpu_ns.saturating_sub(last.cpu_ns));
        let open = self.open.take();
        if self.off_cpu && off_ns > 0 {
            let waited = !ran || last.state != RunState::Running;
            self.open = if waited {
                let (state, wait_stack) = if ran {
                    (state(last.state), last.stack)
                } else {
                    (state(poll.state), stack)
                };
                let interval = OffCPUInterval {
                    start_ns: last.time_ns,
                    end_ns: last.time_ns + off_ns,
                    pid: self.pid,
                    tid: self.tid,
                    state,
                    stack: Some(wait_stack),
                    wakeup: None,
                };
                let extended = open.filter(|&i| {
                    let before = &out.off_cpu[i];
                    before.state == interval.state && before.stack == interval.stack
                });
                match extended {
                    Some(i) => out.off_cpu[i].end_ns = interval.end_ns,
                    None => out.off_cpu.push(interval),
                }
                // A wait that ended before this poll, as one the thread ran
                // after, does not go on into the next.
                let i = extended.unwrap_or(out.off_cpu.len() - 1);
                (!ran).then_some(i)
            } else {
                out.off_cpu.push(OffCPUInterval {
                    start_ns: poll.time_ns - off_ns,
                    end_ns: poll.time_ns,
                    pid: self.pid,
                    tid: self.tid,
                    state: ThreadState::Unknown,
                    stack: None,
                    wakeup: None,
                });
                None
            };
        }
        self.last = Some(Last {
            time_ns: poll.time_ns,
            cpu_ns,
            user_ns: poll.user_ns,
            system_ns: poll.system_ns,
            state: poll.state,
            stack,
        });
    }
}

fn state(state: RunState) -> ThreadState {
    match state {
        RunState::Running => ThreadState::Runnable,
        RunState::Waiting => ThreadState::Blocked,
        RunState::Other => ThreadState::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: u64 = 1_000_000;

    fn poll(
        time_ns: u64,
        user_ns: u64,
        system_ns: u64,
        state: RunState,
        stack: Option<u32>,
    ) -> Poll {
        Poll {
            time_ns,
            user_ns,
            system_ns,
            state,
            stack,
        }
    }

    fn timeline() -> Timeline {
        Timeline::new(10, 11, true)
    }

    fn total_ns(out: &Polled) -> u64 {
        let cpu: u64 = out.samples.iter().map(|s| s.cpu_ns).sum();
        let off: u64 = out.off_cpu.iter().map(|i| i.end_ns - i.start_ns).sum();
        cpu + off
    }

    #[test]
    fn the_first_poll_only_sets_the_baseline() {
        let mut thread = timeline();
        let mut out = Polled::default();
        assert!(thread.needs_stack(5 * MS, 0, RunState::Waiting));
        thread.add(poll(MS, 5 * MS, 0, RunState::Running, Some(0)), &mut out);
        assert!(out.samples.is_empty() && out.off_cpu.is_empty());
        assert_eq!(thread.last_ns(), Some(MS));
        assert!(!thread.needs_stack(5 * MS, 0, RunState::Waiting));
        assert!(thread.needs_stack(5 * MS, 1, RunState::Waiting));
        // Its count may be behind.
        assert!(thread.needs_stack(5 * MS, 0, RunState::Running));
    }

    #[test]
    fn cpu_time_is_sampled_by_mode_at_the_later_poll() {
        let mut thread = timeline();
        let mut out = Polled::default();
        thread.add(poll(0, 0, 0, RunState::Running, Some(0)), &mut out);
        thread.add(
            poll(MS, MS * 3 / 4, MS / 4, RunState::Running, Some(7)),
            &mut out,
        );
        assert_eq!(
            out.samples
                .iter()
                .map(|s| (s.time_ns, s.mode, s.cpu_ns, s.stack))
                .collect::<Vec<_>>(),
            [
                (MS, Mode::User, MS * 3 / 4, 7),
                (MS, Mode::Kernel, MS / 4, 7)
            ]
        );
        assert!(out.off_cpu.is_empty());
    }

    #[test]
    fn a_wait_across_polls_is_one_interval_with_its_stack() {
        let mut thread = timeline();
        let mut out = Polled::default();
        thread.add(poll(0, 0, 0, RunState::Running, Some(1)), &mut out);
        thread.add(poll(MS, MS / 2, 0, RunState::Waiting, Some(2)), &mut out);
        for i in 2..5 {
            assert!(!thread.needs_stack(MS / 2, 0, RunState::Waiting));
            thread.add(poll(i * MS, MS / 2, 0, RunState::Waiting, None), &mut out);
        }
        // Woken: it ran a quarter of the last period.
        thread.add(
            poll(5 * MS, MS * 3 / 4, 0, RunState::Running, Some(3)),
            &mut out,
        );
        let waits: Vec<_> = out
            .off_cpu
            .iter()
            .map(|i| (i.start_ns, i.end_ns, i.state, i.stack))
            .collect();
        assert_eq!(
            waits,
            [
                // It ran half of the first period, while running at its start.
                (MS / 2, MS, ThreadState::Unknown, None),
                (MS, 4 * MS + MS * 3 / 4, ThreadState::Blocked, Some(2)),
            ]
        );
        assert_eq!(total_ns(&out), 5 * MS);
    }

    #[test]
    fn a_thread_that_could_run_but_did_not_waited_for_a_cpu() {
        let mut thread = timeline();
        let mut out = Polled::default();
        thread.add(poll(0, 0, 0, RunState::Running, Some(1)), &mut out);
        thread.add(poll(MS, 0, 0, RunState::Running, Some(1)), &mut out);
        assert_eq!(out.off_cpu.len(), 1);
        assert_eq!(out.off_cpu[0].state, ThreadState::Runnable);
        assert_eq!(out.off_cpu[0].stack, Some(1));
    }

    #[test]
    fn a_new_wait_after_running_starts_a_new_interval() {
        let mut thread = timeline();
        let mut out = Polled::default();
        thread.add(poll(0, 0, 0, RunState::Waiting, Some(1)), &mut out);
        thread.add(poll(MS, 0, 0, RunState::Waiting, None), &mut out);
        // Woken at once, and blocked again elsewhere.
        thread.add(
            poll(2 * MS, MS / 10, 0, RunState::Waiting, Some(2)),
            &mut out,
        );
        thread.add(poll(3 * MS, MS / 10, 0, RunState::Waiting, None), &mut out);
        let waits: Vec<_> = out
            .off_cpu
            .iter()
            .map(|i| (i.start_ns, i.end_ns, i.stack))
            .collect();
        assert_eq!(
            waits,
            [(0, MS + MS * 9 / 10, Some(1)), (2 * MS, 3 * MS, Some(2)),]
        );
        assert_eq!(total_ns(&out), 3 * MS);
    }

    #[test]
    fn cpu_time_over_the_time_passed_leaves_none_off_cpu() {
        let mut thread = timeline();
        let mut out = Polled::default();
        thread.add(poll(0, 0, 0, RunState::Running, Some(1)), &mut out);
        thread.add(
            poll(MS, MS + 3_000, 0, RunState::Running, Some(1)),
            &mut out,
        );
        assert!(out.off_cpu.is_empty());
        assert_eq!(out.samples[0].cpu_ns, MS + 3_000);
    }

    #[test]
    fn a_thread_that_started_since_the_last_poll_has_its_cpu_time_sampled() {
        let mut thread = timeline();
        let mut out = Polled::default();
        thread.started(
            poll(5 * MS, MS / 2, MS / 4, RunState::Waiting, Some(3)),
            &mut out,
        );
        assert_eq!(
            out.samples
                .iter()
                .map(|s| (s.time_ns, s.mode, s.cpu_ns, s.stack))
                .collect::<Vec<_>>(),
            [
                (5 * MS, Mode::User, MS / 2, 3),
                (5 * MS, Mode::Kernel, MS / 4, 3)
            ]
        );
        assert!(out.off_cpu.is_empty());
        // From here on it is polled as any other.
        assert!(!thread.needs_stack(MS / 2, MS / 4, RunState::Waiting));
        thread.add(
            poll(6 * MS, MS / 2, MS / 4, RunState::Waiting, None),
            &mut out,
        );
        assert_eq!(out.off_cpu.len(), 1);
        assert_eq!(out.off_cpu[0].stack, Some(3));
    }

    #[test]
    fn without_off_cpu_only_samples_are_kept() {
        let mut thread = Timeline::new(10, 11, false);
        let mut out = Polled::default();
        thread.add(poll(0, 0, 0, RunState::Waiting, Some(1)), &mut out);
        thread.add(poll(MS, 0, 0, RunState::Waiting, None), &mut out);
        thread.add(
            poll(2 * MS, MS / 2, 0, RunState::Running, Some(2)),
            &mut out,
        );
        assert!(out.off_cpu.is_empty());
        assert_eq!(out.samples.len(), 1);
    }
}
