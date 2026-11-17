use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};
use serde_json::{Value, json};

use super::{Builder, Error, ObservationCounts, firefox, relative_ms};
use crate::filter::Filter;
use crate::recording::{MemoryReading, Mode, ThreadState, Waker};

/// What a marker says of its observation, under the keys of its schema.
/// Each time a thread goes off CPU makes up to three markers, so a busy
/// recording has millions, and they hold only their fields until written.
pub(super) struct MarkerData {
    /// The stack the marker shows, in its thread's stack table.
    cause: Option<usize>,
    payload: Payload,
}

enum Payload {
    OffCpu {
        state: ThreadState,
        /// `None` without a wakeup.
        waker: Option<Arc<str>>,
        stack_recorded: bool,
    },
    Wakeup {
        waker: Arc<str>,
        stack_recorded: bool,
    },
    PageFault {
        faults: u64,
        address: u64,
        mode: Mode,
    },
    /// Boxed, as few markers are of memory and it is the largest.
    Memory(Box<MemoryReading>),
}

#[derive(Serialize)]
struct Cause {
    stack: usize,
}

impl Serialize for MarkerData {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(None)?;
        let cause = |m: &mut S::SerializeMap| match self.cause {
            Some(stack) => m.serialize_entry("cause", &Cause { stack }),
            None => Ok(()),
        };
        let stack_status = |recorded: bool, stack: &'static str| match recorded {
            true => stack,
            false => "not recorded",
        };
        match &self.payload {
            Payload::OffCpu {
                state,
                waker,
                stack_recorded,
            } => {
                cause(&mut m)?;
                let status = stack_status(*stack_recorded, "switch-out stack");
                m.serialize_entry("stackStatus", status)?;
                m.serialize_entry("state", state.as_str())?;
                m.serialize_entry("type", "UhrOffCpu")?;
                m.serialize_entry("waker", waker.as_deref().unwrap_or("unknown"))?;
            }
            Payload::Wakeup {
                waker,
                stack_recorded,
            } => {
                cause(&mut m)?;
                let status = stack_status(*stack_recorded, "waker stack");
                m.serialize_entry("stackStatus", status)?;
                m.serialize_entry("type", "UhrWakeup")?;
                m.serialize_entry("waker", &**waker)?;
            }
            Payload::PageFault {
                faults,
                address,
                mode,
            } => {
                // Addresses can exceed JavaScript's exact integer range.
                m.serialize_entry("address", &format_args!("0x{address:x}"))?;
                cause(&mut m)?;
                m.serialize_entry("faults", faults)?;
                m.serialize_entry("mode", mode.as_str())?;
                m.serialize_entry("type", "UhrPageFault")?;
            }
            Payload::Memory(reading) => {
                m.serialize_entry("anonymous", &reading.rss_anon_bytes)?;
                m.serialize_entry("file", &reading.rss_file_bytes)?;
                m.serialize_entry("peakRss", &reading.peak_rss_bytes)?;
                m.serialize_entry("rss", &reading.rss_bytes())?;
                m.serialize_entry("shared", &reading.rss_shmem_bytes)?;
                m.serialize_entry("swap", &reading.swap_bytes)?;
                m.serialize_entry("type", "UhrMemory")?;
            }
        }
        m.end()
    }
}

impl Builder<'_> {
    pub(super) fn observations(
        &mut self,
        filter: &Filter,
    ) -> Result<(ObservationCounts, Vec<firefox::Counter>), Error> {
        let mut counts = ObservationCounts::default();
        // One label for all the waits a thread ended.
        let mut wakers: HashMap<(u32, u32, &str), Arc<str>> = HashMap::new();
        let interrupt: Arc<str> = "interrupt".into();
        for (interval, start, end) in filter.off_cpu(self.recording, self.functions)? {
            let thread = self.thread(interval.pid, interval.tid, interval.start_ns);
            let waker = interval.wakeup.as_ref().map(|w| match &w.waker {
                Waker::Thread { pid, tid, name } => wakers
                    .entry((*pid, *tid, name))
                    .or_insert_with(|| format!("{name} (pid {pid}, tid {tid})").into())
                    .clone(),
                Waker::Interrupt => interrupt.clone(),
            });
            let wakeup = interval.wakeup.as_ref().map(|w| w.time_ns);
            let data = |state: ThreadState| Payload::OffCpu {
                state,
                waker: waker.clone(),
                stack_recorded: interval.stack.is_some(),
            };
            if let Some(wakeup) = wakeup {
                if start < wakeup {
                    self.marker(
                        thread,
                        "Off CPU: blocked",
                        start,
                        Some(end.min(wakeup)),
                        interval.stack,
                        data(ThreadState::Blocked),
                    );
                }
                if end > wakeup {
                    self.marker(
                        thread,
                        "Off CPU: runnable",
                        start.max(wakeup),
                        Some(end),
                        interval.stack,
                        data(ThreadState::Runnable),
                    );
                }
            } else {
                self.marker(
                    thread,
                    &format!("Off CPU: {}", interval.state.as_str()),
                    start,
                    Some(end),
                    interval.stack,
                    data(interval.state),
                );
            }
            if let Some((wakeup, waker)) = interval.wakeup.as_ref().zip(waker)
                && (start..=end).contains(&wakeup.time_ns)
                && filter
                    .to_ns
                    .is_none_or(|to| wakeup.time_ns < self.start.saturating_add(to))
            {
                let data = Payload::Wakeup {
                    waker,
                    stack_recorded: wakeup.stack.is_some(),
                };
                self.marker(thread, "Wakeup", wakeup.time_ns, None, wakeup.stack, data);
            }
            counts.off_cpu_intervals += 1;
            counts.off_cpu_ns += end - start;
        }
        for (_, fault) in filter.page_faults(self.recording, self.functions)? {
            let thread = self.thread(fault.pid, fault.tid, fault.time_ns);
            self.marker(
                thread,
                "Page fault sample",
                fault.time_ns,
                None,
                Some(fault.stack),
                Payload::PageFault {
                    faults: fault.faults,
                    address: fault.address,
                    mode: fault.mode,
                },
            );
            counts.page_fault_samples += 1;
        }
        let mut counters = Vec::<firefox::Counter>::new();
        let mut counter_ids = BTreeMap::<usize, (usize, u64)>::new();
        if let Some(readings) = filter.memory(self.recording) {
            let mut readings: Vec<_> = readings.collect();
            readings.sort_by_key(|r| r.time_ns);
            for reading in readings {
                let thread = self.thread(reading.pid, reading.pid, reading.time_ns);
                let rss = reading.rss_bytes();
                let (counter, previous) = counter_ids.entry(thread).or_insert_with(|| {
                    let id = counters.len();
                    counters.push(firefox::Counter {
                        name: "Resident memory change", category: "Memory",
                        description: "Changes in resident bytes; Firefox displays values relative to the minimum in the visible range. Absolute readings are in Resident memory markers.",
                        pid: self.threads[thread].data.pid.clone(), main_thread_index: thread,
                        samples: Default::default(),
                    });
                    (id, rss)
                });
                let change = (i128::from(rss) - i128::from(*previous)) as f64;
                counters[*counter]
                    .samples
                    .0
                    .push((relative_ms(reading.time_ns, self.start), change));
                *previous = rss;
                self.marker(
                    thread,
                    "Resident memory",
                    reading.time_ns,
                    None,
                    None,
                    Payload::Memory(Box::new(reading.clone())),
                );
                counts.memory_readings += 1;
            }
        }
        Ok((counts, counters))
    }

    fn marker(
        &mut self,
        thread: usize,
        name: &str,
        start: u64,
        end: Option<u64>,
        stack: Option<u32>,
        payload: Payload,
    ) {
        let cause = stack.and_then(|s| self.stack(thread, s));
        let t = &mut self.threads[thread];
        let name = t.string(name);
        t.data.markers.0.push(firefox::Marker {
            name,
            start: relative_ms(start, self.start),
            end: end.map(|t| relative_ms(t, self.start)),
            data: MarkerData { cause, payload },
        });
    }
}

pub(super) fn schemas() -> Value {
    let schema = |name, description, fields| {
        json!({
            "name": name,
            "display": ["marker-chart", "marker-table", "timeline-overview"],
            "tooltipLabel": "{marker.name}", "tableLabel": "{marker.name}",
            "description": description, "fields": fields,
        })
    };
    let field = |key, label, format| json!({"key": key, "label": label, "format": format});
    json!([
        schema(
            "UhrOffCpu",
            "Time the thread was off CPU. A recorded wakeup separates blocking from waiting for a CPU. The attached stack is where it switched out.",
            vec![
                field("state", "State", "string"),
                field("waker", "Woken by", "string"),
                field("stackStatus", "Stack", "string"),
            ]
        ),
        schema(
            "UhrWakeup",
            "What woke this thread. The attached stack belongs to the waker, not the sleeping thread.",
            vec![
                field("waker", "Woken by", "string"),
                field("stackStatus", "Stack", "string"),
            ]
        ),
        schema(
            "UhrPageFault",
            "A sampled page fault, representing the recorded number of faults. This is not an allocation sample.",
            vec![
                field("faults", "Faults represented", "integer"),
                field("address", "Fault address", "string"),
                field("mode", "CPU mode", "string"),
            ]
        ),
        schema(
            "UhrMemory",
            "Absolute process memory reading. RSS is resident memory, not allocated or live bytes.",
            vec![
                field("rss", "Resident", "bytes"),
                field("anonymous", "Anonymous resident", "bytes"),
                field("file", "File resident", "bytes"),
                field("shared", "Shared resident", "bytes"),
                field("swap", "Swap", "bytes"),
                field("peakRss", "Peak resident", "bytes"),
            ]
        ),
    ])
}
