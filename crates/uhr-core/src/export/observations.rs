use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::{Builder, Error, ObservationCounts, firefox, relative_ms};
use crate::filter::Filter;
use crate::recording::{ThreadState, Waker};

impl Builder<'_> {
    pub(super) fn observations(
        &mut self,
        filter: &Filter,
    ) -> Result<(ObservationCounts, Vec<firefox::Counter>), Error> {
        let mut counts = ObservationCounts::default();
        for (interval, start, end) in filter.off_cpu(self.recording, self.functions)? {
            let thread = self.thread(interval.pid, interval.tid, interval.start_ns);
            let waker = interval.wakeup.as_ref().map(|w| match &w.waker {
                Waker::Thread { pid, tid, name } => format!("{name} (pid {pid}, tid {tid})"),
                Waker::Interrupt => "interrupt".into(),
            });
            let wakeup = interval.wakeup.as_ref().map(|w| w.time_ns);
            let data = |state: ThreadState| {
                json!({
                    "type": "UhrOffCpu", "state": state.as_str(),
                    "waker": waker.as_deref().unwrap_or("unknown"),
                    "stackStatus": if interval.stack.is_some() { "switch-out stack" } else { "not recorded" },
                })
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
            if let Some(wakeup) = &interval.wakeup
                && (start..end).contains(&wakeup.time_ns)
            {
                self.marker(thread, "Wakeup", wakeup.time_ns, None, wakeup.stack, json!({
                    "type": "UhrWakeup", "waker": waker,
                    "stackStatus": if wakeup.stack.is_some() { "waker stack" } else { "not recorded" },
                }));
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
                json!({
                    "type": "UhrPageFault", "faults": fault.faults,
                    // Addresses can exceed JavaScript's exact integer range.
                    "address": format!("0x{:x}", fault.address), "mode": fault.mode.as_str(),
                }),
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
                        description: "Change in resident bytes since the first selected reading. Absolute readings are in Resident memory markers.",
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
                    json!({
                        "type": "UhrMemory", "rss": rss, "anonymous": reading.rss_anon_bytes,
                        "file": reading.rss_file_bytes, "shared": reading.rss_shmem_bytes,
                        "swap": reading.swap_bytes, "peakRss": reading.peak_rss_bytes,
                    }),
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
        mut data: Value,
    ) {
        if let Some(stack) = stack.and_then(|s| self.stack(thread, s)) {
            data["cause"] = json!({"stack": stack});
        }
        let t = &mut self.threads[thread];
        let name = t.string(name);
        t.data.markers.0.push(firefox::Marker {
            name,
            start: relative_ms(start, self.start),
            end: end.map(|t| relative_ms(t, self.start)),
            data,
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
