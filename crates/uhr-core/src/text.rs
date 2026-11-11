//! The short readable form of results, beside their JSON.

use std::io::{self, Write};
use std::path::Path;

use crate::call_paths::{CallPaths, Node, Omitted};
use crate::coverage::{Coverage, SymbolCoverage};
use crate::doctor::{Report, Status};
use crate::export;
use crate::filter::Filter;
use crate::flamegraph::FlameGraph;
use crate::functions::Function;
use crate::metric::{Metric, Unit};
use crate::overview::{CPUTime, Memory, Overview};
use crate::query::{
    FunctionRow, GroupBy, Latency, ModuleRow, QueryResult, RegionRow, Rows, SyscallRow, WakerRow,
    WokenBy,
};
use crate::recording::{Exit, RegionKind, ThreadState};

pub fn write_report(out: &mut impl Write, report: &Report) -> io::Result<()> {
    for check in &report.checks {
        let status = match check.status {
            Status::Ok => "ok",
            Status::Limited => "limited",
            Status::Blocked => "blocked",
        };
        writeln!(out, "{status:<8} {}", check.detail)?;
        if let Some(fix) = &check.fix {
            writeln!(out, "{:<8} fix: {fix}", "")?;
        }
    }
    for note in &report.notes {
        writeln!(out, "{:<8} {note}", "note")?;
    }
    Ok(())
}

pub fn write_overview(out: &mut impl Write, result: &Overview) -> io::Result<()> {
    let exit = match &result.exit {
        Some(Exit::Code(code)) => format!("exited with code {code}"),
        Some(Exit::Signal(signal)) => format!("killed by signal {signal}"),
        Some(Exit::Unknown(reason)) => format!("exit status unknown: {reason}"),
        None => "still running when the recording stopped".into(),
    };
    let command = match &result.command[..] {
        [] => "(no command line)".to_owned(),
        command => command.join(" "),
    };
    writeln!(out, "{command}, {exit}")?;
    let window = &result.window;
    let times = result.times_of_day.as_ref();
    write!(out, "{} recorded", seconds(result.recording_duration_ns))?;
    match (times, &result.times_of_day_unknown) {
        (Some(times), _) => write!(out, " from {}", times.recording_start)?,
        (None, Some(unknown)) => write!(out, " (times of day unknown: {unknown})")?,
        (None, None) => {}
    }
    if !result.filter.is_empty() {
        write!(
            out,
            ", showing {} to {}",
            seconds(window.start_ns),
            seconds(window.end_ns),
        )?;
        if let Some(times) = times {
            write!(out, " ({} to {})", times.window_start, times.window_end)?;
        }
        write!(out, ", filter: {}", describe_filter(&result.filter))?;
    }
    writeln!(out)?;
    let cpu = &result.cpu;
    write!(
        out,
        "{} samples, {} of CPU time",
        cpu.samples,
        seconds(cpu.cpu_ns)
    )?;
    if let Some(utilization) = result.cpu_utilization {
        write!(out, ", {utilization:.2} CPUs busy on average")?;
    }
    writeln!(out)?;
    match cpu.kernel_cpu_ns {
        Some(kernel) => writeln!(
            out,
            "  user {}, kernel {}",
            seconds(cpu.user_cpu_ns),
            seconds(kernel)
        ),
        None => writeln!(
            out,
            "  user {}, kernel not sampled",
            seconds(cpu.user_cpu_ns)
        ),
    }?;
    if cpu.unknown_mode_cpu_ns > 0 {
        writeln!(out, "  unknown mode {}", seconds(cpu.unknown_mode_cpu_ns))?;
    }
    match &result.off_cpu {
        Some(off_cpu) => {
            let unknown = match off_cpu.unknown_state_ns {
                0 => String::new(),
                ns => format!(", unknown {}", seconds(ns)),
            };
            let woken = match off_cpu.wakeup_latency_ns {
                Some(ns) => format!(" ({} of it once woken)", seconds(ns)),
                None => String::new(),
            };
            writeln!(
                out,
                "off CPU {}, summed over threads: runnable {}{woken}, blocked {}{unknown}",
                seconds(off_cpu.runnable_ns + off_cpu.blocked_ns + off_cpu.unknown_state_ns),
                seconds(off_cpu.runnable_ns),
                seconds(off_cpu.blocked_ns)
            )
        }
        None => writeln!(out, "off CPU: not recorded"),
    }?;

    writeln!(out, "\nprocesses")?;
    writeln!(
        out,
        "{:>9} {:>7} {:>6} {:>8} {:>9}  name",
        "cpu", "kernel", "cpus", "threads", "pid"
    )?;
    for process in &result.processes {
        writeln!(
            out,
            "{:>9} {:>7} {:>6} {:>8} {:>9}  {}",
            seconds(process.cpu.cpu_ns),
            kernel_share(&process.cpu),
            process
                .cpu_utilization
                .map_or("-".into(), |u| format!("{u:.2}")),
            process.threads,
            process.pid,
            process.name.as_deref().unwrap_or("<unnamed>"),
        )?;
    }
    if result.processes_omitted > 0 {
        writeln!(
            out,
            "({} more processes, raise --top to see them)",
            result.processes_omitted
        )?;
    }

    writeln!(out, "\nthreads")?;
    // Off CPU since before an attached capture, runnable or blocked.
    let unknown = result
        .threads
        .iter()
        .any(|t| t.unknown_state_share.is_some_and(|s| s > 0.0));
    let unknown_column = |cell: String| {
        if unknown {
            format!(" {cell:>7}")
        } else {
            String::new()
        }
    };
    let percent = |share: Option<f64>| share.map_or("-".into(), |s| format!("{:.1}%", s * 100.0));
    writeln!(
        out,
        "{:>9} {:>7} {:>7} {:>8} {:>7}{} {:>9} {:>9}  name",
        "cpu",
        "kernel",
        "on cpu",
        "runnable",
        "blocked",
        unknown_column("unknown".into()),
        "alive",
        "tid"
    )?;
    for thread in &result.threads {
        writeln!(
            out,
            "{:>9} {:>7} {:>7} {:>8} {:>7}{} {:>9} {:>9}  {}",
            seconds(thread.cpu.cpu_ns),
            kernel_share(&thread.cpu),
            percent(thread.on_cpu_share),
            percent(thread.runnable_share),
            percent(thread.blocked_share),
            unknown_column(percent(thread.unknown_state_share)),
            seconds(thread.alive_ns),
            thread.tid,
            thread.names.last().map_or("<unnamed>", String::as_str),
        )?;
    }
    if result.threads_omitted > 0 {
        writeln!(
            out,
            "({} more threads, raise --top to see them)",
            result.threads_omitted
        )?;
    }
    if let Some(memory) = &result.memory {
        write_memory(out, memory)?;
    }

    writeln!(out, "\ncoverage")?;
    write_coverage(out, &result.coverage)
}

fn write_memory(out: &mut impl Write, memory: &Memory) -> io::Result<()> {
    writeln!(
        out,
        "\nmemory, read every {} ms: resident at the last reading, its change since the first, \
         the most of any reading, and the kernel's peak",
        memory.interval_ns / 1_000_000
    )?;
    writeln!(
        out,
        "{:>10} {:>11} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>9}  name",
        "rss", "change", "max", "peak", "anon", "file", "shmem", "swap", "pid"
    )?;
    for process in &memory.processes {
        let (first, last) = (&process.first, &process.last);
        let change = match last.rss_bytes.checked_sub(first.rss_bytes) {
            Some(grown) => format!("+{}", bytes(grown)),
            None => format!("-{}", bytes(first.rss_bytes - last.rss_bytes)),
        };
        writeln!(
            out,
            "{:>10} {:>11} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>9}  {}",
            bytes(last.rss_bytes),
            change,
            bytes(process.max.rss_bytes),
            bytes(last.peak_rss_bytes),
            bytes(last.rss_anon_bytes),
            bytes(last.rss_file_bytes),
            bytes(last.rss_shmem_bytes),
            bytes(last.swap_bytes),
            process.pid,
            process.name.as_deref().unwrap_or("<unnamed>"),
        )?;
    }
    if memory.processes_omitted > 0 {
        writeln!(
            out,
            "({} more processes, raise --top to see them)",
            memory.processes_omitted
        )?;
    }
    let by_kind: Vec<_> = memory
        .processes
        .iter()
        .filter_map(|process| Some((process, process.regions.as_ref()?)))
        .collect();
    if !by_kind.is_empty() {
        writeln!(
            out,
            "\nresident by kind of region, and name a process gave it, as read last, less often for large processes"
        )?;
    }
    for (process, regions) in by_kind {
        let kinds: Vec<String> = regions
            .kinds
            .iter()
            .filter(|k| k.rss_bytes > 0)
            .map(|k| match &k.name {
                Some(name) => format!("{} {name} {}", k.kind.as_str(), bytes(k.rss_bytes)),
                None => format!("{} {}", k.kind.as_str(), bytes(k.rss_bytes)),
            })
            .collect();
        writeln!(
            out,
            "{:>9}  {} at {}: {}",
            process.pid,
            process.name.as_deref().unwrap_or("<unnamed>"),
            seconds(regions.time_ns),
            kinds.join(", ")
        )?;
    }
    Ok(())
}

/// The share of a row's CPU time spent in the kernel.
fn kernel_share(cpu: &CPUTime) -> String {
    match cpu.kernel_cpu_ns {
        None => "?".into(),
        Some(_) if cpu.cpu_ns == 0 => "-".into(),
        Some(kernel) => format!("{:.1}%", kernel as f64 / cpu.cpu_ns as f64 * 100.0),
    }
}

pub fn write_export(
    out: &mut impl Write,
    report: &export::Report,
    output: &Path,
) -> io::Result<()> {
    writeln!(
        out,
        "wrote {}: {} threads, {} CPU samples ({})",
        output.display(),
        report.threads,
        report.samples,
        seconds(report.cpu_ns)
    )?;
    writeln!(
        out,
        "  {} off-CPU intervals, {} page-fault samples, {} memory readings",
        report.observations.off_cpu_intervals,
        report.observations.page_fault_samples,
        report.observations.memory_readings
    )?;
    writeln!(out, "open the file at https://profiler.firefox.com/")?;
    if !report.filter.is_empty() {
        writeln!(out, "filter: {}", describe_filter(&report.filter))?;
    }
    writeln!(out, "\ncoverage")?;
    writeln!(
        out,
        "  CPU time with an unnamed frame: {}",
        seconds(report.unnamed_cpu_ns)
    )?;
    write_symbol_coverage(out, &report.symbols)?;
    write_coverage(out, &report.coverage)?;
    for limitation in &report.limitations {
        writeln!(out, "  {limitation}")?;
    }
    Ok(())
}

pub fn write_flamegraph(out: &mut impl Write, graph: &FlameGraph, output: &Path) -> io::Result<()> {
    writeln!(
        out,
        "wrote {}: {}, {:.1}% of it in {} stacks",
        output.display(),
        describe_amount(
            graph.metric,
            graph.samples,
            graph.off_cpu_intervals,
            graph.value
        ),
        graph.graphed_share * 100.0,
        graph.stacks
    )?;
    if let Some(root) = &graph.root {
        writeln!(out, "from {}  {}", function_name(root), module_name(root))?;
    }
    if !graph.filter.is_empty() {
        writeln!(out, "filter: {}", describe_filter(&graph.filter))?;
    }
    let coverage = &graph.coverage;
    writeln!(out, "\ncoverage")?;
    if let Some(share) = coverage.named_share {
        writeln!(
            out,
            "  graphed {} with every frame named: {:.1}%",
            counted(graph.unit),
            share * 100.0
        )?;
    }
    for (origin, share) in &coverage.unnamed_by_origin {
        writeln!(out, "  unnamed {}: {:.1}%", origin.as_str(), share * 100.0)?;
    }
    write_no_stack(out, coverage.no_stack_share)?;
    write_symbol_coverage(out, &coverage.symbols)?;
    write_coverage(out, &coverage.recording)
}

pub fn write_call_paths(out: &mut impl Write, result: &CallPaths) -> io::Result<()> {
    let percent = |amount: u64| {
        if result.value == 0 {
            0.0
        } else {
            amount as f64 / result.value as f64 * 100.0
        }
    };
    writeln!(
        out,
        "{}  {}",
        function_name(&result.function),
        module_name(&result.function)
    )?;
    writeln!(
        out,
        "{}. On the stack for {:.1}% of it, its own for {:.1}%",
        describe_amount(
            result.metric,
            result.samples,
            result.off_cpu_intervals,
            result.value
        ),
        result.total_share * 100.0,
        result.self_share * 100.0
    )?;
    if !result.filter.is_empty() {
        writeln!(out, "filter: {}", describe_filter(&result.filter))?;
    }

    writeln!(out, "\ncallers")?;
    write_nodes(out, &result.callers, &result.callers_omitted, 0, &percent)?;
    if result.no_caller > 0 {
        writeln!(
            out,
            "{:>6.1}%  (no caller: where the thread started, or the stack was cut short)",
            percent(result.no_caller)
        )?;
    }
    writeln!(out, "\ncallees")?;
    write_nodes(out, &result.callees, &result.callees_omitted, 0, &percent)?;

    let coverage = &result.coverage;
    writeln!(out, "\ncoverage")?;
    match coverage.named_share {
        Some(share) => writeln!(
            out,
            "  function {} with every frame named, within the depth: {:.1}%",
            counted(result.unit),
            share * 100.0
        ),
        None => writeln!(
            out,
            "  named frames: unknown, no {} in the function",
            counted(result.unit)
        ),
    }?;
    for (origin, share) in &coverage.unnamed_by_origin {
        writeln!(out, "  unnamed {}: {:.1}%", origin.as_str(), share * 100.0)?;
    }
    write_no_stack(out, coverage.no_stack_share)?;
    write_symbol_coverage(out, &coverage.symbols)?;
    write_coverage(out, &coverage.recording)
}

fn write_nodes(
    out: &mut impl Write,
    nodes: &[Node],
    omitted: &Omitted,
    level: usize,
    percent: &dyn Fn(u64) -> f64,
) -> io::Result<()> {
    let indent = "  ".repeat(level);
    if level == 0 && nodes.is_empty() && omitted.nodes == 0 {
        writeln!(out, "  none")?;
    }
    for node in nodes {
        let leaf = match node.self_ {
            Some(amount) if amount > 0 => format!("  (leaf {:.1}%)", percent(amount)),
            _ => String::new(),
        };
        writeln!(
            out,
            "{:>6.1}%  {indent}{}  {}{leaf}",
            percent(node.value),
            function_name(&node.function),
            module_name(&node.function)
        )?;
        write_nodes(out, &node.children, &node.omitted, level + 1, percent)?;
    }
    if omitted.nodes > 0 {
        writeln!(
            out,
            "{:>6.1}%  {indent}({} more)",
            percent(omitted.value),
            omitted.nodes
        )?;
    }
    Ok(())
}

pub fn write_query(out: &mut impl Write, result: &QueryResult) -> io::Result<()> {
    let by = match result.group_by {
        GroupBy::Function => "function",
        GroupBy::Line => "line",
        GroupBy::Module => "module",
        GroupBy::Syscall => "syscall",
        GroupBy::Region => "region",
        GroupBy::Waker => "waker",
        GroupBy::WakerFunction => "waker function",
    };
    writeln!(
        out,
        "{}, by {by}\n",
        describe_amount(
            result.metric,
            result.samples,
            result.off_cpu_intervals,
            result.value
        )
    )?;
    if !result.filter.is_empty() {
        writeln!(out, "filter: {}\n", describe_filter(&result.filter))?;
    }
    match &result.rows {
        Rows::Functions(rows) => write_function_rows(out, result.group_by, rows)?,
        Rows::Modules(rows) => write_module_rows(out, rows)?,
        Rows::Syscalls(rows) => write_syscall_rows(out, rows, result.unit)?,
        Rows::Regions(rows) => write_region_rows(out, rows)?,
        Rows::Wakers(rows) => write_waker_rows(out, rows)?,
    }
    if let Some(window) = &result.calls_window {
        writeln!(
            out,
            "(calls: counted from {} to {}, in whole intervals of about 1.07s)",
            seconds(window.start_ns),
            seconds(window.end_ns)
        )?;
    }
    if result.rows_omitted > 0 {
        writeln!(
            out,
            "({} more rows, raise --top to see them)",
            result.rows_omitted
        )?;
    }

    let coverage = &result.coverage;
    writeln!(out, "\ncoverage")?;
    match coverage.named_share {
        Some(share) => writeln!(
            out,
            "  {} with a named leaf frame: {:.1}%",
            counted(result.unit),
            share * 100.0
        ),
        None => writeln!(
            out,
            "  {0} with a named leaf frame: unknown, no {0}",
            counted(result.unit)
        ),
    }?;
    for (origin, share) in &coverage.unnamed_by_origin {
        writeln!(out, "  unnamed {}: {:.1}%", origin.as_str(), share * 100.0)?;
    }
    match result.group_by {
        GroupBy::WakerFunction if coverage.no_stack_share > 0.0 => writeln!(
            out,
            "  off-CPU time no wakeup with a stack ended: {:.1}% (see --group-by waker)",
            coverage.no_stack_share * 100.0
        )?,
        GroupBy::WakerFunction => {}
        _ => write_no_stack(out, coverage.no_stack_share)?,
    }
    if let Some(share) = coverage.own_programs_share {
        writeln!(
            out,
            "  {} in uhr's eBPF programs: {:.1}%",
            counted(result.unit),
            share * 100.0
        )?;
    }
    write_symbol_coverage(out, &coverage.symbols)?;
    write_coverage(out, &coverage.recording)
}

fn write_function_rows(
    out: &mut impl Write,
    group_by: GroupBy,
    rows: &[FunctionRow],
) -> io::Result<()> {
    let by_line = group_by == GroupBy::Line;
    let by = match group_by {
        GroupBy::Line => "line",
        GroupBy::WakerFunction => "waker function",
        _ => "function",
    };
    writeln!(out, "{:>7} {:>7}  {by}", "self", "total")?;
    for row in rows {
        let line = match (by_line, &row.line) {
            (false, _) => String::new(),
            (true, Some(line)) => {
                let file = line.file.rsplit('/').next().unwrap_or(&line.file);
                format!("  {file}:{}", line.line)
            }
            (true, None) => "  (no line)".into(),
        };
        writeln!(
            out,
            "{:>6.1}% {:>6.1}%  {}{line}  {}",
            row.self_share * 100.0,
            row.total_share * 100.0,
            function_name(&row.function),
            module_name(&row.function),
        )?;
    }
    Ok(())
}

fn write_module_rows(out: &mut impl Write, rows: &[ModuleRow]) -> io::Result<()> {
    writeln!(out, "{:>7} {:>7}  module", "self", "total")?;
    for row in rows {
        writeln!(
            out,
            "{:>6.1}% {:>6.1}%  {}",
            row.self_share * 100.0,
            row.total_share * 100.0,
            row.module.as_deref().unwrap_or(row.origin.as_str()),
        )?;
    }
    Ok(())
}

fn write_region_rows(out: &mut impl Write, rows: &[RegionRow]) -> io::Result<()> {
    writeln!(out, "{:>7}  region", "faults")?;
    for row in rows {
        let kind = row
            .kind
            .map_or("(unknown: no region recorded held it)", RegionKind::as_str);
        let path = row.path.as_ref().map(|p| format!("  {p}"));
        writeln!(
            out,
            "{:>6.1}%  {kind}{}",
            row.share * 100.0,
            path.unwrap_or_default()
        )?;
    }
    Ok(())
}

fn write_waker_rows(out: &mut impl Write, rows: &[WakerRow]) -> io::Result<()> {
    writeln!(
        out,
        "{:>7} {:>9} {:>9} {:>9} {:>9}  waker",
        "time", "intervals", "latency", "pid", "tid"
    )?;
    for row in rows {
        let latency = row.wakeup_latency_ns.map(duration).unwrap_or_default();
        let id = |id: Option<u32>| id.map(|id| id.to_string()).unwrap_or_default();
        let waker = match (row.woken_by, row.state) {
            (Some(WokenBy::Thread), _) => row.waker_name.as_deref().unwrap_or("<unnamed>"),
            (Some(WokenBy::Interrupt), _) => "(interrupt)",
            (None, ThreadState::Runnable) => "(preempted, not woken)",
            (None, ThreadState::Blocked) => "(blocked, wakeup not recorded)",
            (None, ThreadState::Unknown) => "(unknown: off CPU when the capture attached)",
        };
        writeln!(
            out,
            "{:>6.1}% {:>9} {latency:>9} {:>9} {:>9}  {waker}",
            row.share * 100.0,
            row.intervals,
            id(row.waker_pid),
            id(row.waker_tid),
        )?;
    }
    if rows.iter().any(|row| row.wakeup_latency_ns.is_some()) {
        writeln!(
            out,
            "(latency: of the time, how long woken threads waited for a CPU)"
        )?;
    }
    Ok(())
}

fn write_syscall_rows(out: &mut impl Write, rows: &[SyscallRow], unit: Unit) -> io::Result<()> {
    let what = counted(unit);
    let calls = rows.iter().any(|row| row.calls.is_some());
    if calls {
        writeln!(
            out,
            "{:>7} {:>9} {:>10} {:>9} {:>9}  syscall",
            what, "calls", "in calls", "median", "p99"
        )?;
    } else {
        writeln!(out, "{what:>7}  syscall")?;
    }
    for row in rows {
        let syscall = match (row.in_syscall, &row.syscall) {
            _ if row.own_programs => "(uhr's eBPF programs)",
            (_, Some(name)) => name,
            (Some(true), None) => "(in a syscall, unknown which)",
            (Some(false), None) => "(not in a syscall)",
            (None, None) => "(unknown)",
        };
        write!(out, "{:>6.1}%", row.share * 100.0)?;
        match &row.calls {
            Some(calls) => {
                let mut called = calls.calls.to_string();
                if calls.unfinished > 0 {
                    called = format!("{called}+{}", calls.unfinished);
                }
                write!(
                    out,
                    " {called:>9} {:>10} {:>9} {:>9}",
                    duration(calls.time_ns + calls.unfinished_ns),
                    calls.median.map(latency).unwrap_or_default(),
                    calls.p99.map(latency).unwrap_or_default(),
                )?;
            }
            None if calls => write!(out, " {:>9} {:>10} {:>9} {:>9}", "", "", "", "")?,
            None => {}
        }
        writeln!(out, "  {syscall}")?;
    }
    if rows
        .iter()
        .any(|row| row.calls.as_ref().is_some_and(|c| c.unfinished > 0))
    {
        writeln!(
            out,
            "(+n: calls still running when the capture ended, in the time)"
        )?;
    }
    Ok(())
}

/// The range a call time is in, by its end: `<2.0us`, or `>=34.4s` for the
/// last one, which has none.
fn latency(latency: Latency) -> String {
    match latency.below_ns {
        Some(below) => format!("<{}", duration(below)),
        None => format!(">={}", duration(latency.at_least_ns)),
    }
}

fn duration(ns: u64) -> String {
    let ns = ns as f64;
    match ns {
        _ if ns < 1e3 => format!("{ns:.0}ns"),
        _ if ns < 1e6 => format!("{:.1}us", ns / 1e3),
        _ if ns < 1e9 => format!("{:.1}ms", ns / 1e6),
        _ => format!("{:.1}s", ns / 1e9),
    }
}

fn describe_amount(metric: Metric, samples: u64, intervals: u64, value: u64) -> String {
    let seconds = value as f64 / 1e9;
    match metric {
        Metric::OnCPU => format!("{samples} samples, {seconds:.2} s of CPU time"),
        Metric::OffCPU => format!("{intervals} off-CPU intervals, {seconds:.2} s off CPU"),
        Metric::Wall => format!(
            "{samples} samples and {intervals} off-CPU intervals, {seconds:.2} s of thread time"
        ),
        Metric::PageFaults => format!("{samples} page-fault samples, {value} page faults"),
    }
}

/// What a result's amounts are of, in its coverage.
fn counted(unit: Unit) -> &'static str {
    match unit {
        Unit::Ns => "time",
        Unit::Faults => "faults",
    }
}

fn write_no_stack(out: &mut impl Write, share: f64) -> io::Result<()> {
    if share > 0.0 {
        writeln!(out, "  off-CPU time without a stack: {:.1}%", share * 100.0)?;
    }
    Ok(())
}

fn write_symbol_coverage(out: &mut impl Write, coverage: &SymbolCoverage) -> io::Result<()> {
    if !coverage.symbolized {
        writeln!(out, "  not symbolized: run `uhr symbolize`")?;
    }
    for path in &coverage.without_debug_info {
        writeln!(out, "  no debug info, inlined calls not expanded: {path}")?;
    }
    for source in &coverage.symbol_problems {
        let detail = source.detail.as_deref().map(|d| format!(": {d}"));
        writeln!(
            out,
            "  symbols {} {}{}",
            source.status.as_str(),
            source.path,
            detail.unwrap_or_default()
        )?;
    }
    Ok(())
}

fn write_coverage(out: &mut impl Write, coverage: &Coverage) -> io::Result<()> {
    writeln!(out, "  lost events: {}", coverage.lost_events)?;
    if let Some(throttled) = coverage.throttle_events {
        writeln!(out, "  throttle events: {throttled}")?;
    }
    writeln!(
        out,
        "  stacks at the depth limit: {}",
        coverage.stacks_at_stack_limit
    )?;
    if let Some(cut) = coverage.stacks_cut_at_stack_copy {
        writeln!(out, "  stacks cut at the stack copy: {cut}")?;
    }
    if let Some(skipped) = coverage.stacks_not_unwound.filter(|&n| n > 0) {
        writeln!(out, "  stacks of 32-bit code, not unwound: {skipped}")?;
    }
    for missing in &coverage.missing_signals {
        writeln!(
            out,
            "  missing {}: {}",
            missing.signal.as_str(),
            missing.reason
        )?;
    }
    for (stream, ns) in &coverage.overhead_ns {
        writeln!(
            out,
            "  profiler overhead of stream {stream}: {} of CPU time",
            seconds(*ns)
        )?;
    }
    for unknown in &coverage.unknown {
        writeln!(out, "  unknown: {unknown}")?;
    }
    for bias in &coverage.known_biases {
        writeln!(out, "  bias: {bias}")?;
    }
    Ok(())
}

pub fn describe_filter(filter: &Filter) -> String {
    let mut parts = Vec::new();
    parts.extend(filter.pids.iter().map(|pid| format!("pid {pid}")));
    parts.extend(filter.tids.iter().map(|tid| format!("tid {tid}")));
    parts.extend(
        filter
            .thread_names
            .iter()
            .map(|name| format!("thread {name}")),
    );
    parts.extend(
        filter
            .modes
            .iter()
            .map(|mode| format!("mode {}", mode.as_str())),
    );
    parts.extend(
        filter
            .under
            .iter()
            .map(|function| format!("under {function}")),
    );
    parts.extend(
        filter
            .syscalls
            .iter()
            .map(|syscall| format!("syscall {syscall}")),
    );
    parts.extend(
        filter
            .regions
            .iter()
            .map(|region| format!("region {}", region.as_str())),
    );
    if let Some(from) = filter.from_ns {
        parts.push(format!("from {}", seconds(from)));
    }
    if let Some(to) = filter.to_ns {
        parts.push(format!("to {}", seconds(to)));
    }
    parts.join(", ")
}

fn seconds(ns: u64) -> String {
    format!("{:.3}s", ns as f64 / 1e9)
}

fn bytes(n: u64) -> String {
    let units = ["KiB", "MiB", "GiB", "TiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut value = n as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < units.len() {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", units[unit])
}

pub fn function_name(function: &Function) -> String {
    let name = match (&function.name, &function.placeholder) {
        (Some(function), _) => function.clone(),
        (None, Some(placeholder)) => format!("{placeholder} (no symbol)"),
        (None, None) => "<unnamed>".into(),
    };
    match function.function_address {
        Some(address) => format!("{name} @0x{address:x}"),
        None if function.inlined => format!("{name} (inlined)"),
        None => name,
    }
}

fn module_name(function: &Function) -> &str {
    match &function.module {
        Some(path) => path.rsplit('/').next().unwrap_or(path),
        None => function.origin.as_str(),
    }
}
