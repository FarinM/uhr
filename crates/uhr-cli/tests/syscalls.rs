//! End to end: needs perf and a C compiler. `uhr doctor` shows what is
//! missing.
#![cfg(target_os = "linux")]

mod common;

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::Duration;

use serde_json::Value;

use common::{UHR, as_root, compile, scratch, uhr, uhr_as_root};

/// While a test records as root, uhr's programs run at every process's
/// syscalls, outside the syscall's own function, so the tests here take
/// turns.
static EBPF: Mutex<()> = Mutex::new(());

fn one_at_a_time() -> MutexGuard<'static, ()> {
    EBPF.lock().unwrap_or_else(PoisonError::into_inner)
}

fn json(args: &[&str]) -> Value {
    let mut args = args.to_vec();
    args.push("--json");
    serde_json::from_slice(&uhr(&args).stdout).unwrap()
}

#[test]
fn the_time_is_in_the_kernel_on_behalf_of_read_zero() {
    let _turn = one_at_a_time();
    let dir = scratch("syscalls_kernel_time");
    let program = dir.join("syscalls");
    compile("syscalls", &program, "-O2");
    let recording = dir.join("rec");
    let recording = recording.to_str().unwrap();
    // As root, uhr's syscall programs would take part of the time.
    let output = uhr(&[
        "record",
        "-o",
        recording,
        "--no-syscalls",
        "--",
        program.to_str().unwrap(),
        "200000",
    ]);
    // What the kernel measured of the program, as the program printed it.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let own: Vec<f64> = stdout
        .lines()
        .find_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            match fields[..] {
                [
                    "process",
                    "user_ns",
                    user,
                    "kernel_ns",
                    kernel,
                    "wall_ns",
                    wall,
                ] => Some([user, kernel, wall].map(|n| n.parse().unwrap()).to_vec()),
                _ => None,
            }
        })
        .unwrap_or_else(|| panic!("no measurement in {stdout:?}"));
    let (own_user, own_kernel, own_wall) = (own[0], own[1], own[2]);

    let overview = json(&["overview", recording]);
    if overview["kernel_cpu_ns"].is_null() {
        // perf could not sample the kernel here. The overview has to say
        // so instead of calling the program idle.
        let missing = overview["coverage"]["missing_signals"].as_array().unwrap();
        assert!(
            missing.iter().any(|m| m["signal"] == "kernel_cpu_samples"),
            "{missing:?}"
        );
        let unknown = overview["coverage"]["unknown"].as_array().unwrap();
        assert!(
            unknown
                .iter()
                .any(|u| u.as_str().unwrap().starts_with("CPU time in the kernel")),
            "{unknown:?}"
        );
        return;
    }

    let cpu = overview["cpu_ns"].as_f64().unwrap();
    let kernel = overview["kernel_cpu_ns"].as_f64().unwrap() / cpu;
    assert!(
        kernel > 0.8,
        "only {kernel} of the CPU time is in the kernel"
    );
    let own_cpu = own_user + own_kernel;
    assert!(
        (cpu - own_cpu).abs() <= 0.05 * own_cpu + 5e6,
        "sampled {cpu} ns of CPU time, measured {own_cpu}"
    );
    let own_kernel_share = own_kernel / own_cpu;
    assert!(
        (kernel - own_kernel_share).abs() <= 0.1,
        "{kernel} of the CPU time in the kernel, measured {own_kernel_share}"
    );
    let share = overview["threads"][0]["on_cpu_share"].as_f64().unwrap();
    let own_share = own_cpu / own_wall;
    assert!(
        (share - own_share).abs() <= 0.05,
        "on CPU for {share} of its life, measured {own_share}"
    );

    let query = json(&[
        "query",
        recording,
        "--group-by",
        "function",
        "--mode",
        "kernel",
        "--top",
        "100",
    ]);
    // The kernel has a read_zero of its own, which reads /dev/zero.
    let read_zero = query["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["function"] == "read_zero" && r["origin"] == "binary")
        .expect("read_zero is on the kernel stacks");
    assert!(
        read_zero["total_share"].as_f64().unwrap() > 0.95,
        "{read_zero}"
    );
    assert!(
        query["rows"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["origin"] == "kernel" || r["self"] == 0),
        "only kernel code runs in kernel mode"
    );

    let modules = json(&["query", recording, "--group-by", "module"]);
    let module = |path: &dyn Fn(&str) -> bool| {
        modules["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["module"].as_str().is_some_and(path))
            .unwrap_or_else(|| panic!("no such module in {modules}"))
    };
    let in_kernel = module(&|path| path == "[kernel]")["self_share"]
        .as_f64()
        .unwrap();
    assert!(
        (in_kernel - kernel).abs() <= 0.05,
        "{in_kernel} of the time in kernel code, {kernel} in kernel mode"
    );
    let under_program = module(&|path| path.ends_with("/syscalls"))["total_share"]
        .as_f64()
        .unwrap();
    assert!(under_program > 0.95, "{under_program}");

    let manifest: Value =
        serde_json::from_slice(&fs::read(Path::new(recording).join("manifest.json")).unwrap())
            .unwrap();
    if manifest["kernel_symbols"]["status"] != "saved" {
        return;
    }
    let syscalls = json(&["query", recording, "--group-by", "syscall"]);
    let share = |wanted: &dyn Fn(&Value) -> bool| {
        syscalls["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| wanted(r))
            .map_or(0.0, |r| r["share"].as_f64().unwrap())
    };
    let read = share(&|r| r["syscall"] == "read");
    assert!(
        read > kernel - 0.05,
        "{read} of the time in read, {kernel} in the kernel: {syscalls}"
    );
    let outside = share(&|r| r["in_syscall"] == false);
    assert!(
        (outside - (1.0 - kernel)).abs() <= 0.05,
        "{outside} of the time not in a syscall, {kernel} in the kernel: {syscalls}"
    );
}

#[test]
fn counts_every_call_of_each_syscall() {
    let _turn = one_at_a_time();
    let dir = scratch("syscalls_counted");
    let program = dir.join("syscalls");
    compile("syscalls", &program, "-O2");
    let recording = dir.join("rec");
    let rec = recording.to_str().unwrap();
    let args = ["record", "-o", rec, "--", program.to_str().unwrap(), "2000"];
    if uhr_as_root(&args, &recording).is_none() {
        eprintln!("skipped: needs root through sudo without a password");
        return;
    }
    let manifest: Value =
        serde_json::from_slice(&fs::read(recording.join("manifest.json")).unwrap()).unwrap();
    if let Some(missing) = manifest["missing_signals"]
        .as_array()
        .and_then(|m| m.first())
    {
        eprintln!("skipped: {}", missing["reason"]);
        return;
    }
    let result = json(&["query", rec, "--group-by", "syscall", "--top", "100"]);
    let rows = result["rows"].as_array().unwrap();
    let read = rows.iter().find(|r| r["syscall"] == "read").unwrap();
    // Each round reads once, and the loader reads the program's libraries.
    let calls = read["calls"]["calls"].as_u64().unwrap();
    assert!((2000..2010).contains(&calls), "{read}");
    assert!(
        read["calls"]["median"]["below_ns"].as_u64().is_some(),
        "{read}"
    );
    // Too quick for any sample, but counted.
    let mmap = rows.iter().find(|r| r["syscall"] == "mmap").unwrap();
    assert!(mmap["calls"]["calls"].as_u64().unwrap() > 0, "{mmap}");
    assert!(
        rows.iter().all(|r| r["syscall"] != "execve"),
        "counted before exec"
    );
}

#[test]
fn leaves_out_the_syscalls_it_is_asked_to() {
    let _turn = one_at_a_time();
    let dir = scratch("syscalls_skipped");
    let program = dir.join("syscalls");
    compile("syscalls", &program, "-O2");
    let recording = dir.join("rec");
    let rec = recording.to_str().unwrap();
    let args = [
        "record",
        "-o",
        rec,
        "--skip-syscall",
        "read",
        "--",
        program.to_str().unwrap(),
        "20000",
    ];
    if uhr_as_root(&args, &recording).is_none() {
        eprintln!("skipped: needs root through sudo without a password");
        return;
    }
    let manifest: Value =
        serde_json::from_slice(&fs::read(recording.join("manifest.json")).unwrap()).unwrap();
    let streams = manifest["streams"].as_array().unwrap();
    let Some(ebpf) = streams.iter().find(|s| s["id"] == "ebpf") else {
        eprintln!("skipped: no syscall counts: {manifest}");
        return;
    };
    assert_eq!(
        ebpf["collector"]["skipped_syscalls"],
        serde_json::json!(["read"])
    );
    let result = json(&["query", rec, "--group-by", "syscall", "--top", "100"]);
    let rows = result["rows"].as_array().unwrap();
    // Its time is still in the stacks, but none of its calls counted.
    let read = rows.iter().find(|r| r["syscall"] == "read").unwrap();
    assert!(read["share"].as_f64().unwrap() > 0.5, "{read}");
    assert!(read["calls"].is_null(), "{read}");
    let mmap = rows.iter().find(|r| r["syscall"] == "mmap").unwrap();
    assert!(mmap["calls"]["calls"].as_u64().unwrap() > 0, "{mmap}");
    let biases = result["coverage"]["known_biases"].as_array().unwrap();
    assert!(
        biases.iter().any(|b| b
            .as_str()
            .unwrap()
            .contains("not to count the calls of read")),
        "{biases:?}"
    );
}

#[test]
fn refuses_to_skip_a_syscall_it_does_not_know() {
    let dir = scratch("syscalls_skip_unknown");
    let recording = dir.join("rec");
    let output = Command::new(UHR)
        .args(["record", "--skip-syscall", "nosuch", "-o"])
        .arg(&recording)
        .args(["--", "true"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no syscall is named \"nosuch\""),
        "{stderr}"
    );
    assert!(!recording.exists());
}

#[test]
fn tells_its_own_programs_apart() {
    let _turn = one_at_a_time();
    let dir = scratch("syscalls_own_programs");
    let program = dir.join("syscalls");
    compile("syscalls", &program, "-O2");
    let recording = dir.join("rec");
    let rec = recording.to_str().unwrap();
    let args = [
        "record",
        "-o",
        rec,
        "--",
        program.to_str().unwrap(),
        "200000",
    ];
    if uhr_as_root(&args, &recording).is_none() {
        eprintln!("skipped: needs root through sudo without a password");
        return;
    }
    let manifest: Value =
        serde_json::from_slice(&fs::read(recording.join("manifest.json")).unwrap()).unwrap();
    if manifest["kernel_symbols"]["status"] != "saved"
        || manifest["streams"].as_array().unwrap().len() < 2
    {
        eprintln!("skipped: no kernel symbols or no syscall counts");
        return;
    }
    let result = json(&["query", rec, "--group-by", "function", "--top", "1000"]);
    let programs: Vec<&str> = result["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["function"].as_str())
        .filter(|f| f.starts_with("bpf_prog_"))
        .collect();
    // Each round's syscall runs the programs that time it, so samples land
    // in them.
    assert!(
        programs
            .iter()
            .any(|p| p.ends_with("_sys_enter") || p.ends_with("_sys_exit")),
        "{programs:?}"
    );

    let streams = manifest["streams"].as_array().unwrap();
    let ebpf = streams.iter().find(|s| s["id"] == "ebpf").unwrap();
    let overhead = ebpf["coverage"]["overhead_ns"].as_f64().unwrap();
    let share = result["coverage"]["own_programs_share"].as_f64().unwrap();
    let time_ns = result["value"].as_f64().unwrap();
    assert!(overhead > 0.0, "{ebpf}");
    assert!(
        (share * time_ns - overhead).abs() < 1.0,
        "{share} of {time_ns}, {ebpf}"
    );

    let syscalls = json(&["query", rec, "--group-by", "syscall", "--top", "100"]);
    let rows = syscalls["rows"].as_array().unwrap();
    let own = rows.iter().find(|r| r["own_programs"] == true).unwrap();
    assert_eq!(own["share"].as_f64().unwrap(), share, "{syscalls}");
}

#[test]
fn counts_no_syscalls_in_a_pid_namespace_of_its_own() {
    let _turn = one_at_a_time();
    let dir = scratch("syscalls_pid_namespace");
    let program = dir.join("syscalls");
    compile("syscalls", &program, "-O2");
    let recording = dir.join("rec");
    let rec = recording.to_str().unwrap();
    // With a /proc of its own, for perf.
    let unshare = ["unshare", "--pid", "--fork", "--mount-proc"];
    let record = ["record", "-o", rec, "--", program.to_str().unwrap(), "2000"];
    let command = [&unshare[..], &[UHR], &record].concat();
    if as_root(&command, &recording).is_none() {
        eprintln!("skipped: needs root through sudo without a password");
        return;
    }
    let manifest: Value =
        serde_json::from_slice(&fs::read(recording.join("manifest.json")).unwrap()).unwrap();
    let missing = manifest["missing_signals"].as_array().unwrap();
    assert!(
        missing.iter().any(|m| m["signal"] == "syscall_calls"
            && m["reason"].as_str().unwrap().contains("PID namespace")),
        "{manifest}"
    );
}

#[test]
fn follows_processes_after_many_have_come_and_gone() {
    let _turn = one_at_a_time();
    let dir = scratch("syscalls_churn");
    let program = dir.join("churn");
    compile("churn", &program, "-O2");
    let recording = dir.join("rec");
    let rec = recording.to_str().unwrap();
    // More processes than uhr's eBPF programs can follow at once.
    let args = [
        "record",
        "-o",
        rec,
        "--",
        program.to_str().unwrap(),
        "20000",
    ];
    if uhr_as_root(&args, &recording).is_none() {
        eprintln!("skipped: needs root through sudo without a password");
        return;
    }
    let result = json(&["query", rec, "--group-by", "syscall", "--top", "100"]);
    let rows = result["rows"].as_array().unwrap();
    let Some(read) = rows.iter().find(|r| r["syscall"] == "read") else {
        eprintln!("skipped: no syscall counts: {result}");
        return;
    };
    // The last process reads 1000 times, and the loader reads too.
    let calls = read["calls"]["calls"].as_u64().unwrap();
    assert!(calls >= 1000, "{read}");
}

#[test]
fn counts_a_thread_after_many_have_come_and_gone() {
    let _turn = one_at_a_time();
    let dir = scratch("syscalls_thread_exits");
    let program = dir.join("thread_exits");
    compile("thread_exits", &program, "-O2");
    let recording = dir.join("rec");
    let rec = recording.to_str().unwrap();
    // More threads than uhr's eBPF programs can keep a call in flight for.
    let args = [
        "record",
        "-o",
        rec,
        "--",
        program.to_str().unwrap(),
        "70000",
        "1000",
    ];
    if uhr_as_root(&args, &recording).is_none() {
        eprintln!("skipped: needs root through sudo without a password");
        return;
    }
    let result = json(&["query", rec, "--group-by", "syscall", "--top", "100"]);
    let rows = result["rows"].as_array().unwrap();
    let Some(read) = rows.iter().find(|r| r["syscall"] == "read") else {
        eprintln!("skipped: no syscall counts: {result}");
        return;
    };
    // The last thread reads 1000 times, and the loader reads too.
    let calls = read["calls"]["calls"].as_u64().unwrap();
    assert!(calls >= 1000, "{read}");
}

/// The calls of `syscall` counted in `recording` under the threads' name
/// `thread`. `None` if they were not counted.
/// The calls of `syscall` counted, of the threads `filter` keeps.
fn calls_of(recording: &str, filter: &[&str], syscall: &str) -> Option<u64> {
    let mut args = vec![
        "query",
        recording,
        "--group-by",
        "syscall",
        "--metric",
        "off-cpu",
        "--syscall",
        syscall,
    ];
    args.extend(filter);
    let result = json(&args);
    let rows = result["rows"].as_array().unwrap();
    let row = rows.iter().find(|r| r["syscall"] == syscall)?;
    row["calls"]["calls"].as_u64()
}

#[test]
fn counts_the_calls_of_a_thread_by_the_name_it_had() {
    let _turn = one_at_a_time();
    let dir = scratch("syscalls_by_thread_name");
    let program = dir.join("renamed");
    compile("renamed", &program, "-O2");
    let recording = dir.join("rec");
    let rec = recording.to_str().unwrap();
    let args = ["record", "-o", rec, "--", program.to_str().unwrap()];
    if uhr_as_root(&args, &recording).is_none() {
        eprintln!("skipped: needs root through sudo without a password");
        return;
    }
    assert_eq!(calls_of(rec, &["--thread", "renamed"], "getppid"), Some(3));
    // Named through its comm file, by the main thread.
    assert_eq!(calls_of(rec, &["--thread", "by-main"], "getppid"), Some(5));
    assert_eq!(
        calls_of(rec, &["--thread", "by-itself"], "getppid"),
        Some(7)
    );
    assert_eq!(calls_of(rec, &["--thread", "by-*"], "getppid"), Some(12));
}

#[test]
fn counts_each_call_under_a_name_the_thread_had_as_another_renames_it() {
    let _turn = one_at_a_time();
    let dir = scratch("syscalls_renaming");
    let program = dir.join("renaming");
    compile("renaming", &program, "-O2");
    let recording = dir.join("rec");
    let rec = recording.to_str().unwrap();
    let args = ["record", "-o", rec, "--", program.to_str().unwrap()];
    if uhr_as_root(&args, &recording).is_none() {
        eprintln!("skipped: needs root through sudo without a password");
        return;
    }
    let all = calls_of(rec, &[], "getppid").unwrap();
    let named: u64 = ["renaming", "AAAAAAAAAAAAAAA", "BBBBBBBBBBBBBBB"]
        .map(|name| calls_of(rec, &["--thread", name], "getppid").unwrap_or(0))
        .iter()
        .sum();
    assert_eq!(named, all);
}

#[test]
fn has_no_thread_names_where_it_could_not_follow_renames() {
    let _turn = one_at_a_time();
    if fs::metadata("/sys/kernel/btf/vmlinux").is_err() {
        eprintln!("skipped: the kernel has no BTF");
        return;
    }
    let dir = scratch("syscalls_renamed_without_btf");
    let program = dir.join("renamed");
    compile("renamed", &program, "-O2");
    let recording = dir.join("rec");
    let rec = recording.to_str().unwrap();
    // With the kernel's BTF hidden, in a mount namespace of its own.
    let hide = r#"mount --bind /dev/null /sys/kernel/btf/vmlinux && exec "$@""#;
    let record = ["record", "-o", rec, "--", program.to_str().unwrap()];
    let command = [
        &["unshare", "--mount", "sh", "-c", hide, "sh", UHR][..],
        &record,
    ]
    .concat();
    if as_root(&command, &recording).is_none() {
        eprintln!("skipped: needs root through sudo without a password");
        return;
    }
    assert_eq!(calls_of(rec, &[], "getppid"), Some(15));
    assert_eq!(calls_of(rec, &["--thread", "renamed"], "getppid"), None);
    let result = json(&["query", rec, "--group-by", "syscall"]);
    let biases = result["coverage"]["known_biases"].as_array().unwrap();
    assert!(
        biases
            .iter()
            .any(|b| b.as_str().unwrap().contains("renames by another thread")),
        "{biases:?}"
    );
}

#[test]
fn counts_a_thread_that_execs_by_its_new_name() {
    let _turn = one_at_a_time();
    let dir = scratch("syscalls_exec_from_thread");
    let (launcher, program) = (dir.join("exec_from_thread"), dir.join("syscalls"));
    compile("exec_from_thread", &launcher, "-O2");
    compile("syscalls", &program, "-O2");
    let recording = dir.join("rec");
    let rec = recording.to_str().unwrap();
    let (launcher, program) = (launcher.to_str().unwrap(), program.to_str().unwrap());
    let args = ["record", "-o", rec, "--", launcher, program, "2000"];
    if uhr_as_root(&args, &recording).is_none() {
        eprintln!("skipped: needs root through sudo without a password");
        return;
    }
    // Each round reads once, and the loader reads the program's libraries.
    let read = calls_of(rec, &["--thread", "syscalls"], "read").unwrap();
    assert!((2000..2010).contains(&read), "{read}");
    // The kernel keeps 15 bytes of a name.
    assert!(calls_of(rec, &["--thread", "exec_from_threa"], "mmap").unwrap() > 0);
}

#[test]
fn says_which_calls_were_still_running_at_the_end() {
    let _turn = one_at_a_time();
    let dir = scratch("syscalls_unfinished");
    let program = dir.join("naps");
    compile("naps", &program, "-O2");
    let mut target = Command::new(&program)
        .arg("200")
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    thread::sleep(Duration::from_millis(100));
    let recording = dir.join("rec");
    let rec = recording.to_str().unwrap();
    let pid = target.id().to_string();
    let args = ["record", "-o", rec, "--pid", &pid, "--duration", "1s"];
    let recorded = uhr_as_root(&args, &recording);
    target.kill().unwrap();
    target.wait().unwrap();
    if recorded.is_none() {
        eprintln!("skipped: needs root through sudo without a password");
        return;
    }
    let result = json(&["query", rec, "--group-by", "syscall", "--top", "100"]);
    let rows = result["rows"].as_array().unwrap();
    let Some(sleep) = rows.iter().find(|r| r["syscall"] == "clock_nanosleep") else {
        eprintln!("skipped: no syscall counts: {result}");
        return;
    };
    // It sleeps five times in the second, the first begun before uhr
    // attached, so left out, and the last still going at the end.
    let calls = &sleep["calls"];
    assert!(
        (3..=5).contains(&calls["calls"].as_u64().unwrap()),
        "{sleep}"
    );
    assert_eq!(calls["unfinished"], 1, "{sleep}");
    // The other thread made calls too, but none it was still in.
    let getppid = rows.iter().find(|r| r["syscall"] == "getppid").unwrap();
    assert!(getppid["calls"]["calls"].as_u64().unwrap() > 0, "{getppid}");
    let unfinished: u64 = rows
        .iter()
        .filter_map(|r| r["calls"]["unfinished"].as_u64())
        .sum();
    assert_eq!(unfinished, 1, "{result}");
}

#[test]
fn follows_a_process_that_took_the_id_of_one_gone() {
    let _turn = one_at_a_time();
    let dir = scratch("syscalls_reused_id");
    let program = dir.join("reuse");
    compile("reuse", &program, "-O2");
    let recording = dir.join("rec");
    let rec = recording.to_str().unwrap();
    let args = [
        "record",
        "-o",
        rec,
        "--",
        program.to_str().unwrap(),
        "100000",
    ];
    if uhr_as_root(&args, &recording).is_none() {
        eprintln!("skipped: needs root through sudo without a password");
        return;
    }
    let result = json(&["query", rec, "--group-by", "syscall", "--top", "100"]);
    let rows = result["rows"].as_array().unwrap();
    let Some(read) = rows.iter().find(|r| r["syscall"] == "read") else {
        eprintln!("skipped: no syscall counts: {result}");
        return;
    };
    // The second process reads 100000 times, and the loader reads too.
    let calls = read["calls"]["calls"].as_u64().unwrap();
    assert!(calls >= 100000, "{read}");
}
