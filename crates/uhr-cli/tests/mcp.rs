//! Talks to `uhr mcp` as a client does: JSON-RPC, a message per line, over
//! its stdin and stdout.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{Value, json};
use uhr_core::recording::*;

const UHR: &str = env!("CARGO_BIN_EXE_uhr");

struct Client {
    server: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    requests: u64,
    /// What the server answered as the session started.
    initialized: Value,
}

impl Client {
    fn start() -> Self {
        let mut server = Command::new(UHR)
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut client = Client {
            stdin: server.stdin.take(),
            stdout: BufReader::new(server.stdout.take().unwrap()),
            server,
            requests: 0,
            initialized: Value::Null,
        };
        client.initialized = client.request(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0"},
            }),
        );
        client.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
        client
    }

    fn send(&mut self, message: Value) {
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(stdin, "{message}").unwrap();
        stdin.flush().unwrap();
    }

    /// The result of a request, which must not fail.
    fn request(&mut self, method: &str, params: Value) -> Value {
        self.requests += 1;
        let id = self.requests;
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        loop {
            let mut line = String::new();
            let read = self.stdout.read_line(&mut line).unwrap();
            assert_ne!(read, 0, "the server closed its stdout");
            let message: Value = serde_json::from_str(&line).unwrap();
            if message["id"] == id {
                assert!(message.get("error").is_none(), "{method} failed: {message}");
                return message["result"].clone();
            }
        }
    }

    /// The text of a tool's result, as `Err` if the tool said it failed.
    fn call(&mut self, tool: &str, arguments: Value) -> Result<String, String> {
        let result = self.request("tools/call", json!({"name": tool, "arguments": arguments}));
        let text: String = result["content"]
            .as_array()
            .unwrap()
            .iter()
            .map(|block| block["text"].as_str().unwrap())
            .collect();
        match result["isError"].as_bool() {
            Some(true) => Err(text),
            _ => Ok(text),
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.server.kill();
        let _ = self.server.wait();
    }
}

const MS: u64 = 1_000_000;

/// 10 ms of `app`: its main thread spends 6 ms in `parse` and 3 ms in
/// `render`, both called by `main`, and `worker` 1 ms in `main` and 6 ms
/// blocked. A runtime compiled the three functions, so the recording has
/// their names itself.
fn recording(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&dir);
    let code = 0x7f00_0000_0000;
    let functions = ["parse", "render", "main"];
    let starts = |at: usize| code + 0x1000 * at as u64;
    let sample = |tid, time_ms, stack, cpu_ms| Sample {
        time_ns: time_ms * MS,
        pid: 1,
        tid,
        cpu: None,
        mode: Mode::User,
        stack,
        cpu_ns: cpu_ms * MS,
    };
    let thread = |tid| Thread {
        pid: 1,
        tid,
        parent_pid: None,
        parent_tid: None,
        start_ns: None,
        end_ns: None,
    };
    let thread_name = |tid, name: &str| ThreadName {
        pid: 1,
        tid,
        time_ns: None,
        name: name.into(),
    };
    let recording = Recording {
        manifest: Manifest {
            format_version: FORMAT_VERSION,
            platform: Platform {
                os: "linux".into(),
                arch: "x86_64".into(),
            },
            target: Target {
                command: vec!["app".into()],
                launched: true,
                runtime_support: Some(Vec::new()),
                exit: Some(Exit::Code(0)),
            },
            clock: Clock::Monotonic,
            start_ns: Some(0),
            end_ns: Some(10 * MS),
            wall_clock: None,
            streams: vec![Stream {
                id: "perf".into(),
                collector: Collector::Perf {
                    version: "6.8".into(),
                    sampling: Some(Sampling {
                        event: "cpu-clock".into(),
                        frequency_hz: 1000,
                        requested_frequency_hz: 1000,
                    }),
                    page_faults: None,
                    context_switches: true,
                },
                signals: vec![
                    Signal::UserCPUSamples,
                    Signal::UserStacks,
                    Signal::KernelCPUSamples,
                    Signal::KernelStacks,
                    Signal::OffCPUTime,
                    Signal::OffCPUStacks,
                ],
                missing_signals: Vec::new(),
                coverage: StreamCoverage {
                    lost_events: 0,
                    stacks: Some(StackCoverage {
                        unwinding: Unwinding::FramePointers,
                        stack_copy_bytes: None,
                        samples: 3,
                        page_fault_samples: None,
                        off_cpu_intervals: Some(1),
                        throttle_events: Some(0),
                        max_stack_depth: 127,
                        stacks_at_stack_limit: 0,
                        stacks_cut_at_stack_copy: None,
                        stacks_not_unwound: None,
                        interpreters: Vec::new(),
                    }),
                    overhead_ns: None,
                    known_biases: vec!["Samples can land a few instructions late.".into()],
                },
            }],
            missing_signals: Vec::new(),
            kernel_symbols: KernelSymbols::Saved,
        },
        threads: vec![thread(1), thread(2)],
        thread_names: vec![thread_name(1, "app"), thread_name(2, "worker")],
        mappings: vec![Mapping {
            pid: Some(1),
            start: code,
            end: starts(functions.len()),
            file_offset: 0,
            path: "//anon".into(),
            build_id: None,
            time_ns: None,
        }],
        frames: (0..functions.len())
            .map(|at| Frame {
                origin: Origin::Jit,
                address: starts(at) + 0x10,
                mapping: Some(0),
                file_offset: None,
                return_address: false,
                interpreted: None,
            })
            .collect(),
        stacks: vec![vec![0, 2], vec![1, 2], vec![2]],
        samples: vec![sample(1, 1, 0, 6), sample(1, 7, 1, 3), sample(2, 1, 2, 1)],
        page_faults: Vec::new(),
        off_cpu: vec![OffCPUInterval {
            start_ns: 2 * MS,
            end_ns: 8 * MS,
            pid: 1,
            tid: 2,
            state: ThreadState::Blocked,
            stack: Some(2),
            wakeup: None,
        }],
        kernel_symbols: Vec::new(),
        jit_symbols: functions
            .iter()
            .enumerate()
            .map(|(at, name)| JitSymbol {
                pid: 1,
                start: starts(at),
                end: starts(at) + 0x20,
                name: (*name).into(),
            })
            .collect(),
        interpreted_code: Vec::new(),
        syscall_calls: Vec::new(),
        memory: Vec::new(),
        regions: Vec::new(),
        region_memory: Vec::new(),
    };
    recording.write(&dir).unwrap();
    let symbolized = Command::new(UHR)
        .arg("symbolize")
        .arg(&dir)
        .output()
        .unwrap();
    assert!(
        symbolized.status.success(),
        "{}",
        String::from_utf8_lossy(&symbolized.stderr)
    );
    dir
}

#[test]
fn says_what_it_is_and_how_to_start() {
    let client = Client::start();
    let server = &client.initialized;
    assert_eq!(server["serverInfo"]["name"], "uhr");
    assert_eq!(server["serverInfo"]["version"], env!("CARGO_PKG_VERSION"));
    let instructions = server["instructions"].as_str().unwrap();
    assert!(instructions.contains("`overview` first"), "{instructions}");
}

#[test]
fn its_tools_only_read_and_take_a_recording() {
    let mut client = Client::start();
    let listed = client.request("tools/list", json!({}));
    let tools = listed["tools"].as_array().unwrap();
    let names: Vec<_> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["overview"]);
    for tool in tools {
        assert_eq!(tool["annotations"]["readOnlyHint"], true, "{tool}");
        assert_eq!(
            tool["inputSchema"]["required"],
            json!(["recording"]),
            "{tool}"
        );
        assert!(!tool["description"].as_str().unwrap().is_empty(), "{tool}");
    }
}

#[test]
fn overview_says_where_the_time_went() {
    let recording = recording("mcp_overview");
    let mut client = Client::start();
    let text = client
        .call("overview", json!({"recording": recording}))
        .unwrap();
    assert!(text.contains("app, exited with code 0"), "{text}");
    assert!(text.contains("0.010s of CPU time"), "{text}");
    assert!(text.contains("blocked 0.006s"), "{text}");
    assert!(text.contains("worker"), "{text}");
    assert!(
        text.contains("bias: Samples can land a few instructions late."),
        "{text}"
    );

    let worker = json!({"recording": recording, "filter": {"thread_names": ["work*"]}});
    let text = client.call("overview", worker).unwrap();
    assert!(text.contains("filter: thread work*"), "{text}");
    assert!(text.contains("0.001s of CPU time"), "{text}");

    let late = json!({"recording": recording, "filter": {"from": "5ms"}});
    let text = client.call("overview", late).unwrap();
    assert!(text.contains("showing 0.005s to 0.010s"), "{text}");
    assert!(text.contains("0.003s of CPU time"), "{text}");
}

#[test]
fn a_tool_that_fails_says_why() {
    let recording = recording("mcp_errors");
    let mut client = Client::start();
    let missing = recording.join("nope");
    let error = client
        .call("overview", json!({"recording": missing}))
        .unwrap_err();
    assert!(error.contains("it is not a recording"), "{error}");

    // Dropped silently, it would give a result of all threads.
    let misnamed = json!({"recording": recording, "filter": {"thread": ["worker"]}});
    let error = client.call("overview", misnamed).unwrap_err();
    assert!(error.contains("unknown field `thread`"), "{error}");
    assert!(error.contains("`thread_names`"), "{error}");

    let unitless = json!({"recording": recording, "filter": {"from": "5"}});
    let error = client.call("overview", unitless).unwrap_err();
    assert!(error.starts_with("from: needs a unit"), "{error}");
}

#[test]
fn stops_when_the_client_closes_stdin() {
    let mut client = Client::start();
    drop(client.stdin.take());
    assert!(client.server.wait().unwrap().success());
}
