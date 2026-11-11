//! The MCP server: the tools that read a recording, for an agent, over
//! stdin and stdout.

use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::SystemTime;

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerConfig};
use rmcp::schemars::{self, JsonSchema};
use rmcp::service::ServerInitializeError;
use rmcp::{ServerHandler, ServiceExt, tool, tool_handler, tool_router};
use serde::{Deserialize, Serialize};
use tokio::task::JoinError;
use uhr_core::call_paths;
use uhr_core::coverage::Coverage;
use uhr_core::filter::Filter;
use uhr_core::metric::Metric;
use uhr_core::overview;
use uhr_core::query::{self, GroupBy, Query};
use uhr_core::recording::{self, Manifest, Mode, Recording, RegionKind};
use uhr_core::symbols::Symbols;
use uhr_core::text;
use uhr_core::wall_clock::{self, Time};

/// The method, which a client gives its model before any tool is called.
const INSTRUCTIONS: &str = "\
uhr reads profiling recordings: where a program's time and memory went. A recording is a \
directory the uhr CLI made, with `uhr record -o DIR -- COMMAND` or `uhr record -o DIR --pid PID \
--duration 10s`. Every tool takes the path of one.

1. Call `overview` first. It says whether the program was computing or waiting, and what the \
recording could not see.
2. Then `query`. Computing: metric `cpu` by `function`, `line` or `module`. Waiting: metric \
`off_cpu` by `syscall` or `function`, or by `waker` for what ended the waits. Memory growing: \
metric `page_faults` by `function` or `region`.
3. Narrow with the filter instead of reading more rows: `under` keeps the stacks through a \
function, `syscalls` those in a syscall, `thread_names`, `from` and `to` pick threads and a time \
range. `call_paths` shows who calls a function and what it calls.
4. Read the coverage at the end of each result before trusting its numbers: frames without \
names, lost events and cut stacks say what they leave out. The known biases of how the recording \
was made hold for every result, and only `overview` lists them.";

/// Why the server could not start, or stopped.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("starting the async runtime")]
    Runtime(#[source] io::Error),
    #[error("starting the MCP session")]
    Initialize(#[source] Box<ServerInitializeError>),
    #[error("serving MCP")]
    Serve(#[source] JoinError),
}

/// Why a tool has no result.
#[derive(Debug, thiserror::Error)]
enum ToolError {
    #[error(transparent)]
    Recording(#[from] recording::Error),
    #[error("{parameter}")]
    Time {
        parameter: &'static str,
        source: wall_clock::Error,
    },
    #[error(transparent)]
    TimeRange(#[from] wall_clock::Error),
    #[error(transparent)]
    Overview(#[from] overview::Error),
    #[error(transparent)]
    Query(#[from] query::Error),
    #[error(transparent)]
    CallPaths(#[from] call_paths::Error),
    #[error("writing the result")]
    Write(#[from] io::Error),
}

/// Which samples and off-CPU intervals a result covers. The values in one
/// list are alternatives, and every list given has to match.
#[derive(Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(inline)]
struct FilterParams {
    /// Process ids.
    #[serde(default)]
    pids: Vec<u32>,
    /// Thread ids.
    #[serde(default)]
    tids: Vec<u32>,
    /// Patterns for the name a thread had at the time. `*` matches any
    /// characters, `?` one.
    #[serde(default)]
    thread_names: Vec<String>,
    /// CPU modes. Time off CPU has none, so any mode leaves it out.
    #[serde(default)]
    modes: Vec<ModeParam>,
    /// Functions, each as a result shows it, as `parse @0x1550` or `hash
    /// (inlined)`, or by its name alone where only one function has it, or
    /// by its id, which the error lists where several share the name. Keeps
    /// the stacks that contain one of them.
    #[serde(default)]
    under: Vec<String>,
    /// Syscall names, as `read`. Keeps the stacks in one of them.
    #[serde(default)]
    syscalls: Vec<String>,
    /// Kinds of memory region. Only page faults were in one, so any leaves
    /// out CPU samples and time off CPU.
    #[serde(default)]
    regions: Vec<RegionParam>,
    /// Start of a time range: an offset into the recording, as `1.5s` or
    /// `200ms`, or a time of day with a date and a UTC offset, as
    /// `2026-11-06T12:34:56.7Z`.
    from: Option<String>,
    /// End of the time range, not included, given as `from`.
    to: Option<String>,
}

#[derive(Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[schemars(inline)]
enum ModeParam {
    User,
    Kernel,
    Unknown,
}

#[derive(Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[schemars(inline)]
enum RegionParam {
    Heap,
    Stack,
    Anonymous,
    AnonymousCode,
    Shared,
    Code,
    File,
    Kernel,
}

impl FilterParams {
    /// `manifest` has the times of day that `from` and `to` can be.
    fn into_filter(self, manifest: &Manifest) -> Result<Filter, ToolError> {
        let (from_ns, to_ns) = wall_clock::offsets(
            manifest,
            parse_time("from", self.from)?,
            parse_time("to", self.to)?,
        )?;
        Ok(Filter {
            pids: self.pids,
            tids: self.tids,
            thread_names: self.thread_names,
            modes: self
                .modes
                .into_iter()
                .map(|mode| match mode {
                    ModeParam::User => Mode::User,
                    ModeParam::Kernel => Mode::Kernel,
                    ModeParam::Unknown => Mode::Unknown,
                })
                .collect(),
            under: self.under,
            syscalls: self.syscalls,
            regions: self
                .regions
                .into_iter()
                .map(|region| match region {
                    RegionParam::Heap => RegionKind::Heap,
                    RegionParam::Stack => RegionKind::Stack,
                    RegionParam::Anonymous => RegionKind::Anonymous,
                    RegionParam::AnonymousCode => RegionKind::AnonymousCode,
                    RegionParam::Shared => RegionKind::Shared,
                    RegionParam::Code => RegionKind::Code,
                    RegionParam::File => RegionKind::File,
                    RegionParam::Kernel => RegionKind::Kernel,
                })
                .collect(),
            from_ns,
            to_ns,
        })
    }
}

fn parse_time(parameter: &'static str, text: Option<String>) -> Result<Option<Time>, ToolError> {
    text.map(|text| text.parse())
        .transpose()
        .map_err(|source| ToolError::Time { parameter, source })
}

#[derive(Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[schemars(inline)]
enum GroupByParam {
    Function,
    Line,
    Module,
    Syscall,
    Region,
    Waker,
    WakerFunction,
}

impl From<GroupByParam> for GroupBy {
    fn from(group_by: GroupByParam) -> Self {
        match group_by {
            GroupByParam::Function => GroupBy::Function,
            GroupByParam::Line => GroupBy::Line,
            GroupByParam::Module => GroupBy::Module,
            GroupByParam::Syscall => GroupBy::Syscall,
            GroupByParam::Region => GroupBy::Region,
            GroupByParam::Waker => GroupBy::Waker,
            GroupByParam::WakerFunction => GroupBy::WakerFunction,
        }
    }
}

/// What stacks are weighed by. `cpu`: CPU time. `off_cpu`: the time threads
/// were switched out, runnable or blocked. `wall`: both, all the time
/// threads were alive. `page_faults`: page faults, which show the code that
/// first touched memory.
// Written too, for the schema to say which is the default.
#[derive(Clone, Copy, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[schemars(inline)]
enum MetricParam {
    #[default]
    Cpu,
    OffCpu,
    Wall,
    PageFaults,
}

impl From<MetricParam> for Metric {
    fn from(metric: MetricParam) -> Self {
        match metric {
            MetricParam::Cpu => Metric::OnCPU,
            MetricParam::OffCpu => Metric::OffCPU,
            MetricParam::Wall => Metric::Wall,
            MetricParam::PageFaults => Metric::PageFaults,
        }
    }
}

fn default_top() -> usize {
    20
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct OverviewParams {
    /// Path of the recording directory.
    recording: PathBuf,
    /// Processes and threads to list, by CPU time, and processes by memory.
    #[serde(default = "default_top")]
    top: usize,
    #[serde(default)]
    filter: FilterParams,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct QueryParams {
    /// Path of the recording directory.
    recording: PathBuf,
    /// What a row is. `function`, or `line` for a function's source line:
    /// code, ranked by the amount in it, with the amount in it and all it
    /// called beside it. `module`: a binary, a library or the kernel.
    /// `syscall`: the syscall a thread was in. `region`: the kind of memory
    /// a page fault was in, with the metric `page_faults` only. `waker`:
    /// the thread or interrupt that ended each wait, and `waker_function`:
    /// the functions on the stacks of those wakeups, both with the metric
    /// `off_cpu` only.
    group_by: GroupByParam,
    #[serde(default)]
    metric: MetricParam,
    /// Rows to return.
    #[serde(default = "default_top")]
    top: usize,
    #[serde(default)]
    filter: FilterParams,
}

const DEPTH: NonZeroUsize = NonZeroUsize::new(3).unwrap();

fn default_depth() -> NonZeroUsize {
    DEPTH
}

fn default_children() -> usize {
    5
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct CallPathsParams {
    /// Path of the recording directory.
    recording: PathBuf,
    /// The function as a result shows it, as `parse @0x1550` or `hash
    /// (inlined)`, or by its name alone where only one function has it, or
    /// by its id, which the error lists where several share the name.
    function: String,
    #[serde(default)]
    metric: MetricParam,
    /// Levels of callers and of callees to follow.
    #[serde(default = "default_depth")]
    depth: NonZeroUsize,
    /// Callers or callees to show of each function. The rest are summed.
    #[serde(default = "default_children")]
    top: usize,
    #[serde(default)]
    filter: FilterParams,
}

struct Loaded {
    recording: Recording,
    symbols: Option<Symbols>,
}

/// The recording the tools read last. A model asks many questions of one
/// recording, and reading it is most of what a question takes. It stays in
/// memory as long as the server runs, so only one is kept.
#[derive(Default)]
struct Cache {
    last: Mutex<Option<(Files, Arc<Loaded>)>>,
}

/// A recording's directory and what was in it: `uhr symbolize` adds files
/// to a recording, and another can be made where one was.
#[derive(PartialEq, Eq)]
struct Files {
    dir: PathBuf,
    /// By name, each with its size and when it was last written.
    files: Vec<(OsString, u64, SystemTime)>,
}

impl Files {
    fn of(dir: &Path) -> io::Result<Self> {
        let mut files = Vec::new();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let metadata = entry.metadata()?;
            files.push((entry.file_name(), metadata.len(), metadata.modified()?));
        }
        files.sort();
        Ok(Self {
            dir: dir.to_owned(),
            files,
        })
    }
}

impl Cache {
    fn load(&self, dir: &Path) -> Result<Arc<Loaded>, ToolError> {
        // Held while reading, so that calls a client makes at once of one
        // recording read it once. What it guards is whole even after a
        // panic: it is only ever replaced.
        let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
        // A directory that cannot be listed is for reading it to refuse.
        let files = Files::of(dir).ok();
        if let (Some(files), Some((read, loaded))) = (&files, &*last)
            && files == read
        {
            return Ok(loaded.clone());
        }
        // Dropped first, so that reading the next needs no room for both.
        *last = None;
        let recording = Recording::read(dir)?;
        let symbols = Symbols::read(dir, &recording)?;
        let loaded = Arc::new(Loaded { recording, symbols });
        *last = files.map(|files| (files, loaded.clone()));
        Ok(loaded)
    }
}

fn overview(cache: &Cache, params: OverviewParams) -> Result<String, ToolError> {
    let Loaded { recording, symbols } = &*cache.load(&params.recording)?;
    let filter = params.filter.into_filter(&recording.manifest)?;
    let result = overview::run(recording, symbols.as_ref(), &filter, params.top)?;
    render(|out| text::write_overview(out, &result))
}

fn query(cache: &Cache, params: QueryParams) -> Result<String, ToolError> {
    let Loaded { recording, symbols } = &*cache.load(&params.recording)?;
    let query = Query {
        group_by: params.group_by.into(),
        metric: params.metric.into(),
        top: params.top,
        filter: params.filter.into_filter(&recording.manifest)?,
    };
    let mut result = query::run(recording, symbols.as_ref(), &query)?;
    let biases = take_biases(&mut result.coverage.recording);
    render(|out| {
        text::write_query(out, &result)?;
        write_biases(out, biases)
    })
}

fn call_paths(cache: &Cache, params: CallPathsParams) -> Result<String, ToolError> {
    let Loaded { recording, symbols } = &*cache.load(&params.recording)?;
    let query = call_paths::Query {
        function: params.function,
        depth: params.depth.get(),
        top: params.top,
        metric: params.metric.into(),
        filter: params.filter.into_filter(&recording.manifest)?,
    };
    let mut result = call_paths::run(recording, symbols.as_ref(), &query)?;
    let biases = take_biases(&mut result.coverage.recording);
    render(|out| {
        text::write_call_paths(out, &result)?;
        write_biases(out, biases)
    })
}

/// How many biases a result's coverage has, which it then has none of. A
/// recording's are the same in every result, and most of each: a model
/// that reads them once, in `overview`, has several times the room for
/// results.
fn take_biases(coverage: &mut Coverage) -> usize {
    std::mem::take(&mut coverage.known_biases).len()
}

/// Ends the coverage a result was written with.
fn write_biases(out: &mut impl Write, biases: usize) -> io::Result<()> {
    if biases > 0 {
        writeln!(
            out,
            "  known biases: {biases}, of how the recording was made. `overview` lists them"
        )?;
    }
    Ok(())
}

/// The text form of a result: a model reads it at a fraction of the size of
/// the JSON.
fn render(write: impl FnOnce(&mut Vec<u8>) -> io::Result<()>) -> Result<String, ToolError> {
    let mut text = Vec::new();
    write(&mut text)?;
    Ok(String::from_utf8_lossy(&text).into_owned())
}

/// A tool that fails says why in its result, where the model can read it
/// and try again.
async fn respond(
    run: impl FnOnce() -> Result<String, ToolError> + Send + 'static,
) -> CallToolResult {
    // Off the thread that answers the client: reading a large recording
    // takes seconds.
    let error = match tokio::task::spawn_blocking(run).await {
        Ok(Ok(text)) => return CallToolResult::success(vec![ContentBlock::text(text)]),
        Ok(Err(error)) => with_causes(&error),
        Err(error) => format!("the tool did not finish: {error}"),
    };
    CallToolResult::error(vec![ContentBlock::text(error)])
}

/// An error and what caused it, on one line.
fn with_causes(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut cause = error.source();
    while let Some(error) = cause {
        text.push_str(": ");
        text.push_str(&error.to_string());
        cause = error.source();
    }
    text
}

#[derive(Default)]
struct Server {
    cache: Arc<Cache>,
}

#[tool_router]
impl Server {
    /// Where a recording's time and memory went, at the top level: CPU time
    /// in user and kernel mode, time off CPU runnable and blocked, by
    /// process and thread, each process's resident memory, and what the
    /// recording could not see. Call it first: whether the program was
    /// computing or waiting decides what to look at next.
    #[tool(annotations(
        title = "Overview of a recording",
        read_only_hint = true,
        open_world_hint = false
    ))]
    async fn overview(&self, Parameters(params): Parameters<OverviewParams>) -> CallToolResult {
        let cache = self.cache.clone();
        respond(move || overview(&cache, params)).await
    }

    /// Rank what a recording's CPU time, time off CPU or page faults went
    /// to: group them by function, source line, module, syscall, region of
    /// memory or waker, keep what passes a filter, and get the top rows
    /// with their shares, and the coverage. Group and filter the same
    /// recording again to move between levels: by `syscall`, and then by
    /// `function` with that syscall in the filter, shows the code that
    /// makes it.
    #[tool(annotations(
        title = "Query a recording",
        read_only_hint = true,
        open_world_hint = false
    ))]
    async fn query(&self, Parameters(params): Parameters<QueryParams>) -> CallToolResult {
        let cache = self.cache.clone();
        respond(move || query(&cache, params)).await
    }

    /// Who calls a function and what it calls: two trees from the function
    /// outward, its callers and its callees, each path with its share of
    /// the recording's CPU time, time off CPU or page faults. For a
    /// function `query` ranked high: the callers say why it runs, and the
    /// callees where its time goes.
    #[tool(annotations(
        title = "Callers and callees of a function",
        read_only_hint = true,
        open_world_hint = false
    ))]
    async fn call_paths(&self, Parameters(params): Parameters<CallPathsParams>) -> CallToolResult {
        let cache = self.cache.clone();
        respond(move || call_paths(&cache, params)).await
    }
}

#[tool_handler]
impl ServerHandler for Server {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("uhr", env!("CARGO_PKG_VERSION")))
            .with_instructions(INSTRUCTIONS)
    }
}

/// Serves until the client closes stdin.
pub fn serve() -> Result<(), Error> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(Error::Runtime)?;
    runtime.block_on(async {
        let service = Server::default()
            .serve(rmcp::transport::stdio())
            .await
            .map_err(|error| Error::Initialize(Box::new(error)))?;
        service.waiting().await.map_err(Error::Serve)?;
        Ok(())
    })
}
