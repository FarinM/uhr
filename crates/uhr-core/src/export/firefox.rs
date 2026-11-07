//! Firefox processed profile v55. Keep the wire schema here so upstream
//! changes do not affect the recording model. Firefox upgrades this version
//! on import, including moving these per-thread tables into shared tables.

use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Serialize, Serializer};
use serde_json::Value;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Profile {
    pub meta: Value,
    pub libs: Vec<Library>,
    pub threads: Vec<Thread>,
    pub pages: Vec<()>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Library {
    pub name: String,
    pub path: String,
    pub debug_name: String,
    pub debug_path: String,
    pub debug_id: String,
    pub code_id: Option<String>,
    pub arch: String,
}

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Thread {
    pub name: String,
    pub pid: String,
    pub tid: String,
    pub process_name: String,
    pub is_main_thread: bool,
    pub process_type: &'static str,
    pub process_startup_time: f64,
    pub process_shutdown_time: Option<f64>,
    pub register_time: f64,
    pub unregister_time: Option<f64>,
    pub paused_ranges: Vec<()>,
    pub string_array: Vec<String>,
    pub samples: Samples,
    pub stack_table: Stacks,
    pub frame_table: Frames,
    pub func_table: Functions,
    pub resource_table: Resources,
    pub native_symbols: Value,
    pub markers: Value,
}

#[derive(Default)]
pub(super) struct Samples(pub Vec<Sample>);
pub(super) struct Sample {
    pub time: f64,
    pub stack: Option<usize>,
    pub weight: f64,
}

impl Serialize for Samples {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(None)?;
        m.serialize_entry("length", &self.0.len())?;
        m.serialize_entry("time", &column(&self.0, |r| r.time))?;
        m.serialize_entry("stack", &column(&self.0, |r| r.stack))?;
        m.serialize_entry("weight", &column(&self.0, |r| r.weight))?;
        m.serialize_entry("weightType", "tracing-ms")?;
        m.end()
    }
}

#[derive(Default)]
pub(super) struct Stacks(pub Vec<(Option<usize>, usize)>);
impl Serialize for Stacks {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(None)?;
        m.serialize_entry("length", &self.0.len())?;
        m.serialize_entry("prefix", &column(&self.0, |r| r.0))?;
        m.serialize_entry("frame", &column(&self.0, |r| r.1))?;
        m.end()
    }
}

#[derive(Default)]
pub(super) struct Frames(pub Vec<Frame>);
pub(super) struct Frame {
    pub function: usize,
    pub category: usize,
    pub line: Option<u32>,
    pub inlined: bool,
}
impl Serialize for Frames {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let n = self.0.len();
        let mut m = s.serialize_map(None)?;
        m.serialize_entry("length", &n)?;
        m.serialize_entry("func", &column(&self.0, |r| r.function))?;
        m.serialize_entry("category", &column(&self.0, |r| r.category))?;
        m.serialize_entry("line", &column(&self.0, |r| r.line))?;
        m.serialize_entry("inlineDepth", &column(&self.0, |r| u32::from(r.inlined)))?;
        m.serialize_entry("address", &repeat(-1, n))?;
        m.serialize_entry("nativeSymbol", &repeat((), n))?;
        m.serialize_entry("subcategory", &repeat(0, n))?;
        m.serialize_entry("innerWindowID", &repeat(0, n))?;
        m.serialize_entry("column", &repeat((), n))?;
        m.end()
    }
}

#[derive(Default)]
pub(super) struct Functions(pub Vec<Function>);
pub(super) struct Function {
    pub name: usize,
    pub resource: i64,
    pub file: Option<usize>,
    pub line: Option<u32>,
    pub column: Option<u32>,
}
impl Serialize for Functions {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let n = self.0.len();
        let mut m = s.serialize_map(None)?;
        m.serialize_entry("length", &n)?;
        m.serialize_entry("name", &column(&self.0, |r| r.name))?;
        m.serialize_entry("resource", &column(&self.0, |r| r.resource))?;
        m.serialize_entry("fileName", &column(&self.0, |r| r.file))?;
        m.serialize_entry("lineNumber", &column(&self.0, |r| r.line))?;
        m.serialize_entry("columnNumber", &column(&self.0, |r| r.column))?;
        m.serialize_entry("isJS", &repeat(false, n))?;
        m.serialize_entry("relevantForJS", &repeat(false, n))?;
        m.end()
    }
}

#[derive(Default)]
pub(super) struct Resources(pub Vec<(usize, usize)>);
impl Serialize for Resources {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(None)?;
        m.serialize_entry("length", &self.0.len())?;
        m.serialize_entry("lib", &column(&self.0, |r| r.0))?;
        m.serialize_entry("name", &column(&self.0, |r| r.1))?;
        m.serialize_entry("type", &repeat(1, self.0.len()))?;
        m.serialize_entry("host", &repeat((), self.0.len()))?;
        m.end()
    }
}

fn column<T, U: Serialize>(rows: &[T], get: impl Fn(&T) -> U) -> impl Serialize {
    struct Column<'a, T, F>(&'a [T], F);
    impl<T, U: Serialize, F: Fn(&T) -> U> Serialize for Column<'_, T, F> {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            let mut seq = s.serialize_seq(Some(self.0.len()))?;
            for row in self.0 {
                seq.serialize_element(&(self.1)(row))?;
            }
            seq.end()
        }
    }
    Column(rows, get)
}

fn repeat<T: Serialize>(value: T, n: usize) -> impl Serialize {
    struct Repeat<T>(T, usize);
    impl<T: Serialize> Serialize for Repeat<T> {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            let mut seq = s.serialize_seq(Some(self.1))?;
            for _ in 0..self.1 {
                seq.serialize_element(&self.0)?;
            }
            seq.end()
        }
    }
    Repeat(value, n)
}
