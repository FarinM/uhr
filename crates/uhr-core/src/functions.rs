use std::collections::HashMap;

use serde::Serialize;

use crate::recording::{Origin, Recording};
use crate::symbols::{FrameName, Symbols};

/// One function, or the unnamed code of one module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Function {
    /// The build-id, or the module path when there is none, and the function
    /// start, as in `3f9a01c2+0x1550`. Starts come from symbols or the
    /// binary's unwind tables, so the id stays the same across results and
    /// when symbols are resolved again. `None` for code without a known
    /// start: kernel code, a recording not yet symbolized, and the range a
    /// stripped binary's `EntryPoint` placeholder covers.
    pub id: Option<String>,
    /// `None` for frames without a name.
    #[serde(rename = "function")]
    pub name: Option<String>,
    /// The label wholesym made up from the address when there is no name,
    /// such as `fun_1200`. Counted as unnamed.
    pub placeholder: Option<String>,
    /// Path of the file the code was mapped from. The first one seen, when
    /// copies of one binary ran from several paths.
    pub module: Option<String>,
    pub build_id: Option<String>,
    /// Function start relative to the binary's image base, when known.
    pub function_address: Option<u32>,
    pub origin: Origin,
}

/// The placeholder wholesym gives the range from a stripped binary's entry
/// point to the next function start it knows. That range is not one
/// function, and debug symbols split it up.
const ENTRY_POINT: &str = "EntryPoint";

/// What identifies a function's file. Copies of one binary at different
/// paths share a build-id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Module<'a> {
    BuildId(&'a str),
    /// For a file whose build-id was not recorded.
    Path(&'a str),
}

impl Module<'_> {
    fn as_str(&self) -> &str {
        match self {
            Module::BuildId(id) | Module::Path(id) => id,
        }
    }
}

type Key<'a> = (Origin, Option<Module<'a>>, Option<u32>);

/// Why no single function matched what was asked for.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the recording has no function names or ids yet: run `uhr symbolize`")]
    NotSymbolized,
    #[error("no function in the samples has the id or name {0:?}")]
    NotFound(String),
    #[error(
        "{} functions are named {name:?}. Pass one of their ids: {}",
        .ids.len(),
        .ids.join(", ")
    )]
    Ambiguous { name: String, ids: Vec<String> },
}

/// The frames of a recording, grouped into functions by build-id (or path
/// without one) and function start. Mapping ids change across processes
/// and reloads, and build-ids tell apart different binaries at the same
/// path.
pub(crate) struct Functions {
    /// The function of each frame.
    pub(crate) of_frame: Vec<u32>,
    functions: Vec<Function>,
    symbolized: bool,
}

impl Functions {
    pub(crate) fn new(recording: &Recording, symbols: Option<&Symbols>) -> Self {
        let mut ids: HashMap<Key, u32> = HashMap::new();
        let mut functions = Vec::new();
        let of_frame = recording
            .frames
            .iter()
            .enumerate()
            .map(|(frame_id, frame)| {
                let mapping = frame.mapping.map(|m| &recording.mappings[m as usize]);
                let module = mapping.map(|m| match &m.build_id {
                    Some(id) => Module::BuildId(id),
                    None => Module::Path(&m.path),
                });
                let address = symbols.and_then(|s| s.function_addresses[frame_id]);
                *ids.entry((frame.origin, module, address))
                    .or_insert_with(|| {
                        let name = symbols.and_then(|s| s.names[frame_id].as_ref());
                        let placeholder = match name {
                            Some(FrameName::Placeholder(label)) => Some(label.clone()),
                            _ => None,
                        };
                        let boundary = placeholder.as_deref() != Some(ENTRY_POINT);
                        functions.push(Function {
                            id: module.zip(address).filter(|_| boundary).map(
                                |(module, address)| format!("{}+0x{address:x}", module.as_str()),
                            ),
                            name: name.and_then(FrameName::symbol).map(str::to_owned),
                            placeholder,
                            module: mapping.map(|m| m.path.clone()),
                            build_id: mapping.and_then(|m| m.build_id.clone()),
                            function_address: address,
                            origin: frame.origin,
                        });
                        functions.len() as u32 - 1
                    })
            })
            .collect();
        Self {
            of_frame,
            functions,
            symbolized: symbols.is_some(),
        }
    }

    /// The function with the id `wanted`, or the only one named `wanted`.
    pub(crate) fn select(&self, wanted: &str) -> Result<u32, Error> {
        if !self.symbolized {
            return Err(Error::NotSymbolized);
        }
        let all = || (0..self.len() as u32).map(|id| (id, self.get(id)));
        if let Some((id, _)) = all().find(|(_, f)| f.id.as_deref() == Some(wanted)) {
            return Ok(id);
        }
        let named: Vec<_> = all()
            .filter(|(_, f)| f.name.as_deref() == Some(wanted))
            .collect();
        match named[..] {
            [] => Err(Error::NotFound(wanted.to_owned())),
            [(id, _)] => Ok(id),
            _ => Err(Error::Ambiguous {
                name: wanted.to_owned(),
                ids: named
                    .iter()
                    .map(|(_, f)| f.id.clone().unwrap_or_else(|| "<no id>".into()))
                    .collect(),
            }),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.functions.len()
    }

    pub(crate) fn get(&self, id: u32) -> &Function {
        &self.functions[id as usize]
    }
}
