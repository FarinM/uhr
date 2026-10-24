use std::collections::HashMap;

use serde::Serialize;

use crate::recording::{Origin, Recording};
use crate::symbols::{FrameName, Symbols};

/// One function, or the unnamed code of one module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Function {
    /// `None` for frames without a name.
    #[serde(rename = "function")]
    pub name: Option<String>,
    /// The label wholesym made up from the address when there is no name,
    /// such as `fun_1200`. Counted as unnamed.
    pub placeholder: Option<String>,
    /// Path of the file the code was mapped from.
    pub module: Option<String>,
    pub build_id: Option<String>,
    /// Function start relative to the binary's image base, when known.
    pub function_address: Option<u32>,
    pub origin: Origin,
}

/// Origin, module path and build-id, and function address.
type Key<'a> = (Origin, Option<(&'a str, Option<&'a str>)>, Option<u32>);

/// The frames of a recording, grouped into functions by module path,
/// build-id and function address. Mapping ids change across processes and
/// reloads, and build-ids tell apart different binaries at the same path.
pub(crate) struct Functions {
    /// The function of each frame.
    pub(crate) of_frame: Vec<u32>,
    functions: Vec<Function>,
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
                let module = frame.mapping.map(|m| {
                    let mapping = &recording.mappings[m as usize];
                    (mapping.path.as_str(), mapping.build_id.as_deref())
                });
                let address = symbols.and_then(|s| s.function_addresses[frame_id]);
                *ids.entry((frame.origin, module, address))
                    .or_insert_with(|| {
                        let name = symbols.and_then(|s| s.names[frame_id].as_ref());
                        functions.push(Function {
                            name: name.and_then(FrameName::symbol).map(str::to_owned),
                            placeholder: match name {
                                Some(FrameName::Placeholder(label)) => Some(label.clone()),
                                _ => None,
                            },
                            module: module.map(|(path, _)| path.to_owned()),
                            build_id: module.and_then(|(_, id)| id.map(str::to_owned)),
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
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.functions.len()
    }

    pub(crate) fn get(&self, id: u32) -> &Function {
        &self.functions[id as usize]
    }
}
