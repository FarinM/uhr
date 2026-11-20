//! A process's memory as uhr reads it while one of its threads is held
//! still: in chunks, each read once a walk, as the stack and the frames a
//! runtime keeps are read many words at a time, and each read is a call
//! into the kernel that keeps the thread held longer.

use std::cell::RefCell;
use std::collections::HashMap;
use std::io;

use uhr_core::runtimes::Memory;

use crate::mach::Task;

/// Chunks are this size and start at its multiples, so none crosses into
/// memory that is not mapped, whatever the page size.
const CHUNK: u64 = 4096;

/// The chunks one walk read.
#[derive(Default)]
pub(crate) struct Chunks {
    /// Where in `data` each is, by its start.
    index: HashMap<u64, usize>,
    /// Kept from walk to walk, so that a walk allocates none.
    data: Vec<Box<[u8; CHUNK as usize]>>,
}

impl Chunks {
    /// Forgets what a walk read, as the process changes it once the thread
    /// runs again.
    pub(crate) fn clear(&mut self) {
        self.index.clear();
    }

    /// The chunk that starts at `start`, read from `task` unless this walk
    /// read it already. `Ok(None)` if that would read more than `limit`.
    fn chunk(
        &mut self,
        task: &Task,
        start: u64,
        limit: usize,
    ) -> io::Result<Option<&[u8; CHUNK as usize]>> {
        if let Some(&at) = self.index.get(&start) {
            return Ok(Some(&self.data[at]));
        }
        let at = self.index.len();
        if at >= limit {
            return Ok(None);
        }
        if at == self.data.len() {
            self.data.push(Box::new([0; CHUNK as usize]));
        }
        task.read(start, &mut self.data[at][..])
            .map_err(io::Error::other)?;
        self.index.insert(start, at);
        Ok(Some(&self.data[at]))
    }

    /// The word at `address`, reading no more than `limit` chunks.
    pub(crate) fn word(&mut self, task: &Task, address: u64, limit: usize) -> Option<u64> {
        let start = address - address % CHUNK;
        let at = (address - start) as usize;
        let chunk = self.chunk(task, start, limit).ok()??;
        let word = chunk.get(at..at + 8)?;
        Some(u64::from_ne_bytes(word.try_into().expect("eight bytes")))
    }
}

/// A process's memory read through the chunks of a walk, up to `limit` of
/// them; past that, each read as asked.
pub(crate) struct Held<'a> {
    pub task: &'a Task,
    pub chunks: RefCell<&'a mut Chunks>,
    pub limit: usize,
}

impl Memory for Held<'_> {
    fn read(&self, address: u64, into: &mut [u8]) -> io::Result<()> {
        let mut chunks = self.chunks.borrow_mut();
        let mut done = 0;
        while done < into.len() {
            let at = address
                .checked_add(done as u64)
                .ok_or(io::ErrorKind::InvalidInput)?;
            let start = at - at % CHUNK;
            let offset = (at - start) as usize;
            let len = (CHUNK as usize - offset).min(into.len() - done);
            let to = &mut into[done..done + len];
            match chunks.chunk(self.task, start, self.limit)? {
                Some(chunk) => to.copy_from_slice(&chunk[offset..offset + len]),
                None => self.task.read(at, to).map_err(io::Error::other)?,
            }
            done += len;
        }
        Ok(())
    }
}
