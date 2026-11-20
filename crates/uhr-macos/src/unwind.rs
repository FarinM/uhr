//! Walks a suspended thread's stack with framehop, from the unwind tables
//! of the images in its process: Apple's compact unwind info, DWARF CFI,
//! and frame pointers where code has neither, as JIT code.

use std::ops::{Deref, Range};
use std::sync::Arc;

#[cfg(target_arch = "aarch64")]
use framehop::aarch64::{CacheAarch64 as Cache, PtrAuthMask, UnwindRegsAarch64, UnwinderAarch64};
#[cfg(target_arch = "x86_64")]
use framehop::x86_64::{CacheX86_64 as Cache, UnwindRegsX86_64, UnwinderX86_64};
use framehop::{ExplicitModuleSectionInfo, FrameAddress, Module, Unwinder};

use crate::held::Chunks;
use crate::images::Image;
use crate::mach::{Failed, Mapped, Registers, Task};

#[cfg(target_arch = "aarch64")]
type ArchUnwinder = UnwinderAarch64<Text>;
#[cfg(target_arch = "x86_64")]
type ArchUnwinder = UnwinderX86_64<Text>;

/// Part of an image's `__TEXT` segment, as mapped from its process.
#[derive(Clone)]
struct Text {
    segment: Arc<Mapped>,
    range: Range<usize>,
}

impl Deref for Text {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.segment[self.range.clone()]
    }
}

/// The most chunks of a stack one walk reads, 256 KiB, which bounds how
/// long a thread is held still.
const MAX_CHUNKS: usize = 64;

/// The unwind tables of one process's images.
pub(crate) struct Unwinding {
    unwinder: ArchUnwinder,
    cache: Cache,
}

/// One walk: return addresses after the first frame's address, outermost
/// last.
pub(crate) struct Walk {
    pub frames: Vec<FrameAddress>,
    /// Where each frame ends on the stack, its caller's stack pointer, where
    /// its caller was found.
    pub ends: Vec<Option<u64>>,
    pub end: End,
}

/// Why a walk ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum End {
    /// At the outermost frame.
    Outermost,
    /// The stack went on past the most frames asked for.
    Depth,
    /// Before the outermost frame: a frame's caller could not be found, as
    /// in code with neither unwind tables nor a frame pointer, or past the
    /// most stack a walk reads.
    Failed,
}

impl Unwinding {
    pub(crate) fn new() -> Self {
        Self {
            unwinder: ArchUnwinder::new(),
            cache: Cache::new(),
        }
    }

    /// Adds an image's unwind tables, which uhr maps from the process rather
    /// than reads from its file, as images in the dyld shared cache have
    /// none of their own.
    pub(crate) fn add(&mut self, task: &Task, image: &Image) -> Result<(), Failed> {
        let header = &image.header;
        let (Some(text), Some(slide)) = (header.segment("__TEXT"), image.slide()) else {
            return Ok(());
        };
        let segment = Arc::new(task.map(text.vmaddr.wrapping_add(slide), text.vmsize)?);
        let svma = |segment_name: &str, name: &str| {
            let section = header.section(segment_name, name)?;
            Some(section.addr..section.addr + section.size)
        };
        let data = |range: &Option<Range<u64>>| {
            let range = range.as_ref()?;
            let start = range.start.checked_sub(text.vmaddr)? as usize;
            let end = start + (range.end - range.start) as usize;
            (end <= segment.len()).then(|| Text {
                segment: Arc::clone(&segment),
                range: start..end,
            })
        };
        let text_svma = svma("__TEXT", "__text");
        let unwind_info_svma = svma("__TEXT", "__unwind_info");
        let eh_frame_svma = svma("__TEXT", "__eh_frame");
        let info = ExplicitModuleSectionInfo {
            base_svma: text.vmaddr,
            text: data(&text_svma),
            text_svma,
            stubs_svma: svma("__TEXT", "__stubs"),
            stub_helper_svma: svma("__TEXT", "__stub_helper"),
            got_svma: svma("__DATA_CONST", "__got").or_else(|| svma("__DATA", "__got")),
            unwind_info: data(&unwind_info_svma),
            eh_frame: data(&eh_frame_svma),
            eh_frame_svma,
            text_segment_svma: Some(text.vmaddr..text.vmaddr + text.vmsize),
            text_segment: Some(Text {
                range: 0..segment.len(),
                segment: Arc::clone(&segment),
            }),
            eh_frame_hdr_svma: None,
            eh_frame_hdr: None,
            debug_frame: None,
        };
        let start = text.vmaddr.wrapping_add(slide);
        self.unwinder.add_module(Module::new(
            image.path.clone(),
            start..start + text.vmsize,
            start,
            info,
        ));
        Ok(())
    }

    pub(crate) fn remove(&mut self, image: &Image) {
        if let (Some(text), Some(slide)) = (image.header.segment("__TEXT"), image.slide()) {
            self.unwinder.remove_module(text.vmaddr.wrapping_add(slide));
        }
    }

    /// Walks the stack of a thread held still with `registers`, up to
    /// `max` frames, reading it into `chunks`, which it clears first.
    pub(crate) fn walk(
        &mut self,
        task: &Task,
        chunks: &mut Chunks,
        registers: Registers,
        max: usize,
    ) -> Walk {
        chunks.clear();
        let mut read_stack = |address: u64| -> Result<u64, ()> {
            if !address.is_multiple_of(8) {
                return Err(());
            }
            chunks.word(task, address, MAX_CHUNKS).ok_or(())
        };
        let (pc, mut regs) = regs(registers);
        let mut frames = vec![FrameAddress::InstructionPointer(pc)];
        let mut ends = Vec::new();
        let end = loop {
            let frame = *frames.last().expect("never empty");
            let caller =
                self.unwinder
                    .unwind_frame(frame, &mut regs, &mut self.cache, &mut read_stack);
            match caller {
                Ok(Some(address)) => {
                    ends.push(Some(regs.sp()));
                    let Some(caller) = FrameAddress::from_return_address(address) else {
                        break End::Failed;
                    };
                    if frames.len() == max {
                        break End::Depth;
                    }
                    frames.push(caller);
                }
                Ok(None) => break End::Outermost,
                Err(_) => break End::Failed,
            }
        };
        ends.resize(frames.len(), None);
        Walk { frames, ends, end }
    }
}

/// On arm64e, the processes Apple builds sign return addresses, which
/// framehop strips with this mask; it changes none of another process's.
#[cfg(target_arch = "aarch64")]
fn regs(registers: Registers) -> (u64, UnwindRegsAarch64) {
    let mask = PtrAuthMask::new_24_40();
    let regs =
        UnwindRegsAarch64::new_with_ptr_auth_mask(mask, registers.lr, registers.sp, registers.fp);
    (mask.strip_ptr_auth(registers.pc), regs)
}

#[cfg(target_arch = "x86_64")]
fn regs(registers: Registers) -> (u64, UnwindRegsX86_64) {
    (
        registers.pc,
        UnwindRegsX86_64::new(registers.pc, registers.sp, registers.fp),
    )
}
