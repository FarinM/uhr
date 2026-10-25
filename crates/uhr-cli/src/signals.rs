use std::io;
use std::mem::MaybeUninit;
use std::ptr;

use uhr_core::launch::Interrupts;

/// A signal handler can only reach statics.
pub static INTERRUPTS: Interrupts = Interrupts::new();

const SIGNALS: [libc::c_int; 1] = [libc::SIGINT];

/// Sends SIGINT to `INTERRUPTS` until dropped, which brings back how the
/// process handled it before. A handler rather than SIG_IGN, because ignored
/// signals stay ignored in a target after exec.
pub struct Handlers {
    previous: Vec<(libc::c_int, libc::sigaction)>,
}

extern "C" fn interrupt(_: libc::c_int) {
    INTERRUPTS.interrupt();
}

impl Handlers {
    pub fn install() -> io::Result<Self> {
        let mut handlers = Self {
            previous: Vec::new(),
        };
        for signal in SIGNALS {
            // SAFETY: a zeroed sigaction is valid, and the fields set make it
            // a handler that restarts interrupted system calls.
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = interrupt as extern "C" fn(libc::c_int) as libc::sighandler_t;
            action.sa_flags = libc::SA_RESTART;
            let mut previous = MaybeUninit::uninit();
            // SAFETY: both pointers are valid for the call.
            if unsafe { libc::sigaction(signal, &action, previous.as_mut_ptr()) } != 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: sigaction succeeded, so it wrote `previous`.
            handlers
                .previous
                .push((signal, unsafe { previous.assume_init() }));
        }
        Ok(handlers)
    }
}

impl Drop for Handlers {
    fn drop(&mut self) {
        for (signal, previous) in self.previous.drain(..).rev() {
            // SAFETY: `previous` is what sigaction returned for `signal`.
            unsafe { libc::sigaction(signal, &previous, ptr::null_mut()) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handler_of(signal: libc::c_int) -> libc::sighandler_t {
        let mut current = MaybeUninit::uninit();
        // SAFETY: a null new action only reads the current one.
        assert_eq!(
            unsafe { libc::sigaction(signal, ptr::null(), current.as_mut_ptr()) },
            0
        );
        // SAFETY: sigaction succeeded.
        unsafe { current.assume_init() }.sa_sigaction
    }

    #[test]
    fn brings_back_the_earlier_handling() {
        let before = SIGNALS.map(handler_of);
        let handlers = Handlers::install().unwrap();
        assert!(SIGNALS.iter().all(|&s| handler_of(s) != libc::SIG_DFL));
        drop(handlers);
        assert_eq!(SIGNALS.map(handler_of), before);
    }
}
