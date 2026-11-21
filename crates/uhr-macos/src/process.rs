//! What the BSD side of the kernel says of a process: whether it exists,
//! and its name, parent, owner and command line.

use std::io;
use std::mem::{self, MaybeUninit};
use std::ptr;

/// Whether a process has the pid, whether or not uhr may signal it.
pub(crate) fn exists(pid: u32) -> bool {
    // SAFETY: signal 0 checks the pid and sends nothing.
    let sent = unsafe { libc::kill(pid as libc::pid_t, 0) };
    sent == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Its name, from the program it runs, as the kernel keeps it: up to 32
/// bytes.
pub(crate) fn name(pid: u32) -> Option<String> {
    let mut buffer = [0u8; 64];
    // SAFETY: the buffer is valid for its length.
    let len = unsafe {
        libc::proc_name(
            pid as libc::c_int,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
        )
    };
    (len > 0).then(|| String::from_utf8_lossy(&buffer[..len as usize]).into_owned())
}

/// The absolute path of the program it runs.
pub(crate) fn path(pid: u32) -> Option<String> {
    let mut buffer = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: the buffer is valid for its length.
    let len = unsafe {
        libc::proc_pidpath(
            pid as libc::c_int,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
        )
    };
    (len > 0).then(|| String::from_utf8_lossy(&buffer[..len as usize]).into_owned())
}

/// How many threads its task has, which a process can read of another of
/// its user's without its task port.
pub(crate) fn thread_count(pid: u32) -> Option<usize> {
    let mut info = MaybeUninit::<libc::proc_taskinfo>::zeroed();
    let size = mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
    // SAFETY: `info` has room for `size` bytes.
    let written = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDTASKINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    // SAFETY: the kernel filled it.
    (written == size).then(|| unsafe { info.assume_init() }.pti_threadnum as usize)
}

pub(crate) fn parent(pid: u32) -> Option<u32> {
    bsd_info(pid).map(|info| info.pbi_ppid)
}

/// The user and group it runs as.
pub(crate) fn owner(pid: u32) -> Option<(u32, u32)> {
    bsd_info(pid).map(|info| (info.pbi_uid, info.pbi_gid))
}

fn bsd_info(pid: u32) -> Option<libc::proc_bsdinfo> {
    let mut info = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: `info` has room for `size` bytes.
    let written = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    // SAFETY: the kernel filled it.
    (written == size).then(|| unsafe { info.assume_init() })
}

/// Its arguments, from the kernel's copy of what it exec'd with. Only root
/// can read another user's.
pub(crate) fn command_line(pid: u32) -> io::Result<Vec<String>> {
    let mut max: libc::c_int = 0;
    let mut size = mem::size_of::<libc::c_int>();
    let mut name = [libc::CTL_KERN, libc::KERN_ARGMAX];
    // SAFETY: `max` has room for `size` bytes.
    let code = unsafe {
        libc::sysctl(
            name.as_mut_ptr(),
            2,
            (&mut max as *mut libc::c_int).cast(),
            &mut size,
            ptr::null_mut(),
            0,
        )
    };
    if code != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buffer = vec![0u8; max as usize];
    let mut size = buffer.len();
    let mut name = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid as libc::c_int];
    // SAFETY: the buffer has room for `size` bytes.
    let code = unsafe {
        libc::sysctl(
            name.as_mut_ptr(),
            3,
            buffer.as_mut_ptr().cast(),
            &mut size,
            ptr::null_mut(),
            0,
        )
    };
    if code != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(arguments(&buffer[..size]))
}

/// `KERN_PROCARGS2` gives the argument count, the path exec'd, NULs up to an
/// aligned boundary, then each argument and variable, each ending in a NUL.
fn arguments(procargs: &[u8]) -> Vec<String> {
    let Some((count, rest)) = procargs.split_first_chunk::<4>() else {
        return Vec::new();
    };
    let count = i32::from_ne_bytes(*count).max(0) as usize;
    let Some(path_end) = rest.iter().position(|&b| b == 0) else {
        return Vec::new();
    };
    let start = rest[path_end..]
        .iter()
        .position(|&b| b != 0)
        .map_or(rest.len(), |i| path_end + i);
    rest[start..]
        .split(|&b| b == 0)
        .take(count)
        .map(|arg| String::from_utf8_lossy(arg).into_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_arguments_after_the_path() {
        let mut procargs = Vec::new();
        procargs.extend(3i32.to_ne_bytes());
        procargs.extend(b"/usr/local/bin/prog\0\0\0\0");
        procargs.extend(b"prog\0-x\0\0HOME=/\0");
        assert_eq!(arguments(&procargs), ["prog", "-x", ""]);
    }

    #[test]
    fn knows_its_own_process() {
        let pid = std::process::id();
        assert!(exists(pid));
        assert!(name(pid).is_some());
        assert!(path(pid).is_some_and(|path| path.starts_with('/')));
        assert_eq!(parent(pid), Some(std::os::unix::process::parent_id()));
        assert!(thread_count(pid).is_some_and(|count| count >= 1));
        assert!(!command_line(pid).unwrap().is_empty());
    }
}
