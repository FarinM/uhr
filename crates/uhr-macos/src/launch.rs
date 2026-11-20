//! Launching a program that hands uhr its own task port. uhr registers a
//! Mach service under a random name and starts the program with
//! `DYLD_INSERT_LIBRARIES` naming a small library of its own, whose
//! constructor sends the service `mach_task_self()` and waits for an answer,
//! so uhr can take its first poll before the program's own code runs. A
//! process can always give away its own task port, so this needs no root.

use std::collections::hash_map::DefaultHasher;
use std::env;
use std::ffi::{CString, OsString};
use std::fs;
use std::hash::{Hash, Hasher};
use std::io;
use std::mem::{self, MaybeUninit};
use std::os::macos::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use mach2::bootstrap::bootstrap_port;
use mach2::kern_return::kern_return_t;
use mach2::mach_port::{mach_port_allocate, mach_port_deallocate, mach_port_insert_right};
use mach2::message::{
    MACH_MSG_PORT_DESCRIPTOR, MACH_MSG_TYPE_MAKE_SEND, MACH_MSG_TYPE_MOVE_SEND_ONCE,
    MACH_MSG_TYPE_PORT_SEND, MACH_MSG_TYPE_PORT_SEND_ONCE, MACH_MSGH_BITS, MACH_MSGH_BITS_COMPLEX,
    MACH_MSGH_BITS_REMOTE_MASK, MACH_RCV_MSG, MACH_RCV_TIMED_OUT, MACH_RCV_TIMEOUT,
    MACH_RCV_TOO_LARGE, MACH_SEND_MSG, MACH_SEND_TIMEOUT, mach_msg, mach_msg_body_t,
    mach_msg_destroy, mach_msg_header_t, mach_msg_port_descriptor_t,
};
use mach2::port::{MACH_PORT_NULL, MACH_PORT_RIGHT_RECEIVE, mach_port_t};
use mach2::traps::mach_task_self;
use wholesym::samply_symbols::object::FileKind;

use crate::mach::{Failed, Port, Task, check};
use crate::macho;

/// Matches UHR_HELLO in preload.c.
const HELLO: i32 = 0x7568_7231;

/// The variable that names the service to the library.
const SERVICE: &str = "UHR_SERVICE";

const INSERT: &str = "DYLD_INSERT_LIBRARIES";

static LIBRARY: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/libuhr_preload.dylib"));

/// Why a program could not be launched to record.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// dyld would not load uhr's library into the program, and `fix` says
    /// how to change that.
    #[error(
        "cannot record: {detail}{}",
        .fix.as_ref().map(|fix| format!("\nfix: {fix}")).unwrap_or_default()
    )]
    Blocked { detail: String, fix: Option<String> },
    #[error("command not found or not executable: {0}")]
    CommandNotFound(String),
    #[error("registering the Mach service the target sends its task port to")]
    Service(#[source] Failed),
    #[error("writing {}, the library uhr has dyld load into the target", .path.display())]
    Library {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

unsafe extern "C" {
    // From <servers/bootstrap.h>. mach2 leaves it out, as it is deprecated,
    // but it is the only call that registers a service without launchd's
    // job description.
    fn bootstrap_register2(
        bp: mach_port_t,
        service_name: *const libc::c_char,
        sp: mach_port_t,
        flags: u64,
    ) -> kern_return_t;
}

const BOOTSTRAP_NAME_IN_USE: kern_return_t = 1101;

/// A Mach service of uhr's that launched programs send their task ports to.
/// Dropping it ends the service, and with it any hello not yet received.
#[derive(Debug)]
pub(crate) struct Service {
    /// The receive right.
    port: mach_port_t,
    name: String,
}

impl Service {
    pub(crate) fn register() -> Result<Self, Error> {
        let task = unsafe { mach_task_self() };
        let mut port = MACH_PORT_NULL;
        // SAFETY: `port` is valid to write.
        let code = unsafe { mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &mut port) };
        check("mach_port_allocate", code).map_err(Error::Service)?;
        // Releases the receive right if registering fails.
        let mut service = Self {
            port,
            name: String::new(),
        };
        // SAFETY: uhr holds the receive right it makes the send right from.
        let code = unsafe { mach_port_insert_right(task, port, port, MACH_MSG_TYPE_MAKE_SEND) };
        check("mach_port_insert_right", code).map_err(Error::Service)?;
        // The bootstrap server keeps a send right of its own, so uhr's goes.
        let send = Port::new(port);
        loop {
            let name = format!("uhr.{}.{:016x}", std::process::id(), random());
            let c_name = CString::new(name.clone()).expect("no NUL in the name");
            // SAFETY: the name is NUL-terminated, and the right is uhr's.
            let code = unsafe { bootstrap_register2(bootstrap_port, c_name.as_ptr(), port, 0) };
            if code == BOOTSTRAP_NAME_IN_USE {
                continue;
            }
            check("bootstrap_register2", code).map_err(Error::Service)?;
            drop(send);
            service.name = name;
            return Ok(service);
        }
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// The next hello that came, if one did, waiting at most `timeout_ms`.
    /// A message that is not a hello is thrown away.
    pub(crate) fn receive(&self, timeout_ms: u32) -> Result<Option<Hello>, Failed> {
        loop {
            let mut received = MaybeUninit::<Received>::zeroed();
            let header = received.as_mut_ptr().cast::<mach_msg_header_t>();
            // SAFETY: the buffer has room for `size_of::<Received>()` bytes.
            let code = unsafe {
                mach_msg(
                    header,
                    MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                    0,
                    mem::size_of::<Received>() as u32,
                    self.port,
                    timeout_ms,
                    MACH_PORT_NULL,
                )
            };
            match code {
                MACH_RCV_TIMED_OUT => return Ok(None),
                // Without MACH_RCV_LARGE the kernel throws it away.
                MACH_RCV_TOO_LARGE => continue,
                code => check("mach_msg", code)?,
            }
            // SAFETY: the kernel wrote a message into it.
            let received = unsafe { received.assume_init() };
            if let Some(hello) = Hello::from(received) {
                return Ok(Some(hello));
            }
        }
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        // SAFETY: uhr holds the receive right, and nothing uses it after.
        unsafe {
            mach2::mach_port::mach_port_mod_refs(
                mach_task_self(),
                self.port,
                MACH_PORT_RIGHT_RECEIVE,
                -1,
            )
        };
    }
}

/// The message preload.c sends.
#[repr(C)]
#[derive(Clone, Copy)]
struct Message {
    header: mach_msg_header_t,
    body: mach_msg_body_t,
    task: mach_msg_port_descriptor_t,
}

/// A message as received: room for the trailer the kernel adds.
#[repr(C)]
#[derive(Clone, Copy)]
struct Received {
    message: Message,
    trailer: [u8; 128],
}

/// A process that sent uhr its task port, and waits for an answer.
#[derive(Debug)]
pub(crate) struct Hello {
    pub task: Task,
    /// From the kernel, not from the message.
    pub pid: u32,
    pub waiting: Waiting,
}

impl Hello {
    fn from(mut received: Received) -> Option<Self> {
        let message = &mut received.message;
        let header = message.header;
        let remote = header.msgh_bits & MACH_MSGH_BITS_REMOTE_MASK;
        let task = message.task;
        let hello = header.msgh_id == HELLO
            && header.msgh_bits & MACH_MSGH_BITS_COMPLEX != 0
            && header.msgh_size as usize == mem::size_of::<Message>()
            && remote == MACH_MSG_TYPE_PORT_SEND_ONCE
            && header.msgh_remote_port != MACH_PORT_NULL
            && message.body.msgh_descriptor_count == 1
            && u32::from(task.type_) == MACH_MSG_PORT_DESCRIPTOR
            && u32::from(task.disposition) == MACH_MSG_TYPE_PORT_SEND;
        if !hello {
            // SAFETY: a message the kernel wrote, whose rights are uhr's.
            unsafe { mach_msg_destroy(&mut message.header) };
            return None;
        }
        let waiting = Waiting(header.msgh_remote_port);
        let task = Task::from_port(Port::new(task.name));
        let pid = task.pid().ok()?;
        Some(Self { task, pid, waiting })
    }
}

/// A send-once right to the port a process waits on for uhr's answer.
/// Dropped unanswered, it lets the process go on too: the kernel tells it
/// that no answer can come.
#[derive(Debug)]
pub(crate) struct Waiting(mach_port_t);

impl Waiting {
    /// Lets the process go on.
    pub(crate) fn answer(self) {
        let mut header = mach_msg_header_t {
            msgh_bits: MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0),
            msgh_size: mem::size_of::<mach_msg_header_t>() as u32,
            msgh_remote_port: self.0,
            msgh_local_port: MACH_PORT_NULL,
            msgh_voucher_port: MACH_PORT_NULL,
            msgh_id: HELLO,
        };
        // SAFETY: the header is valid, and the right is uhr's to move.
        let code = unsafe {
            mach_msg(
                &mut header,
                MACH_SEND_MSG | MACH_SEND_TIMEOUT,
                header.msgh_size,
                0,
                MACH_PORT_NULL,
                0,
                MACH_PORT_NULL,
            )
        };
        // Sent, the right is gone. A send that failed hands it back, and
        // dropping it lets the process go on just the same.
        if code == 0 {
            mem::forget(self);
        }
    }
}

impl Drop for Waiting {
    fn drop(&mut self) {
        // SAFETY: the right is uhr's, and nothing uses it after.
        unsafe { mach_port_deallocate(mach_task_self(), self.0) };
    }
}

fn random() -> u64 {
    let mut bytes = [0u8; 8];
    // SAFETY: `bytes` is valid to write, and getentropy writes at most 256.
    unsafe { libc::getentropy(bytes.as_mut_ptr().cast(), bytes.len()) };
    u64::from_ne_bytes(bytes)
}

/// The variables a launched target needs: uhr's library first among those
/// dyld inserts, and the service it sends its task port to.
pub(crate) fn environment(service: &Service) -> Result<Vec<(OsString, OsString)>, Error> {
    let library = library()?;
    let mut insert = library.into_os_string();
    if let Some(existing) = env::var_os(INSERT).filter(|v| !v.is_empty()) {
        insert.push(":");
        insert.push(existing);
    }
    Ok(vec![
        (INSERT.into(), insert),
        (SERVICE.into(), service.name().into()),
    ])
}

/// uhr's library, written where dyld can load it. Never removed: every
/// process the target starts inherits the variable that names it, also
/// those left running after uhr ends, and dyld ends a process whose
/// inserted library is missing.
fn library() -> Result<PathBuf, Error> {
    let mut hasher = DefaultHasher::new();
    LIBRARY.hash(&mut hasher);
    let path = env::temp_dir().join(format!("uhr-preload-{:016x}.dylib", hasher.finish()));
    let error = |source| Error::Library {
        path: path.clone(),
        source,
    };
    // The variable separates libraries with colons.
    if path.as_os_str().as_encoded_bytes().contains(&b':') {
        return Err(error(io::Error::other(
            "the path has a colon, which DYLD_INSERT_LIBRARIES cannot hold",
        )));
    }
    if fs::read(&path).is_ok_and(|bytes| bytes == LIBRARY) {
        return Ok(path);
    }
    // Renamed into place, so no process ever loads half of it.
    let partial = path.with_extension(format!("{:016x}.partial", random()));
    fs::write(&partial, LIBRARY).map_err(error)?;
    fs::rename(&partial, &path).map_err(error)?;
    Ok(path)
}

/// `SF_RESTRICTED` from <sys/stat.h>: the flag on the files System
/// Integrity Protection protects.
const SF_RESTRICTED: u32 = 0x0008_0000;

/// Whether System Integrity Protection protects the file, as it does the
/// system's own, which only an update of the system changes.
pub(crate) fn protected(metadata: &fs::Metadata) -> bool {
    metadata.st_flags() & SF_RESTRICTED != 0
}

/// Checks that dyld would load uhr's library into `program`, found through
/// `PATH` as the shell finds it, and returns where it is.
pub(crate) fn check_program(program: &str) -> Result<PathBuf, Error> {
    let path = resolve(program).ok_or_else(|| Error::CommandNotFound(program.to_owned()))?;
    check_file(&path, None)?;
    Ok(path)
}

fn resolve(program: &str) -> Option<PathBuf> {
    let executable = |path: &Path| {
        path.metadata()
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    };
    if program.contains('/') {
        let path = PathBuf::from(program);
        return executable(&path).then_some(path);
    }
    env::split_paths(&env::var_os("PATH")?)
        .map(|dir| dir.join(program))
        .find(|path| executable(path))
}

/// `script` is the script `path` is the interpreter of, if it is one.
fn check_file(path: &Path, script: Option<&Path>) -> Result<(), Error> {
    let blocked = |detail: String, fix: Option<String>| Err(Error::Blocked { detail, fix });
    let shown = path.display();
    let ran = match script {
        Some(script) => format!("{}, which runs {}", shown, script.display()),
        None => shown.to_string(),
    };
    let metadata = fs::metadata(path).map_err(|_| Error::CommandNotFound(shown.to_string()))?;
    if protected(&metadata) {
        let fix = match script {
            Some(script) => interpreter_fix(path, script),
            None => "Record a build of it outside the system's folders, as Homebrew installs, \
                     or a program of your own."
                .to_owned(),
        };
        return blocked(
            format!(
                "System Integrity Protection protects {ran}, so dyld removes the variables that \
                 have it load uhr's library from its environment, and from all it runs"
            ),
            Some(fix),
        );
    }
    if metadata.permissions().mode() & (libc::S_ISUID | libc::S_ISGID) as u32 != 0 {
        return blocked(
            format!(
                "{ran} is set-user-ID or set-group-ID, so dyld ignores the variables that have it load uhr's library"
            ),
            Some("Record a copy of it without the bit.".to_owned()),
        );
    }
    let bytes = fs::read(path).map_err(|_| Error::CommandNotFound(shown.to_string()))?;
    if let Some(line) = bytes.strip_prefix(b"#!") {
        if script.is_some() {
            return Ok(());
        }
        let line = line.split(|&b| b == b'\n').next().unwrap_or_default();
        let line = String::from_utf8_lossy(line);
        let Some(interpreter) = line.split_whitespace().next() else {
            return Ok(());
        };
        return check_file(Path::new(interpreter), Some(path));
    }
    match FileKind::parse(&bytes[..]) {
        Ok(FileKind::MachO64 | FileKind::MachOFat32 | FileKind::MachOFat64 | FileKind::MachO32) => {
        }
        // exec says what is wrong with it.
        _ => return Ok(()),
    }
    let Some(signing) = macho::signing(&bytes) else {
        return blocked(
            format!(
                "{ran} has no code for {}, and uhr records only programs that run natively",
                env::consts::ARCH
            ),
            Some(format!("Build it for {}.", env::consts::ARCH)),
        );
    };
    if signing.restricted {
        return blocked(
            format!(
                "{ran} is marked restricted, so dyld ignores the variables that have it load uhr's library"
            ),
            Some("Record a build without the __RESTRICT segment or the restrict flag.".to_owned()),
        );
    }
    if !signing.takes_inserted_libraries() {
        let missing = match (signing.allows_dyld_variables, signing.loads_any_library) {
            (false, false) => {
                "com.apple.security.cs.allow-dyld-environment-variables and \
                               com.apple.security.cs.disable-library-validation entitlements"
            }
            (true, _) => "com.apple.security.cs.disable-library-validation entitlement",
            (_, true) => "com.apple.security.cs.allow-dyld-environment-variables entitlement",
        };
        return blocked(
            format!(
                "{ran} is signed for the hardened runtime without the {missing}, so dyld \
                 ignores the variables that have it load uhr's library"
            ),
            Some(format!(
                "Sign it again without the hardened runtime: `codesign -s - -f {}`.",
                quoted(path)
            )),
        );
    }
    Ok(())
}

/// A path as a shell takes it in a command to copy.
fn quoted(path: &Path) -> String {
    let text = path.display().to_string();
    let plain = text
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"/._-+".contains(&b));
    match plain {
        true => text,
        false => format!("'{}'", text.replace('\'', "'\\''")),
    }
}

/// How to run a script whose interpreter the system protects: with one the
/// variables reach, as the one `env` would find through `PATH`.
fn interpreter_fix(interpreter: &Path, script: &Path) -> String {
    let named = fs::read(script).ok().and_then(|bytes| {
        let line = bytes.strip_prefix(b"#!")?.split(|&b| b == b'\n').next()?;
        let line = String::from_utf8_lossy(line).into_owned();
        let mut words = line.split_whitespace().skip(1);
        let name = words.find(|w| !w.starts_with('-'))?;
        (interpreter.file_name()? == "env").then(|| name.to_owned())
    });
    let found = named
        .as_deref()
        .and_then(resolve)
        .filter(|path| check_file(path, None).is_ok());
    match found {
        Some(path) => format!(
            "Run the script with that interpreter: `uhr record -- {} {}`.",
            quoted(&path),
            quoted(script)
        ),
        None => "Run the script with an interpreter outside the system's folders, as Homebrew \
                 installs."
            .to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::*;

    #[test]
    fn quotes_paths_a_shell_would_split() {
        assert_eq!(
            quoted(Path::new("/opt/homebrew/bin/python3")),
            "/opt/homebrew/bin/python3"
        );
        assert_eq!(
            quoted(Path::new("/Applications/A b.app")),
            "'/Applications/A b.app'"
        );
        assert_eq!(quoted(Path::new("/tmp/it's")), "'/tmp/it'\\''s'");
    }

    #[test]
    fn blocks_the_programs_the_system_protects() {
        let error = check_program("/bin/sh").unwrap_err();
        assert!(matches!(error, Error::Blocked { .. }), "{error}");
        assert!(error.to_string().contains("System Integrity Protection"));
    }

    #[test]
    fn blocks_scripts_the_system_runs_and_finds_an_interpreter() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("run");
        fs::write(&script, "#!/usr/bin/env sh\necho hi\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let error = check_program(script.to_str().unwrap())
            .unwrap_err()
            .to_string();
        assert!(error.contains("which runs"), "{error}");
    }

    #[test]
    fn a_program_of_ones_own_gets_the_library() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("hello.c");
        fs::write(&source, "int main(void) { return 7; }\n").unwrap();
        let program = dir.path().join("hello");
        let built = Command::new("cc")
            .arg("-o")
            .arg(&program)
            .arg(&source)
            .status()
            .unwrap();
        assert!(built.success());
        check_program(program.to_str().unwrap()).unwrap();

        let service = Service::register().unwrap();
        let mut child = Command::new(&program)
            .envs(environment(&service).unwrap())
            .spawn()
            .unwrap();
        let hello = loop {
            if let Some(hello) = service.receive(10).unwrap() {
                break hello;
            }
            assert!(
                child.try_wait().unwrap().is_none(),
                "exited without a hello"
            );
        };
        assert_eq!(hello.pid, child.id());
        assert!(!hello.task.threads().unwrap().is_empty());
        // Held until answered.
        assert!(child.try_wait().unwrap().is_none());
        hello.waiting.answer();
        assert_eq!(child.wait().unwrap().code(), Some(7));
    }

    #[test]
    fn a_hello_dropped_unanswered_lets_the_process_go_on() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("hello.c");
        fs::write(&source, "int main(void) { return 3; }\n").unwrap();
        let program = dir.path().join("hello");
        let built = Command::new("cc")
            .arg("-o")
            .arg(&program)
            .arg(&source)
            .status()
            .unwrap();
        assert!(built.success());
        let service = Service::register().unwrap();
        let mut child = Command::new(&program)
            .envs(environment(&service).unwrap())
            .spawn()
            .unwrap();
        let hello = loop {
            if let Some(hello) = service.receive(10).unwrap() {
                break hello;
            }
        };
        drop(hello);
        assert_eq!(child.wait().unwrap().code(), Some(3));
    }
}
