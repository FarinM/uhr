use std::fs;
use std::io;
use std::path::Path;
use std::time::SystemTime;

/// Removes the logs V8 writes beside a perf map, `isolate-0x<isolate>-<pid>-v8.log`,
/// that the process `pid` wrote in `dir` since `since`, and returns how many.
/// Node takes no option in its environment to move or stop them.
pub(crate) fn remove_v8_logs(dir: &Path, pid: u32, since: SystemTime) -> io::Result<usize> {
    let suffix = format!("-{pid}-v8.log");
    let mut removed = 0;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(isolate) = name
            .to_str()
            .and_then(|n| n.strip_prefix("isolate-0x")?.strip_suffix(suffix.as_str()))
        else {
            continue;
        };
        let written = entry.metadata()?.modified()?;
        if isolate.bytes().all(|b| b.is_ascii_hexdigit()) && written >= since {
            fs::remove_file(entry.path())?;
            removed += 1;
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_only_the_v8_logs_of_the_process() {
        let dir = tempfile::tempdir().unwrap();
        let since = SystemTime::now() - std::time::Duration::from_secs(1);
        for name in [
            "isolate-0x2e2d5000-41-v8.log",
            "isolate-0x3ae9a000-41-v8.log",
            "isolate-0x3ae9a000-410-v8.log",
            "isolate-0xzz-41-v8.log",
            "notes-41-v8.log",
        ] {
            fs::write(dir.path().join(name), "").unwrap();
        }
        assert_eq!(remove_v8_logs(dir.path(), 41, since).unwrap(), 2);
        let mut left: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(
            left,
            [
                "isolate-0x3ae9a000-410-v8.log",
                "isolate-0xzz-41-v8.log",
                "notes-41-v8.log"
            ]
        );
    }
}
