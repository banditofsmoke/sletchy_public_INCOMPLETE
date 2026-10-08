//! Every process in Sletchy's own tree, read-only: the window, its WebView2 renderers,
//! and the Kernel inside its Job Object.
//!
//! The brief, in my words: "Every thread, process, kernel needs to be visible for the user to see, and
//! to be their own NOC and SOC." This is the part of that the shell can honestly
//! show: the processes Sletchy itself started, found by walking down the process
//! tree from the window. Windows' process table is read (as Task Manager reads it),
//! but only Sletchy's descendants are reported - nothing about the rest of the
//! machine leaves this function. Seeing the rest of the machine is the SOC's job
//! (Wave 4), not the window's.

use std::collections::{HashMap, HashSet, VecDeque};

use serde_json::{json, Value};

#[cfg(windows)]
use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, INVALID_HANDLE_VALUE};
#[cfg(windows)]
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
#[cfg(windows)]
use windows_sys::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

/// One row of Windows' process table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub pid: u32,
    pub ppid: u32,
    pub threads: u32,
    pub name: String,
}

/// The pids in `root`'s tree, root first, breadth-first. Guards against pid reuse
/// making a cycle (a parent pid that now names a child).
pub fn descendants(table: &[Entry], root: u32) -> Vec<u32> {
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    for e in table {
        if e.pid != e.ppid {
            children.entry(e.ppid).or_default().push(e.pid);
        }
    }
    let mut seen = HashSet::from([root]);
    let mut order = vec![root];
    let mut queue = VecDeque::from([root]);
    while let Some(pid) = queue.pop_front() {
        for &child in children.get(&pid).map(Vec::as_slice).unwrap_or(&[]) {
            if seen.insert(child) {
                order.push(child);
                queue.push_back(child);
            }
        }
    }
    order
}

/// What each process is, in the window's terms.
pub fn role(pid: u32, root: u32, name: &str, in_job: bool) -> &'static str {
    if pid == root {
        "window"
    } else if in_job {
        "kernel"
    } else if name.eq_ignore_ascii_case("msedgewebview2.exe") {
        "webview"
    } else {
        "other"
    }
}

#[cfg(windows)]
fn table() -> Vec<Entry> {
    let mut out = Vec::new();
    // SAFETY: a process snapshot, closed below.
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap == INVALID_HANDLE_VALUE {
        return out;
    }
    // SAFETY: zeroed with dwSize set is the documented initial state.
    let mut e: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    // SAFETY: `snap` is live, `e` initialised.
    let mut more = unsafe { Process32FirstW(snap, &mut e) } != 0;
    while more {
        let len = e.szExeFile.iter().position(|&c| c == 0).unwrap_or(e.szExeFile.len());
        out.push(Entry {
            pid: e.th32ProcessID,
            ppid: e.th32ParentProcessID,
            threads: e.cntThreads,
            name: String::from_utf16_lossy(&e.szExeFile[..len]),
        });
        // SAFETY: as above.
        more = unsafe { Process32NextW(snap, &mut e) } != 0;
    }
    // SAFETY: we own the snapshot.
    unsafe { CloseHandle(snap) };
    out
}

#[cfg(windows)]
fn ms(t: FILETIME) -> u64 {
    ((u64::from(t.dwHighDateTime) << 32) | u64::from(t.dwLowDateTime)) / 10_000
}

/// Memory, CPU time and job membership for one pid. Zeros if it cannot be opened
/// (it exited between the snapshot and now, which is ordinary).
#[cfg(windows)]
fn measure(pid: u32, job: Option<&crate::job::Job>) -> (u64, u64, u64, bool) {
    // SAFETY: the least access that can read times and memory; checked for null.
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        return (0, 0, 0, false);
    }
    let zero = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
    // SAFETY: `h` is live; the four out-pointers are valid.
    let cpu = if unsafe { GetProcessTimes(h, &mut created, &mut exited, &mut kernel, &mut user) } != 0 {
        ms(kernel) + ms(user)
    } else {
        0
    };
    // SAFETY: a correctly sized PROCESS_MEMORY_COUNTERS.
    let mut mem: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
    mem.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
    let (working, private) = if unsafe { K32GetProcessMemoryInfo(h, &mut mem, mem.cb) } != 0 {
        (mem.WorkingSetSize as u64, mem.PagefileUsage as u64)
    } else {
        (0, 0)
    };
    let in_job = job.and_then(|j| j.contains(h).ok()).unwrap_or(false);
    // SAFETY: we own `h`.
    unsafe { CloseHandle(h) };
    (cpu, working, private, in_job)
}

/// Sletchy's whole process tree, as JSON rows for the window.
#[cfg(windows)]
pub fn snapshot(job: Option<&crate::job::Job>) -> Value {
    let root = std::process::id();
    let table = table();
    let by_pid: HashMap<u32, &Entry> = table.iter().map(|e| (e.pid, e)).collect();
    let rows: Vec<Value> = descendants(&table, root)
        .into_iter()
        .filter_map(|pid| by_pid.get(&pid).map(|e| (pid, *e)))
        .map(|(pid, e)| {
            let (cpu_ms, working, private, in_job) = measure(pid, job);
            json!({
                "pid": pid,
                "ppid": e.ppid,
                "name": e.name,
                "threads": e.threads,
                "cpu_ms": cpu_ms,
                "memory_bytes": working,
                "private_bytes": private,
                "in_job": in_job,
                "role": role(pid, root, &e.name, in_job),
            })
        })
        .collect();
    Value::Array(rows)
}

#[cfg(not(windows))]
pub fn snapshot(_job: Option<&()>) -> Value {
    Value::Array(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(pid: u32, ppid: u32) -> Entry {
        Entry { pid, ppid, threads: 1, name: format!("p{pid}.exe") }
    }

    #[test]
    fn descendants_walks_the_tree_and_nothing_else() {
        let table = vec![e(1, 0), e(10, 1), e(11, 1), e(20, 10), e(99, 50), e(100, 99)];
        assert_eq!(descendants(&table, 1), vec![1, 10, 11, 20]);
        assert!(!descendants(&table, 1).contains(&99), "an unrelated process leaked in");
    }

    #[test]
    fn a_pid_reuse_cycle_does_not_loop() {
        let table = vec![e(1, 2), e(2, 1)];
        assert_eq!(descendants(&table, 1), vec![1, 2]);
    }

    #[test]
    fn roles() {
        assert_eq!(role(7, 7, "sletchy-desktop.exe", false), "window");
        assert_eq!(role(8, 7, "python.exe", true), "kernel");
        assert_eq!(role(9, 7, "msedgewebview2.exe", false), "webview");
        assert_eq!(role(10, 7, "conhost.exe", false), "other");
    }

    #[cfg(windows)]
    #[test]
    fn the_test_process_finds_itself_and_its_confined_child() {
        use std::os::windows::io::AsRawHandle;
        let (mut child, job) = crate::job::spawn_confined(
            std::process::Command::new("cmd").args(["/c", "ping", "-n", "5", "127.0.0.1"]),
            crate::job::Limits::LAW_ZERO,
        )
        .unwrap();
        let rows = snapshot(Some(&job));
        let rows = rows.as_array().unwrap();
        let me = std::process::id();
        assert_eq!(rows[0]["pid"], me, "the root is this process");
        let kid = rows.iter().find(|r| r["pid"] == child.id()).expect("the child is listed");
        assert_eq!(kid["in_job"], true);
        assert_eq!(kid["role"], "kernel");
        assert!(job.contains(child.as_raw_handle() as _).unwrap());
        let _ = child.kill();
        let _ = child.wait();
    }
}
