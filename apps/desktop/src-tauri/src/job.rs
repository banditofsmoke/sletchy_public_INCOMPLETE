//! A Job Object that holds the Kernel before it runs a single instruction.
//!
//! LAW 0 section 5: every process Sletchy starts is created inside a Job Object with
//! its ceilings *already applied* - never started and limited afterwards, which is a
//! race. `std::process::Command` cannot create a process directly inside a job, so:
//!
//! 1. the job is created and its limits set, before the process exists
//! 2. the process is created **suspended** (`CREATE_SUSPENDED`), so it has run nothing
//! 3. it is assigned to the job
//! 4. only then is its thread resumed
//!
//! If step 3 or 4 fails the process is killed, still suspended. It never runs
//! unconfined. Closing the job handle kills everything in it (`KILL_ON_JOB_CLOSE`),
//! so the Kernel and anything it starts die with the window.

use std::io;
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::process::{Child, Command};

use windows_sys::Win32::Foundation::{CloseHandle, BOOL, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob, JobObjectBasicAccountingInformation,
    JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
    JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Threading::{
    OpenThread, ResumeThread, CREATE_NO_WINDOW, CREATE_SUSPENDED, THREAD_SUSPEND_RESUME,
};

/// The ceilings a job carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub memory_bytes: usize,
    pub active_processes: u32,
}

impl Limits {
    /// LAW 0 section 5's table: 2 GB per job. Eight processes is room for the uv
    /// launcher, Python, and the helpers Stop everything starts (PowerShell, icacls).
    pub const LAW_ZERO: Limits = Limits {
        memory_bytes: 2 * 1024 * 1024 * 1024,
        active_processes: 8,
    };
}

/// An owned Job Object handle. Dropping it kills every process in the job.
pub struct Job {
    handle: HANDLE,
    pub limits: Limits,
}

// SAFETY: a job handle is a kernel object reference, valid from any thread. The shell
// only ever touches it from behind the bridge's mutex.
unsafe impl Send for Job {}

impl Job {
    /// Create a job with `limits` applied. The job exists, limited, before anything joins it.
    pub fn new(limits: Limits) -> io::Result<Job> {
        // SAFETY: null attributes and name are documented as valid.
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        let job = Job { handle, limits };

        // SAFETY: an all-zero JOBOBJECT_EXTENDED_LIMIT_INFORMATION is a valid "no limits".
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_JOB_MEMORY
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        info.BasicLimitInformation.ActiveProcessLimit = limits.active_processes;
        info.JobMemoryLimit = limits.memory_bytes;

        // SAFETY: `info` is a correctly sized, initialised struct for this info class.
        let ok = unsafe {
            SetInformationJobObject(
                job.handle,
                JobObjectExtendedLimitInformation,
                &info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION as *const core::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error()); // `job` drops and closes the handle
        }
        Ok(job)
    }

    pub fn assign(&self, process: HANDLE) -> io::Result<()> {
        // SAFETY: both handles are live for the duration of the call.
        if unsafe { AssignProcessToJobObject(self.handle, process) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Whether `process` is in this job: the positive control for `spawn_confined`, and
    /// how the window tells a Kernel process from its own.
    pub fn contains(&self, process: HANDLE) -> io::Result<bool> {
        let mut result: BOOL = 0;
        // SAFETY: both handles are live; `result` is a valid out-pointer.
        if unsafe { IsProcessInJob(process, self.handle, &mut result) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(result != 0)
    }
}

/// What the kernel has counted for everything that ever ran in a job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JobStats {
    pub active_processes: u32,
    pub total_processes: u32,
    pub cpu_ms: u64,
    pub peak_memory_bytes: u64,
}

impl Job {
    /// Read-only accounting the kernel keeps for the job: CPU time, process counts,
    /// and the peak memory the whole job used, against its ceiling.
    pub fn stats(&self) -> io::Result<JobStats> {
        // SAFETY: zeroed structs of the exact size each info class expects.
        let mut acct: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
        let mut ext: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: live handle, valid out-pointers, correct sizes.
        let ok = unsafe {
            QueryInformationJobObject(
                self.handle,
                JobObjectBasicAccountingInformation,
                &mut acct as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION as *mut core::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                std::ptr::null_mut(),
            ) != 0
                && QueryInformationJobObject(
                    self.handle,
                    JobObjectExtendedLimitInformation,
                    &mut ext as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION as *mut core::ffi::c_void,
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                    std::ptr::null_mut(),
                ) != 0
        };
        if !ok {
            return Err(io::Error::last_os_error());
        }
        let cpu_100ns = (acct.TotalUserTime + acct.TotalKernelTime).max(0) as u64;
        Ok(JobStats {
            active_processes: acct.ActiveProcesses,
            total_processes: acct.TotalProcesses,
            cpu_ms: cpu_100ns / 10_000,
            peak_memory_bytes: ext.PeakJobMemoryUsed as u64,
        })
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        // SAFETY: we own this handle and close it exactly once. With KILL_ON_JOB_CLOSE
        // this terminates every process still in the job.
        unsafe { CloseHandle(self.handle) };
    }
}

/// Resume every thread of `pid`. A process created suspended has exactly one.
fn resume_threads(pid: u32) -> io::Result<usize> {
    // SAFETY: a thread snapshot of the whole system; closed below.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: zeroed THREADENTRY32 with dwSize set is the documented initial state.
    let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

    let mut resumed = 0;
    // SAFETY: `snapshot` is live and `entry` is initialised as required.
    let mut more = unsafe { Thread32First(snapshot, &mut entry) } != 0;
    while more {
        if entry.th32OwnerProcessID == pid {
            // SAFETY: opening a thread id we just enumerated; checked for null.
            let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
            if !thread.is_null() {
                // SAFETY: `thread` is live; ResumeThread returns u32::MAX on failure.
                if unsafe { ResumeThread(thread) } != u32::MAX {
                    resumed += 1;
                }
                unsafe { CloseHandle(thread) };
            }
        }
        // SAFETY: as for Thread32First.
        more = unsafe { Thread32Next(snapshot, &mut entry) } != 0;
    }
    // SAFETY: we own the snapshot handle.
    unsafe { CloseHandle(snapshot) };
    Ok(resumed)
}

fn kill(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Start `cmd` inside a new job with `limits`, or not at all.
pub fn spawn_confined(cmd: &mut Command, limits: Limits) -> io::Result<(Child, Job)> {
    let job = Job::new(limits)?;
    cmd.creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW);
    let mut child = cmd.spawn()?;

    if let Err(err) = job.assign(child.as_raw_handle() as HANDLE) {
        kill(&mut child);
        return Err(err);
    }
    match resume_threads(child.id()) {
        Ok(n) if n > 0 => Ok((child, job)),
        Ok(_) => {
            kill(&mut child);
            Err(io::Error::other("the new process had no thread to resume"))
        }
        Err(err) => {
            kill(&mut child);
            Err(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn cmd(args: &[&str]) -> Command {
        let mut c = Command::new("cmd");
        c.args(["/c"]).args(args);
        c
    }

    #[test]
    fn a_confined_process_runs_and_is_in_its_job() {
        let (mut child, job) = spawn_confined(&mut cmd(&["exit", "7"]), Limits::LAW_ZERO).unwrap();
        assert!(job.contains(child.as_raw_handle() as HANDLE).unwrap());
        // Positive control (L001): it was resumed and actually ran - exit 7, not a hang.
        assert_eq!(child.wait().unwrap().code(), Some(7));
    }

    #[test]
    fn an_unconfined_process_is_not_in_the_job() {
        // Positive control for `contains`: it can say no.
        let job = Job::new(Limits::LAW_ZERO).unwrap();
        let mut child = cmd(&["exit", "0"]).spawn().unwrap();
        assert!(!job.contains(child.as_raw_handle() as HANDLE).unwrap());
        child.wait().unwrap();
    }

    #[test]
    fn closing_the_job_kills_what_is_inside_it() {
        // Loopback only; a sleep that needs no console (L003: no dialogs).
        let (mut child, job) = spawn_confined(
            &mut cmd(&["ping", "-n", "30", "127.0.0.1"]),
            Limits::LAW_ZERO,
        )
        .unwrap();
        assert!(child.try_wait().unwrap().is_none(), "it should still be running");
        drop(job);
        let deadline = Instant::now() + Duration::from_secs(10);
        while child.try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline, "the job closed and the process lived on");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    #[test]
    fn the_job_counts_what_ran_in_it() {
        let (mut child, job) = spawn_confined(&mut cmd(&["exit", "0"]), Limits::LAW_ZERO).unwrap();
        child.wait().unwrap();
        let stats = job.stats().unwrap();
        // Measured on 10.0.19045: 2, not 1. Windows gives every console program a
        // conhost.exe, and it lands in the same job, against the same process limit.
        assert!(stats.total_processes >= 1, "nothing was counted");
        assert!(stats.peak_memory_bytes > 0);
        // The conhost can outlive its program by a moment; the job empties shortly after.
        let deadline = Instant::now() + Duration::from_secs(5);
        while job.stats().unwrap().active_processes > 0 {
            assert!(Instant::now() < deadline, "something stayed alive in the job");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    #[test]
    fn the_law_zero_limits_are_the_documented_ones() {
        assert_eq!(Limits::LAW_ZERO.memory_bytes, 2 * 1024 * 1024 * 1024);
        assert_eq!(Limits::LAW_ZERO.active_processes, 8);
    }
}
