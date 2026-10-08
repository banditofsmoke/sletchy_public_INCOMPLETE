//! The window's one connection to Sletchy: `sletchy bridge`, over its pipes.
//!
//! Nothing listens. The shell starts the Kernel as its own child (inside a Job Object
//! on Windows, see `job.rs`), writes one JSON request per line to its stdin, and reads
//! one JSON response per line from its stdout (ADR-0008).
//!
//! This side is deliberately thin: it refuses a method the generated allowlist does
//! not name before anything crosses the pipe, times out rather than hanging, and
//! restarts the Kernel on the next call if it died. Everything else - validation,
//! the two proofs a dangerous switch needs, the ledger - is the Kernel's job, and is
//! not duplicated here.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::methods::{METHODS, PROTOCOL_VERSION};

/// How many stderr lines to keep for the Raw view and for error messages.
const STDERR_KEEP: usize = 200;

/// Where the Kernel lives and how to start it.
#[derive(Clone, Debug)]
pub struct Launch {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub cwd: PathBuf,
}

impl Launch {
    /// The repository's own virtualenv, with the repository as working directory, so
    /// the window and the CLI share one `var/`. A release must bundle the Kernel
    /// instead; that is not built yet (ADR-0008, "Costs").
    pub fn from_repo() -> Launch {
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("..").join("..");
        let repo = repo.canonicalize().unwrap_or(repo);
        let venv = repo.join(".venv");
        let program = if cfg!(windows) {
            venv.join("Scripts").join("sletchy.exe")
        } else {
            venv.join("bin").join("sletchy")
        };
        Launch { program, args: vec!["bridge".into()], cwd: repo }
    }
}

/// A refusal shaped like the Kernel's own, so the window handles both one way.
pub fn refusal(code: &str, message: impl Into<String>) -> Value {
    json!({ "ok": false, "error": { "code": code, "message": message.into() } })
}

/// Stop everything may remove firewall rules and revert sandbox changes, which takes time.
pub fn timeout_for(method: &str) -> Duration {
    match method {
        m if m.starts_with("stop.") => Duration::from_secs(180),
        "init" => Duration::from_secs(60),
        _ => Duration::from_secs(30),
    }
}

pub fn request_line(id: u64, method: &str, params: &Value) -> String {
    let mut line = json!({ "id": id, "method": method, "params": params }).to_string();
    line.push('\n');
    line
}

/// The response to request `id`, if `line` is it. Anything else - a stale answer to a
/// request that timed out, or noise - is not.
pub fn reply_for(line: &str, id: u64) -> Option<Value> {
    let value: Value = serde_json::from_str(line).ok()?;
    (value.get("id").and_then(Value::as_u64) == Some(id)).then_some(value)
}

struct LimitsView {
    memory_bytes: usize,
    active_processes: u32,
}

struct Running {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
    #[cfg(windows)]
    job: crate::job::Job,
}

enum Outcome {
    Reply(Value),
    Timeout,
    Gone,
    WriteFailed(String),
}

pub struct Bridge {
    launch: Launch,
    running: Option<Running>,
    next_id: u64,
    stderr: Arc<Mutex<VecDeque<String>>>,
    last_error: Option<String>,
    starts: u32,
}

impl Bridge {
    pub fn new(launch: Launch) -> Bridge {
        Bridge {
            launch,
            running: None,
            next_id: 1,
            stderr: Arc::new(Mutex::new(VecDeque::new())),
            last_error: None,
            starts: 0,
        }
    }

    fn start(&mut self) -> Result<(), String> {
        if !self.launch.program.exists() {
            return Err(format!(
                "the Sletchy kernel was not found at {}. Run `uv sync` in the repository.",
                self.launch.program.display()
            ));
        }
        let mut cmd = Command::new(&self.launch.program);
        cmd.args(&self.launch.args)
            .current_dir(&self.launch.cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        #[cfg(windows)]
        let (mut child, job) = crate::job::spawn_confined(&mut cmd, crate::job::Limits::LAW_ZERO)
            .map_err(|e| format!("could not start the kernel inside its job: {e}"))?;
        #[cfg(not(windows))]
        let mut child = cmd.spawn().map_err(|e| format!("could not start the kernel: {e}"))?;

        let stdin = child.stdin.take().ok_or("no stdin")?;
        let stdout = child.stdout.take().ok_or("no stdout")?;
        let stderr = child.stderr.take().ok_or("no stderr")?;

        let (tx, lines) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let ring = Arc::clone(&self.stderr);
        thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if let Ok(mut ring) = ring.lock() {
                    if ring.len() == STDERR_KEEP {
                        ring.pop_front();
                    }
                    ring.push_back(line);
                }
            }
        });

        self.running = Some(Running {
            child,
            stdin,
            lines,
            #[cfg(windows)]
            job,
        });
        self.starts += 1;
        Ok(())
    }

    fn exchange(&mut self, method: &str, params: &Value) -> Outcome {
        let id = self.next_id;
        self.next_id += 1;
        let Some(running) = self.running.as_mut() else {
            return Outcome::Gone;
        };
        let line = request_line(id, method, params);
        if let Err(err) = running.stdin.write_all(line.as_bytes()).and_then(|()| running.stdin.flush()) {
            return Outcome::WriteFailed(err.to_string());
        }
        let deadline = Instant::now() + timeout_for(method);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match running.lines.recv_timeout(remaining) {
                Ok(line) => {
                    if let Some(reply) = reply_for(&line, id) {
                        return Outcome::Reply(reply);
                    }
                }
                Err(RecvTimeoutError::Timeout) => return Outcome::Timeout,
                Err(RecvTimeoutError::Disconnected) => return Outcome::Gone,
            }
        }
    }

    fn settle(&mut self, method: &str, outcome: Outcome) -> Value {
        match &outcome {
            Outcome::Reply(reply) => reply.clone(),
            Outcome::Timeout => {
                self.stop();
                refusal(
                    "bridge_timeout",
                    format!("the kernel did not answer {method} within {:?}; it was stopped and will restart", timeout_for(method)),
                )
            }
            Outcome::Gone | Outcome::WriteFailed(_) => {
                let cause = match &outcome {
                    Outcome::WriteFailed(err) => format!(" (writing the request failed: {err})"),
                    _ => String::new(),
                };
                let tail = self.stderr_tail(3).join(" | ");
                self.stop();
                let message = if tail.is_empty() {
                    format!("the kernel stopped unexpectedly{cause}; it will restart on the next request")
                } else {
                    format!("the kernel stopped unexpectedly{cause}: {tail}")
                };
                self.last_error = Some(message.clone());
                refusal("bridge_unavailable", message)
            }
        }
    }

    /// Start the Kernel and check it speaks this shell's protocol.
    fn ensure_running(&mut self) -> Result<(), Value> {
        if self.running.is_some() {
            return Ok(());
        }
        if let Err(message) = self.start() {
            self.last_error = Some(message.clone());
            return Err(refusal("bridge_unavailable", message));
        }
        let outcome = self.exchange("status", &json!({}));
        let status = self.settle("status", outcome);
        let protocol = status.pointer("/result/protocol").and_then(Value::as_u64);
        if protocol != Some(u64::from(PROTOCOL_VERSION)) {
            self.stop();
            let message = format!(
                "the kernel speaks protocol {protocol:?}; this window speaks {PROTOCOL_VERSION}. Rebuild one of them."
            );
            self.last_error = Some(message.clone());
            return Err(refusal("protocol_mismatch", message));
        }
        Ok(())
    }

    /// Ask the Kernel for `method`. Always returns an answer; never panics.
    pub fn call(&mut self, method: &str, params: Value) -> Value {
        if !METHODS.contains(&method) {
            return refusal("method_not_allowed", format!("the window may not ask for {method:?}"));
        }
        if !params.is_object() {
            return refusal("invalid_params", "params must be an object");
        }
        if let Err(refused) = self.ensure_running() {
            return refused;
        }
        let outcome = self.exchange(method, &params);
        self.settle(method, outcome)
    }

    pub fn stop(&mut self) {
        if let Some(mut running) = self.running.take() {
            let _ = running.child.kill();
            let _ = running.child.wait();
            // Dropping `running` closes the job handle, which kills anything the
            // Kernel started that is still alive.
        }
    }

    /// The limits on the running Kernel's job, read from the job itself. None when
    /// nothing is running, or off Windows where there is no job.
    fn limits(&self) -> Option<LimitsView> {
        #[cfg(windows)]
        {
            self.running.as_ref().map(|r| LimitsView {
                memory_bytes: r.job.limits.memory_bytes,
                active_processes: r.job.limits.active_processes,
            })
        }
        #[cfg(not(windows))]
        {
            None
        }
    }

    /// The kernel's own accounting for the Kernel's job. Null when nothing runs.
    fn job_stats(&self) -> Value {
        #[cfg(windows)]
        {
            match self.running.as_ref().map(|r| r.job.stats()) {
                Some(Ok(s)) => json!({
                    "active_processes": s.active_processes,
                    "total_processes": s.total_processes,
                    "cpu_ms": s.cpu_ms,
                    "peak_memory_bytes": s.peak_memory_bytes,
                }),
                _ => Value::Null,
            }
        }
        #[cfg(not(windows))]
        {
            Value::Null
        }
    }

    /// Every process in Sletchy's tree: the window, its renderers, the Kernel.
    fn processes(&self) -> Value {
        #[cfg(windows)]
        {
            crate::procs::snapshot(self.running.as_ref().map(|r| &r.job))
        }
        #[cfg(not(windows))]
        {
            crate::procs::snapshot(None)
        }
    }

    fn stderr_tail(&self, n: usize) -> Vec<String> {
        self.stderr
            .lock()
            .map(|ring| ring.iter().rev().take(n).rev().cloned().collect())
            .unwrap_or_default()
    }

    /// What the Raw view shows about the connection itself.
    pub fn info(&self) -> Value {
        let pid = self.running.as_ref().map(|r| r.child.id());
        json!({
            "program": self.launch.program.display().to_string(),
            "cwd": self.launch.cwd.display().to_string(),
            "running": self.running.is_some(),
            "pid": pid,
            "starts": self.starts,
            "protocol": PROTOCOL_VERSION,
            "confined": self.limits().is_some(),
            "limits": self.limits().map(|l| json!({
                "memory_bytes": l.memory_bytes,
                "active_processes": l.active_processes,
                "kill_on_close": true,
            })),
            "last_error": self.last_error,
            "stderr_tail": self.stderr_tail(40),
            "job": self.job_stats(),
            "processes": self.processes(),
        })
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_method_off_the_allowlist_never_reaches_the_kernel() {
        let mut bridge = Bridge::new(Launch {
            program: PathBuf::from("Z:/definitely/not/here.exe"),
            args: vec![],
            cwd: PathBuf::from("."),
        });
        for method in ["evil.exec", "", "status ", "ledger.append", "flags.reset_all"] {
            let answer = bridge.call(method, json!({}));
            assert_eq!(answer["error"]["code"], "method_not_allowed", "{method}");
        }
        assert_eq!(bridge.starts, 0, "a refused method started the kernel");
    }

    #[test]
    fn params_must_be_an_object() {
        let mut bridge = Bridge::new(Launch::from_repo());
        for params in [json!([]), json!("x"), json!(1), json!(null)] {
            assert_eq!(bridge.call("status", params)["error"]["code"], "invalid_params");
        }
        assert_eq!(bridge.starts, 0);
    }

    #[test]
    fn a_missing_kernel_is_an_answer_not_a_crash() {
        let mut bridge = Bridge::new(Launch {
            program: PathBuf::from("Z:/definitely/not/here.exe"),
            args: vec![],
            cwd: PathBuf::from("."),
        });
        let answer = bridge.call("status", json!({}));
        assert_eq!(answer["error"]["code"], "bridge_unavailable");
        assert!(answer["error"]["message"].as_str().unwrap().contains("uv sync"));
    }

    #[test]
    fn only_the_reply_to_this_request_is_accepted() {
        assert!(reply_for(r#"{"id": 3, "ok": true}"#, 3).is_some());
        assert!(reply_for(r#"{"id": 2, "ok": true}"#, 3).is_none(), "a stale reply");
        assert!(reply_for(r#"{"id": null, "ok": false}"#, 3).is_none());
        assert!(reply_for("not json", 3).is_none());
    }

    #[test]
    fn a_request_is_exactly_one_line() {
        let line = request_line(9, "flags.set", &json!({"name": "a\nb"}));
        assert!(line.ends_with('\n'));
        assert_eq!(line.matches('\n').count(), 1, "an embedded newline would split the request");
    }

    #[test]
    fn stop_gets_longer_than_everything_else() {
        assert!(timeout_for("stop.run") > timeout_for("status"));
        assert!(timeout_for("stop.plan") > timeout_for("flags.set"));
    }

    /// The real thing, when the repository's virtualenv exists: start the Kernel inside
    /// its job, ask for status, and get the protocol this shell was generated for.
    #[test]
    fn the_real_kernel_answers_status_when_present() {
        let launch = Launch::from_repo();
        if !launch.program.exists() {
            eprintln!("skipping: no kernel at {}", launch.program.display());
            return;
        }
        let mut bridge = Bridge::new(launch);
        let answer = bridge.call("status", json!({}));
        assert_eq!(answer["ok"], true, "{answer}");
        assert_eq!(answer["result"]["protocol"], u64::from(PROTOCOL_VERSION));
        assert!(bridge.info()["running"].as_bool().unwrap());
        // Whether a signing key exists depends on the machine: a developer's usually
        // has one, a fresh CI runner does not, and this test never provisions one.
        // Either way, a dangerous switch with no proofs must be refused - and with a
        // key, refused for the right reason.
        let set_up = answer["result"]["ledger_state"] == "ok";
        let refused = bridge.call("flags.set", json!({"name": "senses_camera", "enabled": true}));
        assert_eq!(refused["ok"], false, "{refused}");
        let expected = if set_up { "confirmation_required" } else { "not_initialised" };
        assert_eq!(refused["error"]["code"], expected);
    }
}
