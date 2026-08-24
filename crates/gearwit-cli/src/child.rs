//! One-owner Chanvoy child processes.
//!
//! The slot is the only killer and reaper. Drop kills and reaps so a daemon
//! shutdown cannot leave an orphan.

use std::io;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};

/// Outcome of killing and reaping the occupied child.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KillReap {
    /// A kill signal was sent, or the child had already exited.
    pub killed: bool,
    /// `wait` collected a status (including already-exited).
    pub reaped: bool,
}

/// Occupies at most one child. A second spawn fails until reap.
#[derive(Debug)]
pub struct ChildSlot {
    pid: Option<u32>,
    waiter: Option<mpsc::Receiver<io::Result<ExitStatus>>>,
    thread: Option<JoinHandle<()>>,
}

impl Default for ChildSlot {
    fn default() -> Self {
        Self::new()
    }
}

impl ChildSlot {
    /// Empty slot.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            pid: None,
            waiter: None,
            thread: None,
        }
    }

    /// Process id of the occupied child.
    #[must_use]
    pub fn pid(&self) -> Option<u32> {
        self.pid
    }

    /// True when a child is occupied and not yet reaped by this slot.
    #[must_use]
    pub fn occupied(&self) -> bool {
        self.pid.is_some()
    }

    /// Spawn `program` with `args` into this slot.
    ///
    /// # Errors
    ///
    /// Returns already-exists when occupied, or a spawn I/O error.
    pub fn spawn(&mut self, program: &str, args: &[String]) -> io::Result<u32> {
        if self.pid.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "child slot occupied",
            ));
        }
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let pid = child.id();
        let (tx, rx) = mpsc::channel();
        let thread = thread::spawn(move || {
            let status = child.wait();
            let _ = tx.send(status);
        });
        self.pid = Some(pid);
        self.waiter = Some(rx);
        self.thread = Some(thread);
        Ok(pid)
    }

    /// Block until the child exits and is reaped.
    ///
    /// # Errors
    ///
    /// Returns I/O errors from the waiter thread, or not-found when empty.
    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        let rx = self
            .waiter
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "child slot empty"))?;
        let status = rx
            .recv()
            .map_err(|_| io::Error::other("child waiter disconnected"))?;
        self.finish();
        status
    }

    /// Non-blocking wait. Leaves the slot occupied when still running.
    ///
    /// # Errors
    ///
    /// Returns waiter I/O errors.
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        let Some(rx) = self.waiter.as_mut() else {
            return Ok(None);
        };
        match rx.try_recv() {
            Ok(status) => {
                self.waiter.take();
                self.finish();
                status.map(Some)
            }
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => {
                self.waiter.take();
                self.finish();
                Err(io::Error::other("child waiter disconnected"))
            }
        }
    }

    /// SIGKILL the occupied child if needed, then reap. Empty slot is a no-op.
    ///
    /// # Errors
    ///
    /// Returns waiter I/O errors after a kill was attempted.
    pub fn kill_and_reap(&mut self) -> io::Result<KillReap> {
        let Some(pid) = self.pid else {
            return Ok(KillReap {
                killed: false,
                reaped: false,
            });
        };
        let _ = Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let rx = self.waiter.take();
        let reaped = if let Some(rx) = rx {
            match rx.recv() {
                Ok(Ok(_) | Err(_)) => true,
                Err(_) => false,
            }
        } else {
            true
        };
        self.finish();
        Ok(KillReap {
            killed: true,
            reaped,
        })
    }

    fn finish(&mut self) {
        self.pid = None;
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for ChildSlot {
    fn drop(&mut self) {
        let _ = self.kill_and_reap();
    }
}

/// True when `kill -0` succeeds for `pid`.
#[must_use]
pub fn pid_is_alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::{ChildSlot, pid_is_alive};
    use std::time::{Duration, Instant};

    #[test]
    fn second_spawn_fails_until_reap() {
        let mut slot = ChildSlot::new();
        let pid = slot
            .spawn("sleep", &["30".to_owned()])
            .expect("first spawn");
        assert!(slot.occupied());
        let err = slot
            .spawn("sleep", &["1".to_owned()])
            .expect_err("occupied");
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        let report = slot.kill_and_reap().expect("reap");
        assert!(report.killed);
        assert!(report.reaped);
        assert!(!slot.occupied());
        assert!(!pid_is_alive(pid));
        slot.spawn("true", &[]).expect("reuse after reap");
        let _ = slot.wait();
    }

    #[test]
    fn drop_kills_and_reaps() {
        let pid;
        {
            let mut slot = ChildSlot::new();
            pid = slot.spawn("sleep", &["30".to_owned()]).expect("spawn");
            assert!(pid_is_alive(pid));
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline && pid_is_alive(pid) {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!pid_is_alive(pid), "drop must not orphan pid {pid}");
    }

    #[test]
    fn lease_expiry_kills_and_reaps_running_child() {
        let mut slot = ChildSlot::new();
        let pid = slot.spawn("sleep", &["30".to_owned()]).expect("spawn");
        let report = slot.kill_and_reap().expect("lease");
        assert!(report.killed && report.reaped);
        assert!(!pid_is_alive(pid));
        let empty = slot.kill_and_reap().expect("empty");
        assert!(!empty.killed && !empty.reaped);
    }
}
