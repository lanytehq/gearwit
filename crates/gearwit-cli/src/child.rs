//! One-owner Chanvoy child processes.
//!
//! The slot is the only killer and reaper. The child stays in this process so
//! `try_wait` is pollable and `Child::kill` plus `wait` can surface errors.

use std::io;
use std::process::{Child, Command, ExitStatus, Stdio};

/// Outcome of killing and reaping the occupied child.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KillReap {
    /// `Child::kill` succeeded.
    pub killed: bool,
    /// `Child::wait` collected a status.
    pub reaped: bool,
}

/// Occupies at most one child. A second spawn fails until reap.
#[derive(Debug)]
pub struct ChildSlot {
    child: Option<Child>,
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
        Self { child: None }
    }

    /// Process id of the occupied child.
    #[must_use]
    pub fn pid(&self) -> Option<u32> {
        self.child.as_ref().map(Child::id)
    }

    /// True when a child is occupied and not yet reaped by this slot.
    #[must_use]
    pub fn occupied(&self) -> bool {
        self.child.is_some()
    }

    /// Spawn `program` with `args` into this slot.
    ///
    /// # Errors
    ///
    /// Returns already-exists when occupied, or a spawn I/O error.
    pub fn spawn(&mut self, program: &str, args: &[String]) -> io::Result<u32> {
        if self.child.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "child slot occupied",
            ));
        }
        let child = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let pid = child.id();
        self.child = Some(child);
        Ok(pid)
    }

    /// Non-blocking wait. Leaves the slot occupied when still running.
    ///
    /// # Errors
    ///
    /// Returns waiter I/O errors.
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        let Some(child) = self.child.as_mut() else {
            return Ok(None);
        };
        match child.try_wait()? {
            Some(status) => {
                self.child = None;
                Ok(Some(status))
            }
            None => Ok(None),
        }
    }

    /// SIGKILL the occupied child, then reap. Empty slot is a no-op.
    ///
    /// # Errors
    ///
    /// Returns kill or wait errors. Already-exited children still reap.
    pub fn kill_and_reap(&mut self) -> io::Result<KillReap> {
        let Some(mut child) = self.child.take() else {
            return Ok(KillReap {
                killed: false,
                reaped: false,
            });
        };
        let kill_error = child.kill().err().filter(|error| {
            error.kind() != io::ErrorKind::InvalidInput && error.kind() != io::ErrorKind::NotFound
        });
        match child.wait() {
            Ok(_) => {
                if let Some(error) = kill_error {
                    return Err(error);
                }
                Ok(KillReap {
                    killed: true,
                    reaped: true,
                })
            }
            Err(error) => Err(kill_error.unwrap_or(error)),
        }
    }
}

impl Drop for ChildSlot {
    fn drop(&mut self) {
        let _ = self.kill_and_reap();
    }
}

#[cfg(test)]
mod tests {
    use super::ChildSlot;

    #[test]
    fn second_spawn_fails_until_reap() {
        let mut slot = ChildSlot::new();
        slot.spawn("sleep", &["30".to_owned()])
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
        slot.spawn("true", &[]).expect("reuse after reap");
        let mut spins = 0;
        while slot.occupied() {
            spins += 1;
            assert!(spins < 200, "true did not exit");
            if slot.try_wait().expect("poll").is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(!slot.occupied());
    }

    #[test]
    fn drop_kills_and_reaps() {
        let mut slot = ChildSlot::new();
        slot.spawn("sleep", &["30".to_owned()]).expect("spawn");
        drop(slot);
    }

    #[test]
    fn lease_expiry_kills_and_reaps_running_child() {
        let mut slot = ChildSlot::new();
        slot.spawn("sleep", &["30".to_owned()]).expect("spawn");
        let report = slot.kill_and_reap().expect("lease");
        assert!(report.killed && report.reaped);
        assert!(!slot.occupied());
        let empty = slot.kill_and_reap().expect("empty");
        assert!(!empty.killed && !empty.reaped);
    }
}
