//! Library surface for the Gearwit CLI.
//!
//! Command parsing lives in the binary. Classification is tested here so
//! census cards do not depend on process globals.

#![forbid(unsafe_code)]

pub mod attach;
pub mod check;
pub mod child;
pub mod daemon;
pub mod sanitize;
pub mod wait_on;
pub mod who;

pub use attach::{AttachSpec, render_attach_receipt, run_attach_session};
pub use check::render_check;
pub use daemon::run_daemon_wait;
pub use wait_on::{WaitOnSpec, WaitResult, run_wait_on};
pub use who::{HarnessFamily, HarnessObservation, ProcessCensus, WhoCard};
