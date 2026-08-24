//! Library surface for the Gearwit CLI.
//!
//! Command parsing lives in the binary. Classification is tested here so
//! census cards do not depend on process globals.

#![forbid(unsafe_code)]

pub mod check;
pub mod sanitize;
pub mod wait_on;
pub mod who;

pub use check::render_check;
pub use wait_on::{WaitOnSpec, WaitResult, run_wait_on};
pub use who::{HarnessFamily, HarnessObservation, ProcessCensus, WhoCard};
