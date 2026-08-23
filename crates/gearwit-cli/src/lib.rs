//! Library surface for the Gearwit CLI.
//!
//! Command parsing lives in the binary. Classification is tested here so
//! census cards do not depend on process globals.

#![forbid(unsafe_code)]

pub mod who;

pub use who::{HarnessHint, ProcessCensus, WhoCard};
