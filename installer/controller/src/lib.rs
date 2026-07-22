#![forbid(unsafe_code)]

//! Verified typed loader and pure simulator for the executable installer
//! state graph. This crate contains no platform adapters and exposes no
//! production disk, firmware, boot, filesystem, or security mutation API.

pub mod graph;
pub mod replay;
pub mod simulator;
pub mod trace;

pub use graph::*;
pub use replay::*;
pub use simulator::*;
pub use trace::*;
