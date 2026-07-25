#![forbid(unsafe_code)]

//! Verified typed loader and pure simulator for the executable installer
//! state graph. This crate contains no platform adapters and exposes no
//! production disk, firmware, boot, filesystem, or security mutation API.

pub mod authority;
pub mod graph;
pub mod platform;
pub mod replay;
pub mod replica;
pub mod runtime;
pub mod simulator;
pub mod trace;

pub use authority::*;
pub use graph::*;
pub use platform::*;
pub use replay::*;
pub use replica::*;
pub use runtime::*;
pub use simulator::*;
pub use trace::*;
