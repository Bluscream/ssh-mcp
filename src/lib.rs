//! ssh-mcp as a library, so the tools can be embedded directly rather
//! than run as a subprocess. The binary in `main.rs` is a thin wrapper
//! over this.

pub mod config;
pub mod policy;
pub mod tools;
