//! two_key_gate: deterministic provenance, taint and capability gate for LLM
//! agent tool calls. Author: Heywood Geblomi. License: MIT.
//!
//! The gate sits between the model and the tool executor. It never asks the
//! model whether a call is safe. It refuses any privileged tool call whose
//! controlling arguments are not positively traced to trusted spans
//! (system prompt or user turns), regardless of what the model output says.

pub mod crypto;
pub mod gate;
pub mod json;
pub mod log;
pub mod policy;
pub mod service;
pub mod taint;
