//! SuperBrave: build a verified, engine-optimized filter list for the Brave
//! `adblock` (adblock-rust) engine.

pub mod config;
pub mod fetch;
pub mod optimise;
pub mod output;
pub mod parse;
pub mod pipeline;
pub mod rewrite;
pub mod verify;
