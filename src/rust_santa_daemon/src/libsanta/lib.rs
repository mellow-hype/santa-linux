pub mod uxpc;
pub mod commands;
pub mod consts;
pub mod engine_types;
pub mod cache;

use std::fmt;
use serde::Serialize;
use serde_json::json;
use consts::{SANTACTL_NAME, SANTAD_NAME};

/// SantaMode Enum
#[derive(Clone, Copy)]
pub enum SantaMode {
    Lockdown,
    Monitor,
}

impl fmt::Display for SantaMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SantaMode::Lockdown => write!(f, "Lockdown"),
            SantaMode::Monitor => write!(f, "Monitor"),
        }
    }
}

/// Trait for types that support being json-ified to simplify doing so.
pub trait Jsonify: Serialize {
    fn jsonify(&self) -> String {
        let js = json!(self);
        js.to_string()
    }

    fn jsonify_pretty(&self) -> String {
        serde_json::to_string_pretty(self)
            .unwrap_or(self.jsonify())
    }
}

pub trait Loggable {
    fn log(&self, src: LoggerSource);
}

pub enum LoggerSource {
    SantaDaemon,
    SantaCtl,
}
impl ToString for LoggerSource {
    fn to_string(&self) -> String {
        match self {
            LoggerSource::SantaCtl => String::from(SANTACTL_NAME),
            LoggerSource::SantaDaemon => String::from(SANTAD_NAME),
        }
    }
}
