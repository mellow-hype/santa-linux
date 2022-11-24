pub mod uxpc;
pub mod commands;
pub mod consts;
pub mod engine_types;
pub mod rules;

use std::fmt;
use serde::Serialize;
use serde_json::json;
use consts::{SANTACTL_NAME, SANTAD_NAME};
use sha2::{Sha256, Digest};
use std::{fs, io};
use std::path::PathBuf;


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


/// Calculate the SHA256 hash of the file given in `target`
pub fn hash_file_at_path(target: &PathBuf) -> Option<String> {
    // sanity check to make sure file exists
    if !target.exists() { return None }
    // open the file
    let mut file = match fs::File::open(&target) {
        Ok(f) => f,
        Err(_) => return None,
    };

    // hash file via Read object, avoid reading the entire file into memory
    let mut hasher = Sha256::new();
    if let Err(_) = io::copy(&mut file, &mut hasher) {
        return None
    }
    // finalize the calculation (consumes the hasher instance)
    let hash_bytes = hasher.finalize();
    // we're done
    Some(String::from(format!("{:x}", hash_bytes)))
}