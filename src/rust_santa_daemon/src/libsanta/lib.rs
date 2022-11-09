pub mod netlink;
pub mod daemon;
pub mod uxpc;
pub mod engine;
mod cache;

use std::fmt;

// Constants
pub const SANTAD_NAME: &str = "[santa-DAEMON]";
pub const NL_SANTA_PROTO: u8 = 30;
pub const NL_SANTA_FAMILY_NAME: &str = "gnl_santa";

pub const SANTA_BASE_PATH: &str = "/opt/santa";
pub const RULES_DB_PATH: &str = "/opt/santa/rules.json";
pub const XPC_SOCKET_PATH: &str = "/opt/santa/santa.xpc";
pub const XPC_CLIENT_PATH: &str = "/opt/santa/santactl.xpc";
pub const XPC_SERVER_PATH: &str = "/opt/santa/santad.xpc";

// status command
pub const STATUS_CMD: &str = "status";


/// SantaMode Enum
#[derive(Clone, Copy)]
#[allow(dead_code)]
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
