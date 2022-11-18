// std imports
use std::fmt;
use std::path::PathBuf;
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

// local imports
use crate::{SantaMode, Jsonify, Loggable, LoggerSource};

/// HashState
#[derive(Clone, Copy)]
pub enum HashState {
    HashOk,
    HashBlock,
    HashUnknown,
}
/// Derive a HashState from a PolicyRule
impl From<PolicyRule> for HashState {
    fn from(s: PolicyRule) -> HashState {
        match s {
            PolicyRule::Allow => HashState::HashOk,
            PolicyRule::Block => HashState::HashBlock,
        }
    }
}


/// PolicyRule: an emum for the different type of rules that can exist
#[derive(Deserialize, Serialize, Debug, Clone, Copy, ValueEnum)]
pub enum PolicyRule {
    Allow,
    Block,
}
/// Display trait for PolicyRule
impl fmt::Display for PolicyRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyRule::Allow => write!(f, "ALLOW"),
            PolicyRule::Block => write!(f, "BLOCK"),
        }
    }
}


/// PolicyDecisionReason: the reason for a given policy decision
#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub enum PolicyDecisionReason {
    AllowListed,
    BlockListed,
    Unknown,
    Error,
}
/// Derive a PolicyDecisionReason from a HashState
impl From<HashState> for PolicyDecisionReason {
    fn from(s: HashState) -> PolicyDecisionReason {
        match s {
            HashState::HashOk => PolicyDecisionReason::AllowListed,
            HashState::HashBlock => PolicyDecisionReason::BlockListed,
            HashState::HashUnknown => PolicyDecisionReason::Unknown,
        }
    }
}
/// Implement ToString trait for PolicyDecisionReason
impl ToString for PolicyDecisionReason {
    fn to_string(&self) -> String {
        match self {
            PolicyDecisionReason::AllowListed => String::from("allowlisted"),
            PolicyDecisionReason::BlockListed => String::from("blocklisted"),
            PolicyDecisionReason::Unknown => String::from("unknown binary"),
            PolicyDecisionReason::Error => String::from("ERROR"),
        }
    }
}


/// PolicyDecision: an enum for the different decisions the policy engine will return
#[derive(Serialize, Deserialize, Clone, Copy, Eq, PartialEq, Debug)]
pub enum PolicyDecision {
    Allow,
    Block,
}
/// Convert a PolicyDecision to String
impl ToString for PolicyDecision {
    fn to_string(&self) -> String {
        match self {
            PolicyDecision::Allow => String::from("ALLOW"),
            PolicyDecision::Block => String::from("BLOCK"),
        }
    }
}
/// Derive a PolicyDecision from a PolicyRule
impl From<PolicyRule> for PolicyDecision {
    fn from(s: PolicyRule) -> PolicyDecision {
        match s {
            PolicyRule::Allow => PolicyDecision::Allow,
            PolicyRule::Block => PolicyDecision::Block,
        }
    }
}
/// Derive a policy decision from a SantaMode
impl From<SantaMode> for PolicyDecision {
    fn from(s: SantaMode) -> PolicyDecision {
        match s {
            SantaMode::Monitor => PolicyDecision::Allow,
            SantaMode::Lockdown => PolicyDecision::Block,
        }
    }
}
// Derive a PolicyDecision from a HashState


/// PolicyEngineResult
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct PolicyEngineResult {
    pub filepath: String,
    pub hash: String,
    pub decision: PolicyDecision,
    pub reason: PolicyDecisionReason,
}
/// PolicyEngineResult logging method
impl Loggable for PolicyEngineResult {
    fn log(&self, src: LoggerSource) {
        println!("{}: {} ({}) {} -> {}",
            src.to_string(),
            self.reason.to_string(),
            self.decision.to_string(),
            self.filepath,
            self.hash);
    }
}
/// Implement Jsonify trait for PolicyEngineResult
impl Jsonify for PolicyEngineResult {}


/// PolicyEngineStatus: A struct describing the current status of the PolicyEngine
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct PolicyEngineStatus {
    pub mode: String,
    pub rule_count: usize,
    pub cache_count: usize,
}
/// Implement Jsonify trait for PolicyEngineStatus
impl Jsonify for PolicyEngineStatus {}


/// PolicyEngineRuleTarget: ffff that represents the different types of rule targets
pub enum PolicyEngineRuleTarget {
    Path(PathBuf),
    ShaHash(String),
}

/// PolicyEnginePathTarget: Enum that represents the different path-based targets used by
/// the policy engine.
pub enum PolicyEnginePathTarget {
    PidExePath(u32),
    FilePath(PathBuf),
}
// From trait to output a PolicyEnginePathTarget::PidExePath when provided a u32
impl From<u32> for PolicyEnginePathTarget {
    fn from(n: u32) -> Self {
       PolicyEnginePathTarget::PidExePath(n) 
    }
}
// From trait to output a PolicyEnginePathTarget::FilePath when provided a String
impl From<PathBuf> for PolicyEnginePathTarget {
    fn from(n: PathBuf) -> Self {
       PolicyEnginePathTarget::FilePath(n) 
    }
}
// PolicyEnginePathTarget implementation
impl PolicyEnginePathTarget {
    pub fn path_string(&self) -> String {
        match self {
            PolicyEnginePathTarget::PidExePath(pid) => format!("/proc/{pid}/exe"),
            PolicyEnginePathTarget::FilePath(path) => String::from(format!("{}", path.display())),
        }
    }

    pub fn path(&self) -> PathBuf {
        match self {
            PolicyEnginePathTarget::PidExePath(pid) => PathBuf::from(format!("/proc/{pid}/exe")),
            PolicyEnginePathTarget::FilePath(path) => PathBuf::from(path),
        }
    }

    #[allow(dead_code)]
    pub fn canonical(&self) -> PathBuf {
        match self.path().canonicalize() {
            Ok(x) => x,
            Err(_) => self.path(),
        }
    }

    pub fn canonical_string(&self) -> String {
        match self.path().canonicalize() {
            Ok(x) => {
                if let Some(f) = x.to_str() {
                    return String::from(f)
                } else {
                    return self.path_string()
                }
            }
            Err(_) => {
                return self.path_string()
            },
        }
    }
}
