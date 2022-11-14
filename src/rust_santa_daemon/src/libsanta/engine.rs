// std imports
use std::{io, fs, fmt};
use std::collections::HashMap;
use clap::ValueEnum;
use nix::sys::signal;
use nix::unistd::Pid;

use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};

// local imports
use crate::{SantaMode, Jsonify, Loggable, LoggerSource};
use crate::consts::{SANTAD_NAME, SANTA_BASE_PATH, RULES_DB_PATH};
use crate::cache::{SantaCache, CacheSignature};

/// Enum of policy decisions returned during hash validation checks
#[allow(dead_code)]
#[derive(Deserialize, Serialize, Debug, Clone, Copy, ValueEnum)]
pub enum PolicyRule {
    Allow,
    Block,
}

impl fmt::Display for PolicyRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyRule::Allow => write!(f, "Allowlist"),
            PolicyRule::Block => write!(f, "Blocklist"),
        }
    }
}

/// PolicyDecisionReason: the reason for a given policy decision
#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub enum PolicyDecisionReason {
    AllowListed,
    BlockListed,
    Unknown,
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
            PolicyDecisionReason::AllowListed => String::from("ALLOWLISTED"),
            PolicyDecisionReason::BlockListed => String::from("BLOCKLISTED"),
            PolicyDecisionReason::Unknown => String::from("UNKNOWN"),
        }
    }
}

/// PolicyDecision
#[derive(Serialize, Deserialize, Clone, Copy, Eq, PartialEq, Debug)]
#[allow(dead_code)]
pub enum PolicyDecision {
    Allow,
    Block,
    Invalid,
}

/// Convert a PolicyDecision to String
impl ToString for PolicyDecision {
    fn to_string(&self) -> String {
        match self {
            PolicyDecision::Allow => String::from("ALLOW"),
            PolicyDecision::Block => String::from("BLOCK"),
            PolicyDecision::Invalid => String::from("INVALID")
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


/// HashState
#[derive(Clone, Copy)]
#[allow(dead_code)]
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


/// A struct describing the current status of the PolicyEngine
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct PolicyEngineStatus {
    mode: String,
    rule_count: usize,
    cache_count: usize,
}
/// Implement Jsonify trait for PolicyEngineStatus
impl Jsonify for PolicyEngineStatus {}


// PolicyEngineTarget types
pub enum PolicyEngineTargetType {
    Pid,
    Path,
}

// A struct representing a target for the PolicyEngine
pub struct PolicyEngineTarget ( String, PolicyEngineTargetType );
impl From<String> for PolicyEngineTarget {
    fn from(target: String) -> PolicyEngineTarget {
        if let Ok(pid) = target.parse::<u32>() {
            let target = String::from(format!("/proc/{pid}/exe"));
            return PolicyEngineTarget(target, PolicyEngineTargetType::Pid)
        } else {
            return PolicyEngineTarget(target, PolicyEngineTargetType::Path)
        }
    }
}


/// PolicyEngine struct
pub struct PolicyEngine {
    pub mode: SantaMode,
    pub rules: HashMap<String, PolicyRule>,
    cache: SantaCache,
}
impl Jsonify for HashMap<String, PolicyRule> {}

/// PolicyEngine implementation
impl PolicyEngine {
    pub fn new(mode: SantaMode, cache_size: usize) -> PolicyEngine {
        let mut engine = PolicyEngine{
            mode,
            rules: HashMap::new(),
            cache: SantaCache::new(cache_size),
        };
        // ensure the /opt/santa directory exists
        // check if the rules file exits
        let rules_filepath = std::path::PathBuf::from(RULES_DB_PATH);
        if !rules_filepath.exists() {
            // it doesn't so lets check if the parent directory exists and create it if not
            let santa_path = std::path::PathBuf::from(SANTA_BASE_PATH);
            if !santa_path.exists() {
                if let Err(_) = std::fs::create_dir(santa_path) {
                    eprintln!("Could not create santa directory at {SANTA_BASE_PATH}");
                    // continue without loading rules from a file
                    return engine
                }
            }
            // create an empty rules file
            if let Err(_) = std::fs::File::create(rules_filepath.clone()) {
                eprintln!("Could not create empty rules file");
            }
            // return, we don't need to read an empty rules db
            engine
        } else {
            // the rules DB file already existed, read it
            engine.load_rules_db();
            // return, we've done what we came here to do
            engine
        }
   }

    /// Add a new rule
    #[allow(dead_code)]
    pub fn add_rule(&mut self, hash: &str, rule: PolicyRule) {
        println!("{SANTAD_NAME}: adding {} rule for hash {hash}",
                 PolicyDecision::from(rule).to_string());
        self.rules.insert(String::from(hash), rule);
    }

    /// Remove a rule
    #[allow(dead_code)]
    pub fn remove_rule(&mut self, hash: &str) {
        self.rules.remove(hash);
    }

    /// Get engine status
    pub fn get_status(&self) -> PolicyEngineStatus {
        let rule_count = self.rules.len();
        let cache_count = self.cache.len();
        let mode = format!("{}", self.mode);
        PolicyEngineStatus { mode, rule_count, cache_count }
    }

    // load rules db
    fn load_rules_db(&mut self) {
        // Read the file
        if let Ok(rules_json) = fs::read_to_string(RULES_DB_PATH) {
            // Read the JSON contents of the file as an instance of `User`.
            let rules = serde_json::from_str(&rules_json);
            if let Ok(rules_json) = rules {
                self.rules = rules_json;
            }
        } else {
            eprintln!("Failed to read file to string: {RULES_DB_PATH}");
        }
    }

    /// Kill a target process by PID
    pub fn kill(&self, pid: String) {
        let target: i32 = pid.parse().expect("should have received number");
        let target_pid = Pid::from_raw(target);

        signal::kill(target_pid, signal::SIGKILL).unwrap();
    }

    /// Get the canonical name of the file pointed to by the /proc/<PID>/exe symlink.
    fn canonical_path(&self, proc_exe_path: &str) -> String {
        // This should always be a link since we construct the /proc/pid/exe path ourselves with
        // the pid.
        fs::read_link(&proc_exe_path)
            // empty pathbuf if we couldnt resolve the link
            .unwrap_or(std::path::PathBuf::new())
            .into_os_string()
            .into_string()
            // convert to string or use the proc exe path if we failed for some reason
            .unwrap_or(String::from(proc_exe_path))
    }

    /// Calculate the SHA256 hash of the file pointed to by `proc_pid_path`, which is expected to be
    /// a path pointing to the exe file in the proc fs for the target PID: /proc/<PID>/exe
    fn hash(&self, proc_exe_path: &str) -> String {
        // open the file
        let mut file = fs::File::open(proc_exe_path).expect("proc path should exist");
        // hash file via Read object, avoid reading the entire file into memory
        let mut hasher = Sha256::new();
        io::copy(&mut file, &mut hasher).expect("copy the data");
        // finalize the calculation (consumes the hasher instance)
        let hash_bytes = hasher.finalize();
        // we're done
        String::from(format!("{:x}", hash_bytes))
    }

    /// Check the rules database for the given hash and return a PolicyDecision based on the
    /// result.
    fn make_decision(&self, state: HashState) -> PolicyDecision {
        match state {
            HashState::HashOk => PolicyDecision::Allow,
            HashState::HashBlock => PolicyDecision::Block,
            HashState::HashUnknown => {
                PolicyDecision::from(self.mode)
            },
        }
    }

    /// Determine a state for the given hash based on whether its on the allowlist, blocklist, or
    /// unknown.
    fn hash_state(&self, hash: &str) -> HashState {
        match self.rules.get(hash).copied() {
            // A rule exists, return a decision based on the rule
            Some(rule) => return HashState::from(rule),
            // No rule found, decide based on the current mode
            None => return HashState::HashUnknown,
        };
    }

    /// Return a PolicyDecision for the target pointed to by PolicyEngineTarget, only performing 
    /// a hashing operation if the target's signature is not in the hash cache.
    pub fn analyze(&mut self, target: PolicyEngineTarget) -> PolicyEngineResult {

        let filepath;
        if let PolicyEngineTargetType::Pid = target.1 {
            filepath = self.canonical_path(&target.0.clone());
        } else {
            filepath = target.0.clone();
        }

        // calculate a signature using file metadata
        let uniq_sig = match CacheSignature::new(&target.0) {
            // Skip using the cache if we were unable to generate a cache signature
            Err(_) => {
                // do the hash operation
                let hash = self.hash(&target.0);

                // make a decision
                let hash_state = self.hash_state(&hash);
                let decision = self.make_decision(hash_state);
                let reason = PolicyDecisionReason::from(hash_state);

                // return the result
                return PolicyEngineResult { filepath, hash, decision, reason }
            }
            Ok(s) => {s},
        };

        // check if the signature is in the cache
        match self.cache.find(uniq_sig.to_string()) {
            // Cache Hit
            Some(hash) => {
                // we already know the hash for this file, get it's state
                let hash_state = self.hash_state(hash);
                // make a decision
                let decision = self.make_decision(hash_state);
                // get the reason for the decision
                let reason = PolicyDecisionReason::from(hash_state);

                // return the result
                PolicyEngineResult { filepath, hash: String::from(hash), decision, reason }
            },

            // Cache Miss
            None => {
                // do the hash operation
                let hash = self.hash(&target.0);

                // insert the entry into the cache
                self.cache.insert(uniq_sig.to_string(), hash.clone());

                // make a decision
                let hash_state = self.hash_state(&hash);
                let decision = self.make_decision(hash_state);
                let reason = PolicyDecisionReason::from(hash_state);

                // return the result
                PolicyEngineResult { filepath, hash, decision, reason }
            },
        }
    }
}

