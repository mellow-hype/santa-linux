// local imports
use crate::{SANTAD_NAME, SANTA_BASE_PATH, RULES_DB_PATH, SantaMode};
use crate::cache::{SantaCache, CacheSignature};

// std imports
use std::collections::HashMap;
use std::{io, fs};
use nix::sys::signal;
use nix::unistd::Pid;

// sha256 support
use sha2::{Sha256, Digest};
// json
use serde::Deserialize;
use serde::Serialize;

/// Enum of policy decisions returned during hash validation checks
#[allow(dead_code)]
#[derive(Deserialize, Debug, Clone, Copy)]
pub enum PolicyRule {
    Allow,
    Block,
}

/// PolicyDecisionReason: the reason for a given policy decision
#[derive(Clone, Copy, Eq, PartialEq)]
#[allow(dead_code)]
pub enum PolicyDecisionReason {
    AllowListed,
    BlockListed,
    Unknown,
}

impl From<HashState> for PolicyDecisionReason {
    fn from(s: HashState) -> PolicyDecisionReason {
        match s {
            HashState::HashOk => PolicyDecisionReason::AllowListed,
            HashState::HashBlock => PolicyDecisionReason::BlockListed,
            HashState::HashUnknown => PolicyDecisionReason::Unknown,
        }
    }
}

impl PolicyDecisionReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            PolicyDecisionReason::AllowListed => "ALLOWLISTED",
            PolicyDecisionReason::BlockListed => "BLOCKLISTED",
            PolicyDecisionReason::Unknown => "UNKNOWN",
        }
    }
}

/// HashState
#[derive(Clone, Copy, Eq, PartialEq)]
#[allow(dead_code)]
pub enum HashState {
    HashOk,
    HashBlock,
    HashUnknown,
}
impl From<PolicyRule> for HashState {
    fn from(s: PolicyRule) -> HashState {
        match s {
            PolicyRule::Allow => HashState::HashOk,
            PolicyRule::Block => HashState::HashBlock,
        }
    }
}

/// PolicyDecision
#[derive(Clone, Copy, Eq, PartialEq)]
#[allow(dead_code)]
pub enum PolicyDecision {
    Allow,
    Block,
}

impl PolicyDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            PolicyDecision::Allow => "ALLOW",
            PolicyDecision::Block => "BLOCK",
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

/// Derive a policy decision from the mode.
impl From<SantaMode> for PolicyDecision {
    fn from(s: SantaMode) -> PolicyDecision {
        match s {
            SantaMode::Monitor => PolicyDecision::Allow,
            SantaMode::Lockdown => PolicyDecision::Block,
        }
    }
}


/// PolicyEngineResult
#[derive(Clone)]
pub struct PolicyEngineResult {
    pub filepath: String,
    pub hash: String,
    pub decision: PolicyDecision,
    pub reason: PolicyDecisionReason,
}

impl PolicyEngineResult {
    pub fn log(&self) {
        println!("{SANTAD_NAME}: {} ({}) {} -> {}",
            self.reason.as_str(),
            self.decision.as_str(),
            self.filepath,
            self.hash);
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct PolicyEngineStatus {
    mode: String,
    rule_count: usize,
    cache_count: usize,
}

/// PolicyEngine struct
pub struct PolicyEngine {
    pub mode: SantaMode,
    pub rules: HashMap<String, PolicyRule>,
    cache: SantaCache,
}

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
                 PolicyDecision::from(rule).as_str());
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
    fn kill(&self, pid: String, reason: PolicyDecisionReason) {
        let target: i32 = pid.parse().expect("should have received number");
        let target_pid = Pid::from_raw(target);
        let reason_str = reason.as_str();

        println!("{SANTAD_NAME}: {reason_str} application; killing pid {pid}");
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

    /// Return a PolicyDecision for a given target PID `t_pid`, only performing the hashing
    /// operation if the file signature is not in the hash cache.
    pub fn analyze(&mut self, t_pid: &str) -> PolicyEngineResult {
        // construct the `/proc/PID/exe
        let proc_pid_path = format!("/proc/{t_pid}/exe");
        // canonical path for pid exe
        let filepath = self.canonical_path(&proc_pid_path);
        // calculate a signature using file metadata
        let uniq_sig = CacheSignature::new(&proc_pid_path);

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

                // check whether we need to kill the process
                match decision {
                    PolicyDecision::Block => {
                        self.kill(String::from(t_pid), reason);
                    },
                    _ => {},
                }

                // return the result
                PolicyEngineResult { filepath, hash: String::from(hash), decision, reason }
            },

            // Cache Miss
            None => {
                // do the hash operation
                let hash = self.hash(&proc_pid_path);

                // insert the entry into the cache
                self.cache.insert(uniq_sig.to_string(), hash.clone());

                // make a decision
                let hash_state = self.hash_state(&hash);
                let decision = self.make_decision(hash_state);
                let reason = PolicyDecisionReason::from(hash_state);

                // check whether we need to kill the process
                match decision {
                    PolicyDecision::Block =>
                        self.kill(String::from(t_pid), reason),
                    _ => {},
                }

                // return the result
                PolicyEngineResult { filepath, hash, decision, reason }
            },
        }
    }
}

