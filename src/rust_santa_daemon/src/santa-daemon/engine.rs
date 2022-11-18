// std imports
use std::{io, fs};
use std::collections::HashMap;
use std::path::PathBuf;

use nix::sys::signal;
use nix::unistd::Pid;
use sha2::{Sha256, Digest};

// local imports
use crate::{SantaMode, Jsonify};
use libsanta::commands::RuleCommandInputType;
use libsanta::consts::{SANTAD_NAME, SANTA_BASE_PATH, RULES_DB_PATH};
use libsanta::cache::{SantaCache, CacheSignature};
use libsanta::engine_types::{*};
use serde::{Serialize, Deserialize};


/// Read the default rules database file
pub fn read_rules_db_file() -> Result<HashMap<String, PolicyRule>, String> {
    // Read the file
    if let Ok(rules_json) = fs::read_to_string(RULES_DB_PATH) {
        // Read the JSON contents of the file as a hashmap.
        let rules = serde_json::from_str(&rules_json);
        if let Ok(rules_json) = rules {
            return Ok(rules_json)
        } else {
            let msg = "Failed to parse JSON to hashmap";
            eprintln!("{}", msg.to_string());
            Err(msg.to_string())
        }
    } else {
        let msg = format!("Failed to read file to string: {RULES_DB_PATH}");
        eprintln!("{}", msg);
        Err(msg.to_string())
    }
}

/// Calculate the SHA256 hash of the file given in `target`
pub fn hash_file_at_path(target: PathBuf) -> Option<String> {
    // sanity check to make sure file exists
    if !target.exists() { return None }
    // open the file
    let mut file = fs::File::open(&target).unwrap();
    // hash file via Read object, avoid reading the entire file into memory
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher).expect("copy the data");
    // finalize the calculation (consumes the hasher instance)
    let hash_bytes = hasher.finalize();
    // we're done
    Some(String::from(format!("{:x}", hash_bytes)))
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct RulesDb (HashMap<String, PolicyRule>);
impl Jsonify for RulesDb {}

/// PolicyEngine struct
pub struct SantaEngine {
    pub mode: SantaMode,
    pub rules: RulesDb,
    cache: SantaCache,
}
// impl Jsonify for HashMap<String, PolicyRule> {}

/// PolicyEngine implementation
impl SantaEngine {
    pub fn new(mode: SantaMode, cache_size: usize) -> SantaEngine {
        let mut engine = SantaEngine{
            mode,
            rules: RulesDb(HashMap::new()),
            cache: SantaCache::new(cache_size),
        };

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
            if let Ok(rules) = read_rules_db_file() {
                engine.rules = RulesDb(rules);
            }
            // return, we've done what we came here to do
            engine
        }
    }

    /// Check the rules database for the given hash and return a PolicyDecision based on the
    /// result.
    fn decision_from_hash_state(&self, state: HashState) -> PolicyDecision {
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
        match self.rules.0.get(hash).copied() {
            // A rule exists, return a decision based on the rule
            Some(rule) => return HashState::from(rule),
            // No rule found, decide based on the current mode
            None => return HashState::HashUnknown,
        };
    }

    /// Return a PolicyDecision for the target pointed to by PolicyEnginePathTarget, only performing 
    /// a hashing operation if the target's signature is not in the hash cache.
    pub fn analyze(&mut self, target: PolicyEnginePathTarget) -> PolicyEngineResult {

        // normalize the path and return it as a string
        let filepath = target.canonical_string();

        // calculate a signature using file metadata
        let uniq_sig = match CacheSignature::new(&target.path_string()) {
            // Skip using the cache if we were unable to generate a cache signature
            Err(_) => {
                // do the hash operation
                let hash: String = match hash_file_at_path(target.path()) {
                    None => {
                        eprintln!("failed to hash file at path");
                        let decision = PolicyDecision::from(self.mode);
                        let reason = PolicyDecisionReason::Error;
                        return PolicyEngineResult { filepath, hash: "".to_string(), decision, reason }
                    },
                    Some(h) => h,
                };

                // make a decision
                let hash_state = self.hash_state(&hash);
                let decision = self.decision_from_hash_state(hash_state);
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
                let decision = self.decision_from_hash_state(hash_state);
                // get the reason for the decision
                let reason = PolicyDecisionReason::from(hash_state);

                // return the result
                PolicyEngineResult { filepath, hash: String::from(hash), decision, reason }
            },

            // Cache Miss
            None => {
                // do the hash operation
                let hash: String = match hash_file_at_path(target.path()) {
                    None => {
                        eprintln!("failed to hash file at path");
                        let decision = PolicyDecision::from(self.mode);
                        let reason = PolicyDecisionReason::Error;
                        return PolicyEngineResult { filepath, hash: "".to_string(), decision, reason }
                    },
                    Some(h) => h,
                };


                // insert the entry into the cache
                self.cache.insert(uniq_sig.to_string(), hash.clone());

                // make a decision
                let hash_state = self.hash_state(&hash);
                let decision = self.decision_from_hash_state(hash_state);
                let reason = PolicyDecisionReason::from(hash_state);

                // return the result
                PolicyEngineResult { filepath, hash, decision, reason }
            },
        }
    }

    /// Kill a target process by PID
    pub fn kill(&self, pid: String) {
        let target: i32 = pid.parse().expect("should have received number");
        let target_pid = Pid::from_raw(target);

        signal::kill(target_pid, signal::SIGKILL).unwrap();
    }

    /// Add a new rule
    pub fn add_rule(&mut self, hash: RuleCommandInputType, rule: PolicyRule) {
        match hash {
            RuleCommandInputType::Hash(val) => {
                println!("{SANTAD_NAME}: adding {} rule for hash {val}",
                        PolicyDecision::from(rule).to_string());
                self.rules.0.insert(String::from(val), rule);
            },
            RuleCommandInputType::Path(val) => {
                if let Some(hash) = hash_file_at_path(val.clone()) {
                    self.rules.0.insert(String::from(hash), rule);
                } else {
                    eprintln!("failed to hash file at path: {}", val.display())
                }
            },
        }
    }

    /// Remove a rule
    pub fn remove_rule(&mut self, hash: RuleCommandInputType) {
        match hash {
            RuleCommandInputType::Hash(val) => {
                println!("{SANTAD_NAME}: removing rule for hash {val}");
                self.rules.0.remove(&val);
            },
            RuleCommandInputType::Path(val) => {
                if let Some(hash) = hash_file_at_path(val.clone()) {
                    self.rules.0.remove(&hash);
                } else {
                    eprintln!("failed to hash file at path: {}", val.display())
                }
            },
        }
    }

    /// Get engine status
    pub fn status(&self) -> PolicyEngineStatus {
        let rule_count = self.rules.0.len();
        let cache_count = self.cache.len();
        let mode = format!("{}", self.mode);
        PolicyEngineStatus { mode, rule_count, cache_count }
    }

}

