// std imports

use nix::sys::signal;
use nix::unistd::Pid;

// local imports
use crate::SantaMode;
use libsanta::rules::RulesDb;
use libsanta::engine_types::{
    HashState,
    PolicyDecision,
    PolicyDecisionReason,
    PolicyEngineResult,
};

/// PolicyEngine struct
pub struct SantaEngine {
    pub mode: SantaMode,
    pub rules: RulesDb,
}
// impl Jsonify for HashMap<String, PolicyRule> {}

/// PolicyEngine implementation
impl SantaEngine {
    pub fn new(mode: SantaMode) -> SantaEngine {
        SantaEngine{
            mode,
            rules: RulesDb::new(),
        }
    }

    /// Sync the daemon's ruleset back to the rules db file
    #[allow(dead_code)]
    fn sync_rules(&self) {
        // write_json_to_file(&self.rules, RULES_DB_PATH)
    }

    /// Check the rules database for the given hash and return a PolicyDecision based on the
    /// result.
    fn decision_from_hash_state(&self, state: &HashState) -> PolicyDecision {
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
    #[allow(dead_code)]
    fn hash_state(&self, hash: &str) -> HashState {
        match self.rules.0.get(hash).copied() {
            // A rule exists, return a decision based on the rule
            Some(rule) => return HashState::from(rule),
            // No rule found, decide based on the current mode
            None => return HashState::HashUnknown,
        };
    }

    pub fn decide(&self, hash: &str) -> PolicyEngineResult {
        match self.rules.0.get(hash).copied() {
            // A rule exists, return a decision based on the rule
            Some(rule) => {
                let state = HashState::from(rule);
                let dec = self.decision_from_hash_state(&state);
                let reason = PolicyDecisionReason::from(state);
                return PolicyEngineResult {filepath: "".to_string(), hash: hash.to_string(), decision: dec, reason}
            }
            // No rule found, decide based on the current mode
            None => {
                let state = HashState::HashUnknown;
                let dec = self.decision_from_hash_state(&state);
                let reason = PolicyDecisionReason::from(state);
                return PolicyEngineResult {filepath: "".to_string(), hash: hash.to_string(), decision: dec, reason}
            }
        };
    }

    /// Kill a target process by PID
    pub fn kill(&self, pid: i32) {
        let target_pid = Pid::from_raw(pid);
        if let Err(_) = signal::kill(target_pid, signal::SIGKILL) {
            eprintln!("Error sending SIGKILL to process with pid {pid}")
        }
    }
}

