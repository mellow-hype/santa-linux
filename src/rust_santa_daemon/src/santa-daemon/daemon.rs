use std::path::Path;
use std::error::Error;
use libsanta::{
    hash_file_at_path,
    consts::{SANTA_BASE_PATH, XPC_SOCKET_PATH},
    SantaMode,
    uxpc::SantaXpcServer, 
    engine_types::{PolicyEnginePathTarget, PolicyEngineResult, PolicyDecision, PolicyDecisionReason, PolicyEngineStatus},
};

use crate::{engine::{SantaEngine}, cache::{CacheSignature, SantaCache}};
use crate::netlink::{NetlinkAgent, NlSantaCommand};

/// SantaDaemon object
pub struct SantaDaemon {
    pub netlink: NetlinkAgent,
    pub engine: SantaEngine,
    pub xpc_rx: SantaXpcServer,
    pub cache: SantaCache,
}

/// A SantaDaemon instance
impl SantaDaemon {
    pub fn new(mode: SantaMode) -> Result<SantaDaemon, Box<dyn Error>> {
        // ensure the /opt/santa directory exists
        let santa_base = Path::new(SANTA_BASE_PATH);
        if !santa_base.exists() {
            std::fs::create_dir_all(santa_base)?;
        }

        let mut daemon = SantaDaemon {
            netlink: NetlinkAgent::new(Some(0), &[])?,
            engine: SantaEngine::new(mode),
            xpc_rx: SantaXpcServer::new(XPC_SOCKET_PATH, true),
            cache: SantaCache::new(1000),
        };
        daemon.init()?;
        Ok(daemon)
    }

    /// Get engine status
    pub fn status(&self) -> PolicyEngineStatus {
        let rule_count = self.engine.rules.0.len();
        let cache_count = self.cache.len();
        let mode = format!("{}", self.engine.mode);
        PolicyEngineStatus { mode, rule_count, cache_count }
    }

    /// Return a PolicyDecision for the target pointed to by PolicyEnginePathTarget, only performing 
    /// a hashing operation if the target's signature is not in the hash cache.
    pub fn check(&mut self, target: &PolicyEnginePathTarget) -> PolicyEngineResult {
        // normalize the path and return it as a string
        let filepath = target.canonical_string();

        // calculate a signature using file metadata
        let uniq_sig = match CacheSignature::new(&target.path_string()) {
            // Skip using the cache if we were unable to generate a cache signature
            Err(_) => {
                // do the hash operation
                let hash: String = match hash_file_at_path(&target.path()) {
                    None => {
                        eprintln!("failed to hash file at path");
                        let decision = PolicyDecision::from(self.engine.mode);
                        let reason = PolicyDecisionReason::Error;
                        return PolicyEngineResult { filepath, hash: "".to_string(), decision, reason }
                    },
                    Some(h) => h,
                };

                // make a decision
                let mut pres = self.engine.decide(&hash);
                pres.filepath = filepath;
                return pres
            }
            Ok(s) => {s},
        };


        // check if the signature is in the cache
        match self.cache.find(&uniq_sig.to_string()) {
            // Cache Hit
            Some(hash) => {
                // return the result
                let mut res = self.engine.decide(&hash);
                res.filepath = filepath;
                return res
                // PolicyEngineResult { filepath, hash: String::from(hash), decision, reason }
            },
            None => {
                // do the hash operation
                let hash: String = match hash_file_at_path(&target.path()) {
                    None => {
                        eprintln!("failed to hash file at path");
                        let decision = PolicyDecision::from(self.engine.mode);
                        let reason = PolicyDecisionReason::Error;
                        return PolicyEngineResult { filepath, hash: "".to_string(), decision, reason }
                    },
                    Some(h) => h,
                };
                self.cache.insert(uniq_sig.to_string(), hash.clone());
                let mut res = self.engine.decide(&hash);
                res.filepath = filepath;
                return res
            }
        }
    }

    /// Initialize the daemon
    fn init(&mut self) -> Result<(), Box<dyn Error>> {
        // Check in with the kernel
        self.checkin()?;

        // NOTE: the daemon's netlink socket is set to be nonblocking so that both
        // the netlink socket and the unix xpc socket can be processed without
        // blocking each other.
        self.set_nonblocking();
        Ok(())
    }

    /// Set the netlink socket to non-blocking
    fn set_nonblocking(&mut self) {
        if let Err(_) = self.netlink.socket.nonblock() {
            eprintln!("SantaDaemon failed to set netlink socket to nonblocking")
        }
    }

    /// Do check-in with the kernel module
    fn checkin(&mut self) -> Result<(), Box<dyn Error>> {
        self.netlink.send_cmd(&NlSantaCommand::MsgCheckin, &"")?;
        self.netlink.recv()?;
        Ok(())
    }
}
