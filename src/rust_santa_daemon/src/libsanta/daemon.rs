use crate::{SantaMode, SANTA_BASE_PATH, XPC_SOCKET_PATH};
use crate::netlink::{NetlinkAgentGeneric, NlSantaCommand};
use crate::engine::PolicyEngine;
use crate::uxpc::{SantaXpcServer};
use std::path::Path;

/// SantaDaemon object
pub struct SantaDaemon {
    pub netlink: NetlinkAgentGeneric,
    pub engine: PolicyEngine,
    pub xpc_rx: SantaXpcServer,
}

/// A SantaDaemon instance
impl SantaDaemon {
    pub fn new(mode: SantaMode) -> SantaDaemon {
        // ensure the /opt/santa directory exists
        let santa_base = Path::new(SANTA_BASE_PATH);
        if !santa_base.exists() {
            std::fs::create_dir(santa_base).unwrap();
        }

        let mut daemon = SantaDaemon {
            netlink: NetlinkAgentGeneric::new(Some(0), &[]),
            engine: PolicyEngine::new(mode, 1000),
            xpc_rx: SantaXpcServer::new(String::from(XPC_SOCKET_PATH)),
        };
        daemon.init();
        daemon
    }

    /// Initialize the daemon
    fn init(&mut self) {
        // Check in with the kernel
        self.checkin();

        // NOTE: the daemon's netlink socket is set to be nonblocking so that both
        // the netlink socket and the unix xpc socket can be processed without
        // blocking each other.
        self.set_nonblocking();
    }

    /// Set the netlink socket to non-blocking
    fn set_nonblocking(&mut self) {
        if let Err(_) = self.netlink.socket.nonblock() {
            eprintln!("SantaDaemon failed to set netlink socket to nonblocking")
        }
    }

    /// Do check-in with the kernel module
    fn checkin(&mut self) {
        self.netlink.send_cmd(NlSantaCommand::MsgCheckin, &"")
            .expect("failed to send msg");
        // receive a response (we don't do anything with it though)
        self.netlink.recv();
    }
}
