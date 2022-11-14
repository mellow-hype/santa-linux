use libsanta::consts::{SANTA_BASE_PATH, XPC_SOCKET_PATH};
use libsanta::netlink::{NetlinkAgent, NlSantaCommand};
use libsanta::engine::PolicyEngine;
use libsanta::SantaMode;
use libsanta::uxpc::{SantaXpcServer};
use std::path::Path;
use std::error::Error;


/// SantaDaemon object
pub struct SantaDaemon {
    pub netlink: NetlinkAgent,
    pub engine: PolicyEngine,
    pub xpc_rx: SantaXpcServer,
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
            engine: PolicyEngine::new(mode, 1000),
            xpc_rx: SantaXpcServer::new(String::from(XPC_SOCKET_PATH), true),
        };
        daemon.init()?;
        Ok(daemon)
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
        self.netlink.send_cmd(NlSantaCommand::MsgCheckin, &"")?;
        self.netlink.recv()?;
        Ok(())
    }
}
