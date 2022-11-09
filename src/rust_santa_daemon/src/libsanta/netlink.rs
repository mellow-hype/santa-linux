use crate::{NL_SANTA_PROTO, NL_SANTA_FAMILY_NAME};
use std::process;
use std::error::Error;

// neli import for Netlink support
#[allow(unused_imports)]
use neli::{
    consts::{genl::*, nl::*, socket::*},
    neli_enum,
    genl::{Genlmsghdr, Nlattr},
    nl::{Nlmsghdr, NlPayload},
    socket::NlSocketHandle,
    types::{Buffer, GenlBuffer},
};


/// Enum of known commands that have been registered for operations with the kernel module.
/// This corresponds to the GNL_SANTA_ATTRIBUTE enum on the kernel side.
#[neli_enum(serialized_type = "u8")]
pub enum NlSantaCommand {
    Unspec = 0,
    // We expect MSG commands to have NlSantaAttribute:Msg
    Msg = 1,        // Generic message type (string)
    MsgCheckin = 2, // Checkin from agent (string)
    MsgGetPid = 3,  // Command for GetPID
    MsgHashDone = 4,// Agent finished hash operation
    ReplyWithNlmsgErr = 5,
    MsgGetRules = 6,
}
// Implement necessary trait for the neli lib on the NlSantaCommand enum.
impl neli::consts::genl::Cmd for NlSantaCommand{}


/// Enum of known netlink attributes that have been defined for operations with the kernel module.
/// This corresponds to the GNL_SANTA_ATTRIBUTE enum on the kernel side.
#[neli_enum(serialized_type = "u16")]
pub enum NlSantaAttribute {
    Unspec = 0,
    // We expect MSG attributes to be NULL terminated C strings
    Msg = 1,
    MsgCheckin = 2,
    MsgHashDone = 3,
}
// Implement necessary trait for the neli lib on the NlSantaAttribute enum.
impl neli::consts::genl::NlAttrType for NlSantaAttribute{}


/// Netlink socket wrapper object with send and recv methods
pub struct NetlinkAgentGeneric {
    pub family_id: u16,
    pub socket: NlSocketHandle,
    pub groups: Vec<u32>,
}

/// NetlinkAgentGeneric implementation.
impl NetlinkAgentGeneric {
    /// Create a new instance of a NetlinkAgent.
    /// Example:
    /// ```
    /// let agent = NetlinkAgentGeneric::new(Some(0), &[]);
    /// ```
    pub fn new(pid: Option<u32>, groups: &[u32]) -> NetlinkAgentGeneric {
        // create and bind the socket
        let mut socket = NlSocketHandle::connect(
            NlFamily::Generic,
            pid,
            groups,
        ).expect("socket should be created");

        // resolve family ID
        let family_id = socket.resolve_genl_family(NL_SANTA_FAMILY_NAME)
            .expect("the kernel module should be loaded before running the daemon");

        NetlinkAgentGeneric { family_id, socket, groups: Vec::from(groups) }
    }

    /// Send a specific `NlSantaCommand` and message payload via Netlink; the socket handle passed
    /// in should already be initialized and bound using `NlSocketHandle::connect()`.
    /// Example:
    /// ```
    /// let agent = NetlinkAgentGeneric::new(Some(0), &[]);
    /// agent.send_cmd(NlSantaCommand::Msg, "hello")?;
    /// ```
    pub fn send_cmd(&mut self, command: NlSantaCommand, 
                    msg_data: &str) -> Result<(), Box<dyn Error>> {
        // set up attributes + payload
        let mut attrs: GenlBuffer<NlSantaAttribute, Buffer> = GenlBuffer::new();
        attrs.push(
            Nlattr::new(
                false,
                false,
                // the attribute in which the data will be stored
                NlSantaAttribute::Msg,
                // the actual payload data
                msg_data,
            )?,
        );

        // The generic netlink header, contains the attributes (actual data) as payload.
        let genlhdr = Genlmsghdr::new(
            // the custom command we've defined in NlSantaCommand
            command,
            // this is the custom protocol version, application specific
            NL_SANTA_PROTO,
            // contains the actual payload data
            attrs,
        );

        // Construct the Nlmsghdr struct that will be passed to send().
        let nlhdr = {
            let len = None;
            let nl_type = self.family_id;
            let flags = NlmFFlags::new(&[NlmF::Request]);
            let seq = None;
            let pid = Some(process::id());
            let payload = NlPayload::Payload(genlhdr);
            Nlmsghdr::new(len, nl_type, flags, seq, pid, payload)
        };

        // Send the request
        self.socket.send(nlhdr)?;
        Ok(())
    }

    /// Receive a netlink message using the opened socket
    /// Example:
    /// ```
    /// let agent = NetlinkAgentGeneric::new(Some(0), &[]);
    /// let res = agent.recv().unwrap();
    /// let msg = res.get_payload().unwrap();
    /// let attr_handle = msg.get_attr_handle().unwrap();
    /// let payload_data = attr_handle.
    ///     get_attr_payload_as_with_len::<String>(NlSantaAttribute::Msg).unwrap();
    /// ```
    pub fn recv(&mut self)
                -> Option<Nlmsghdr<u16, Genlmsghdr<NlSantaCommand, NlSantaAttribute>>> {
        // If the socket is in non-blocking mode the Result'ing Option may be None if no
        // data could be immediately read from the socket, which isn't an issue. In blocking
        // mode, the Result will either be Some(Nlmsghdr) or NlError; errors are an issue regardless
        // of the blocking context.
        match self.socket.recv() {
            Ok(msg) => msg,
            Err(e) => {
                eprintln!("error on netlink recv(): {}", e);
                None
            }
        }
    }
}


