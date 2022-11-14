use std::process;
use std::error::Error;

pub const NL_SANTA_PROTO: u8 = 30;
pub const NL_SANTA_FAMILY_NAME: &str = "gnl_santa";

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
pub struct NetlinkAgent {
    pub family_id: u16,
    pub socket: NlSocketHandle,
    pub groups: Vec<u32>,
}

/// NetlinkAgent implementation.
impl NetlinkAgent {
    /// Create a new instance of a NetlinkAgent.
    /// Example:
    /// ```
    /// let agent = NetlinkAgent::new(Some(0), &[]);
    /// ```
    pub fn new(pid: Option<u32>, groups: &[u32]) -> Result<NetlinkAgent, Box<dyn Error>> {
        // create and bind the socket
        let mut socket = NlSocketHandle::connect(
            NlFamily::Generic,
            pid,
            groups,
        )?;

        // resolve family ID
        let family_id = socket.resolve_genl_family(NL_SANTA_FAMILY_NAME)?;

        Ok(NetlinkAgent { family_id, socket, groups: Vec::from(groups) })
    }

    /// Send a specific `NlSantaCommand` and message payload via Netlink; the socket handle passed
    /// in should already be initialized and bound using `NlSocketHandle::connect()`.
    /// Example:
    /// ```
    /// let agent = NetlinkAgent::new(Some(0), &[]);
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
    /// let agent = NetlinkAgent::new(Some(0), &[]);
    /// let res = agent.recv().unwrap();
    /// let msg = res.get_payload().unwrap();
    /// let attr_handle = msg.get_attr_handle().unwrap();
    /// let payload_data = attr_handle.
    ///     get_attr_payload_as_with_len::<String>(NlSantaAttribute::Msg).unwrap();
    /// ```
    pub fn recv(&mut self)
                -> Result<Option<(NlSantaCommand, String)>, String> {
        // If the socket is in non-blocking mode the Result'ing Option may be None if no
        // data could be immediately read from the socket, which isn't an issue. In blocking
        // mode, the Result will either be Some(Nlmsghdr) or NlError; errors are an issue regardless
        // of the blocking context.
        match self.socket.recv() {
            Ok(msg) => {
                let mess: Option<Nlmsghdr<u16, Genlmsghdr<NlSantaCommand, NlSantaAttribute>>> = msg;
                match mess {
                    // Some means we were able to read a message from the socket
                    Some(x) => {
                        if let Ok(pay) = x.get_payload() {
                            let cmd: NlSantaCommand = pay.cmd;
                            let attr_handle = pay.get_attr_handle();
                            let x = attr_handle.get_attr_payload_as_with_len::<String>(NlSantaAttribute::Msg);
                            if let Ok(payload) = x {
                                return Ok(Some((cmd, payload)))
                            } else {
                                return Err("failed to parse payload from the attr".to_string())
                            }
                        } else {
                            return Err("failed to get payload from nlmsgh header".to_string())
                        }
                    }
                    // None means a message couldn't be immediately read from the socket, which is okay
                    // since the netlink socket it set to be non-blocking; we just move on and try to read again
                    // on the next iteration
                    None => {
                        return Ok(None)
                    }
                }
            },
            Err(e) => {
                let err = format!("error on netlink recv: {e}");
                Err(err.to_string())
            }
        }
    }
}


