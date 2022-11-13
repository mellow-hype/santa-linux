use std::os::unix::net::UnixStream;
use std::os::unix::net::UnixListener;
use std::io::prelude::*;
use std::io::{Error, ErrorKind};
use std::path::Path;

/// A server-side Unix socket
pub struct SantaXpcServer {
    rx: UnixListener,
}
impl SantaXpcServer {
    pub fn new(path: String, nonblocking: bool) -> SantaXpcServer {
        // set up the socket for receiving commands
        let rx_sockpath = Path::new(&path);
        // delete old socket if it exists
        if rx_sockpath.exists() {
            std::fs::remove_file(rx_sockpath).expect("should be able to delete file");
        }
        // bind the rx socket
        let rx = match UnixListener::bind(rx_sockpath) {
            Err(_) => panic!("failed to bind santactl xpc listener socket: {path}"),
            Ok(socket) => socket,
        };
        // set the socket to non-blocking
        rx.set_nonblocking(nonblocking).expect("Couldn't set xpc socket to non-blocking");

        SantaXpcServer {rx}
    }

    // the socket should be non-blocking so we'll either get a connection
    // or move on and try again on the next iteration
    pub fn recv(&self) -> Option<String> {
        if let Ok((mut client, _)) = self.rx.accept() {
            let mut data = String::new();
            match client.read_to_string(&mut data) {
                Ok(_) => return Some(data),
                Err(_) => {
                    eprintln!("failed to parse message to string");
                    return None
                }
            }
        } else {
            None
        }
    }
}

/// A client-side Unix socket
pub struct SantaXpcClient {
    tx: UnixStream, // where we send messages
}

impl SantaXpcClient {
    pub fn new(path: String) -> SantaXpcClient {
        // set up the socket connection for sending responses?
        let sockpath = std::path::Path::new(&path);
        // connect the socket
        let tx = match UnixStream::connect(sockpath) {
            Ok(asdf) => {asdf},
            Err(_) => panic!("couldn't connect to daemon socket, is it running?"),
        };
        // set the socket to non-blocking
        tx.set_nonblocking(true).expect("Couldn't set xpc socket to non-blocking");

        // return sock
        SantaXpcClient {tx}
    }

    pub fn send(&mut self, msg: &[u8]) -> std::io::Result<()> {
        if msg.len() > 1023 {
            let err = Error::new(ErrorKind::InvalidInput,
                                "Message too long, not sending (limit is 1024 bytes)");
            return Err(err)
        }

        // send the message
        self.tx.write_all(msg).unwrap();
        Ok(())
    }
}
