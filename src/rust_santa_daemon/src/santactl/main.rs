// Local imports
use libsanta::uxpc::{SantaXpcClient, SantaXpcCtlServer};
use libsanta::{XPC_SOCKET_PATH, XPC_CLIENT_PATH};
use fork::{Fork, daemon};

fn main() {
    let path = String::from(XPC_CLIENT_PATH);
    let server = SantaXpcCtlServer::new(path, false);

    // create the server socket in a child process
    if let Ok(Fork::Child) = daemon(false, true) {
        loop {
            if let Some(asdf) = server.recv() {
                println!("santactl xpc server socket got: {asdf}")
            }
        }
    }

    // create the client socket
    let mut client = SantaXpcClient::new(String::from(XPC_SOCKET_PATH));
    client.send(b"status").unwrap();
}
