// Local imports
use libsanta::uxpc::{SantaXpcClient, SantaXpcServer};
use libsanta::{XPC_SOCKET_PATH, XPC_CLIENT_PATH};
use std::time::Duration;
use std::thread;

fn main() {
    let path = String::from(XPC_CLIENT_PATH);
    let server = SantaXpcServer::new(path, false);

    // send the command msg in a thread
    thread::spawn(move || {
        // create the client socket and send the message
        let mut client = SantaXpcClient::new(String::from(XPC_SOCKET_PATH));
        client.send(b"status").unwrap();

        // sleep to give the listener a chance to recv the message
        thread::sleep(Duration::from_millis(50));
    });

    // sleep to give the sender thread a chance to send the message
    thread::sleep(Duration::from_millis(50));

    // wait for the response
    if let Some(asdf) = server.recv() {
        println!("{asdf}");
    }
}
