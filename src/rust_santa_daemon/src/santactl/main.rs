// Local imports
use libsanta::uxpc::SantaXpcClient;
use libsanta::XPC_SOCKET_PATH;

fn main() {
    // create the client socket
    let mut client = SantaXpcClient::new(String::from(XPC_SOCKET_PATH));
    client.send(b"status").unwrap();
}
