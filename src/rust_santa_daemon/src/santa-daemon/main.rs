/// Rust implementation of the Santa daemon
use std::error::Error;
use std::fs::File;

use daemonize::Daemonize;
use clap::Parser;

use libsanta::{SANTAD_NAME, XPC_CLIENT_PATH, STATUS_CMD, SantaMode};
use libsanta::netlink::{NlSantaCommand, NlSantaAttribute};
use libsanta::daemon::SantaDaemon;
use libsanta::engine::PolicyEngineStatus;
use libsanta::uxpc::SantaXpcClient;

/// Cli argument parser via clap
#[derive(Parser)]
struct Cli {
    /// Whether the process should daemonize or not 
    #[arg(short, long, action)]
    daemonize: bool,
}

fn worker_loop() -> Result<(), Box<dyn Error>> {
    // instantiate the daemon instance
    let mut daemon = SantaDaemon::new(SantaMode::Monitor);

    // do stuff forever
    loop {
        // Check for messages from the kernel on the netlink socket
        if let Some(nlmsg) = daemon.netlink.recv() {
            // we got a request, parse the payload
            let res = nlmsg;
            if let Ok(msg) = res.get_payload() {
                // get the command and a handle to the attributes
                let cmd: NlSantaCommand = msg.cmd;
                let attr_handle = msg.get_attr_handle();

                // Handle commands
                match cmd {
                    NlSantaCommand::Msg => {
                        // parse out payload
                        match attr_handle
                            .get_attr_payload_as_with_len::<String>(NlSantaAttribute::Msg) {
                            Ok(pid) => {
                                // get an answer
                                let answer = daemon.engine.analyze(&pid);
                                // log the answer
                                answer.log();
                                // let the kernel know we're done, don't expect a response
                                daemon.netlink.send_cmd(NlSantaCommand::MsgHashDone, &"")?;
                            },
                            Err(_) => eprintln!("{SANTAD_NAME}: invalid message form"),
                        }
                    },
                    _ => eprintln!("{SANTAD_NAME}: received unknown command"),
                }
            } else {
                eprintln!("{SANTAD_NAME}: Failed to read paylod from generic netlink message");
            }
        };
        // Check for messages on the xpc socket
        if let Some(data) = daemon.xpc_rx.recv() {
            match &data[..] {
                STATUS_CMD => {
                    let status: PolicyEngineStatus = daemon.engine.get_status();
                    let status_json = serde_json::to_string_pretty(&status)
                        .expect("should be able to pretty print json string");
                    let mut xclient = SantaXpcClient::new(String::from(XPC_CLIENT_PATH));
                    xclient.send(status_json.as_bytes()).expect("daemon sent message to client");
                },
                _ => {},
            };
        };
    };
}

/// Main
fn main() -> Result<(), Box<dyn Error>> {
    // Parse command-line args
    let args = Cli::parse();

    // determine whether we should fork to the background or run normally
    println!("{SANTAD_NAME}: Entering main message processing loop...");
    match args.daemonize {
        true => {
            let stderr = File::create("/var/log/santad_err.log")
                .expect("should have write access to /var/log");
            let stdout = File::create("/var/log/santad.log")
                .expect("should have write access to /var/log");
            let daemonized = Daemonize::new()
                .stderr(stderr)
                .stdout(stdout);

            // main loop
            match daemonized.start() {
                Ok(_) => {
                    println!("Successfully daemonized the santad process...");
                    // do stuff forever
                    worker_loop().unwrap();
                }
                Err(err) => eprintln!("Failed to daemonize the process: {err}"),
            };
        },
        false => {
            // do stuff forever
            worker_loop().unwrap();
        },
    };
    Ok(())
}
