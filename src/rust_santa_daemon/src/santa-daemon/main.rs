/// Rust implementation of the Santa daemon
mod daemon;
use daemon::SantaDaemon;
use libsanta::commands::RuleAction;

use std::error::Error;
use std::fs::OpenOptions;
use std::path::Path;

use daemonize::Daemonize;
use clap::Parser;

use libsanta::{SantaMode, Loggable, LoggerSource, Jsonify};
use libsanta::{
    netlink::NlSantaCommand,
    commands::{SantaCtlCommand, RuleCommand, FileInfoCommand, CommandTypes},
    engine::{PolicyDecision, PolicyEngineTarget},
    uxpc::SantaXpcClient,
    consts::{SANTAD_NAME, XPC_CLIENT_PATH, SANTA_LOG, SANTA_ERRLOG},
};

/// santa-daemon
#[derive(Parser)]
struct Cli {
    /// Whether the process should daemonize or not 
    #[arg(short, long, action)]
    daemonize: bool,
}

/// The main worker loop that handles incoming messages
fn worker_loop() -> Result<(), Box<dyn Error>> {
    // instantiate the daemon instance
    let mut daemon = SantaDaemon::new(SantaMode::Monitor)?;

    // do stuff forever
    loop {
        // Check for messages from the kernel on the netlink socket
        match daemon.netlink.recv() {
            Ok(res) => {
                // No errors on the recv(), lets check if we got a message
                if let Some((cmd, payload)) = res {
                    match cmd {
                        NlSantaCommand::Msg => {
                            // get an answer
                            let target = PolicyEngineTarget::from(payload.clone());
                            let answer = daemon.engine.analyze(target);
                            // log the answer
                            answer.log(LoggerSource::SantaDaemon);

                            // kill the process if it should be blocked
                            if let PolicyDecision::Block = answer.decision {
                                daemon.engine.kill(String::from(payload));
                            }

                            // let the kernel know we're done, don't expect a response
                            daemon.netlink.send_cmd(NlSantaCommand::MsgHashDone, &"")?;
                        },
                        _ => eprintln!("{SANTAD_NAME}: received unknown command"),
                    }
                }
            },
            Err(err) => eprintln!("{SANTAD_NAME}: {err}"),
        }
        // Check for messages on the xpc socket
        if let Some(data) = daemon.xpc_rx.recv() {
            if let Ok(_asdf) = serde_json::from_str::<SantaCtlCommand>(&data) {
                match _asdf.ctype {
                    CommandTypes::Status => {
                        let status = daemon.engine.get_status().jsonify_pretty();
                        let mut xclient = SantaXpcClient::new(String::from(XPC_CLIENT_PATH));
                        if let Err(err) = xclient.send(status.as_bytes()) {
                            eprintln!("{SANTAD_NAME}: Failed to send message to XPC client - {err}")
                        }
                    },
                    CommandTypes::FileInfo => {
                        if let Ok(cmd) = serde_json::from_str::<FileInfoCommand>(&_asdf.command) {
                            let target = PolicyEngineTarget::from(cmd.path);
                            let answer = daemon.engine.analyze(target).jsonify_pretty();
                            let mut xclient = SantaXpcClient::new(String::from(XPC_CLIENT_PATH));
                            if let Err(err) = xclient.send(answer.as_bytes()) {
                                eprintln!("{SANTAD_NAME}: Failed to send message to XPC client - {err}")
                            }
                        } else {
                            eprintln!("Invalid message format for FileInfoCommand: {}", _asdf.command)
                        }
                    },
                    CommandTypes::Rule => {
                        if let Ok(_cmd) = serde_json::from_str::<RuleCommand>(&_asdf.command) {
                            let msg;
                            match _cmd.action {
                                RuleAction::Insert => {
                                    daemon.engine.add_rule(&_cmd.hash, _cmd.policy);
                                    msg = format!("Inserted {} rule for hash {}", _cmd.policy, _cmd.hash);
                                },
                                RuleAction::Remove => {
                                    daemon.engine.remove_rule(&_cmd.hash);
                                    msg = format!("Inserted {} rule for hash {}", _cmd.policy, _cmd.hash);
                                },
                                RuleAction::Show => {
                                    msg = daemon.engine.rules.jsonify_pretty();
                                },
                            }
                            let mut xclient = SantaXpcClient::new(String::from(XPC_CLIENT_PATH));
                            if let Err(err) = xclient.send(msg.as_bytes()) {
                                eprintln!("{SANTAD_NAME}: Failed to send message to XPC client - {err}")
                            }
                        } else {
                            eprintln!("Invalid message format for FileInfoCommand: {}", _asdf.command)
                        }
                    },
                }
            }
            else {
                eprintln!("Invalid message format for SantaCtlCommand: {}", data)
            }
        };
    };
}


/// Main
fn main() -> Result<(), Box<dyn Error>> {
    // Parse command-line args
    let args = Cli::parse();

    // determine whether we should fork to the background or run normally
    println!("{SANTAD_NAME}: Entering main message processing loop...");
    if args.daemonize {
        let stderr_path = Path::new(SANTA_ERRLOG);
        let stderr = match OpenOptions::new().append(true).create(true).open(stderr_path) {
            Ok(file) => {file},
            Err(e) => {
                eprintln!("Error: {e}");
                return Ok(())
            },
        };

        let stdout_path = Path::new(SANTA_LOG);
        let stdout = match OpenOptions::new().append(true).create(true).open(stdout_path) {
            Ok(file) => {file},
            Err(e) => {
                eprintln!("Error: {e}");
                return Ok(())
            },
        };

        // create the daemon instance with stdout/stderr redirection
        let daemonized = Daemonize::new()
            .stderr(stderr)
            .stdout(stdout);

        match daemonized.start() {
            Ok(_) => {
                // do stuff forever
                println!("Successfully daemonized the santad process...");
                worker_loop().unwrap();
            }
            Err(err) => eprintln!("Failed to daemonize the process: {err}"),
        };
    } else {
        // do stuff forever
        worker_loop().unwrap();
    }

    Ok(())
}
