/// Rust implementation of the Santa daemon
mod daemon;
mod netlink;
mod engine;

use std::error::Error;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

use daemonize::Daemonize;
use clap::Parser;

use libsanta::{SantaMode, Loggable, LoggerSource, Jsonify};
use libsanta::{
    consts::{SANTAD_NAME, XPC_CLIENT_PATH},
    uxpc::SantaXpcClient,
    engine_types::{PolicyDecision, PolicyEnginePathTarget},
    commands::{SantaCtlCommand,
        RuleCommand,
        FileInfoCommand,
        CommandTypes,
        RuleAction,
        RuleCommandInputType,
    },
};
use daemon::SantaDaemon;
use netlink::NlSantaCommand;

pub const SANTA_LOG: &str = "/var/log/santad.log";
pub const SANTA_ERRLOG: &str = "/var/log/santad_err.log";

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
                        NlSantaCommand::MsgDoHash => {
                            // parse the pid from the payload
                            let pid: i32 = match payload.parse() {
                                Ok(p) => p,
                                Err(_) => {
                                    eprintln!("Failed to parse PID from payload");
                                    continue
                                }
                            };
                            let target = PolicyEnginePathTarget::from(pid as u32);
                            // get an answer
                            let answer = daemon.engine.analyze(&target);
                            // log the answer
                            answer.log(LoggerSource::SantaDaemon);

                            // kill the process if it should be blocked
                            if let PolicyDecision::Block = answer.decision {
                                daemon.engine.kill(pid);
                            }

                            // let the kernel know we're done, don't expect a response
                            daemon.netlink.send_cmd(&NlSantaCommand::MsgHashDone, &"")?;
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
                    // Status command
                    CommandTypes::Status => {
                        let status = daemon.engine.status().jsonify_pretty();
                        let mut xclient = SantaXpcClient::new(XPC_CLIENT_PATH);
                        if let Err(err) = xclient.send(status.as_bytes()) {
                            eprintln!("{SANTAD_NAME}: Failed to send message to XPC client - {err}")
                        }
                    },
                    // Fileinfo command
                    CommandTypes::FileInfo => {
                        if let Ok(cmd) = serde_json::from_str::<FileInfoCommand>(&_asdf.command) {
                            let path = PathBuf::from(&cmd.path);
                            if !path.exists() {
                                eprintln!("{SANTAD_NAME}:FileInfoHandler | File not found - {}", cmd.path.display());
                                continue;
                            }
                            let target = PolicyEnginePathTarget::FilePath(path);
                            let answer = daemon.engine.analyze(&target).jsonify_pretty();
                            let mut xclient = SantaXpcClient::new(XPC_CLIENT_PATH);
                            if let Err(err) = xclient.send(answer.as_bytes()) {
                                eprintln!("{SANTAD_NAME}: Failed to send message to XPC client - {err}")
                            }
                        } else {
                            eprintln!("Invalid message format for FileInfoCommand: {}", _asdf.command)
                        }
                    },
                    // Rule command
                    CommandTypes::Rule => {
                        if let Ok(_cmd) = serde_json::from_str::<RuleCommand>(&_asdf.command) {
                            let msg;
                            match _cmd.action {
                                // Insert rules command
                                RuleAction::Insert => {
                                    let what_happened = daemon.engine.add_rule(&_cmd.target, _cmd.policy);
                                    match _cmd.target {
                                        RuleCommandInputType::Hash(hash) => {
                                            msg = format!("{} rule for hash {}: {}", 
                                                          what_happened, hash, _cmd.policy);
                                        },
                                        RuleCommandInputType::Path(p) => {
                                            msg = format!("{} rule for file {}: {}", 
                                                          what_happened, p.display(), _cmd.policy);
                                        },
                                    }
                                },
                                // Remove rules command
                                RuleAction::Remove => {
                                    if let Some(what_happened) = daemon.engine.remove_rule(&_cmd.target){
                                        match _cmd.target {
                                            RuleCommandInputType::Hash(hash) => {
                                                msg = format!("{} rule for hash: {}", 
                                                            what_happened, hash);
                                            },
                                            RuleCommandInputType::Path(p) => {
                                                msg = format!("{} rule for hash of file: {}", 
                                                            what_happened, p.display());
                                            },
                                        }
                                    } else {
                                        match _cmd.target {
                                            RuleCommandInputType::Hash(hash) => {
                                                msg = format!("No rule for hash '{}'", hash);
                                            },
                                            RuleCommandInputType::Path(p) => {
                                                msg = format!("No rule for hash of file: {}", p.display());
                                            },
                                        }
                                    }
                                },
                                // Show rules command
                                RuleAction::Show => {
                                    msg = daemon.engine.rules.jsonify_pretty();
                                },
                            }
                            let mut xclient = SantaXpcClient::new(XPC_CLIENT_PATH);
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
    println!("{SANTAD_NAME}: Entering main message processing loop...");

    // determine whether we should fork to the background or run normally
    if args.daemonize {
        // stderr output file
        let stderr_path = Path::new(SANTA_ERRLOG);
        let stderr = match OpenOptions::new().append(true).create(true).open(stderr_path) {
            Ok(file) => {file},
            Err(e) => {
                eprintln!("Error: {e}");
                return Ok(())
            },
        };

        // stdout output file
        let stdout_path = Path::new(SANTA_LOG);
        let stdout = match OpenOptions::new().append(true).create(true).open(stdout_path) {
            Ok(file) => {file},
            Err(e) => {
                eprintln!("Error: {e}");
                return Ok(())
            },
        };

        // create the daemon instance with stdout/stderr redirection
        let daemonized = Daemonize::
            new()
            .stderr(stderr)
            .stdout(stdout);
        
        // start up
        match daemonized.start() {
            Ok(_) => {
                println!("Successfully daemonized the santad process...");
                if let Err(err) = worker_loop() {
                    eprintln!("Error encountered during the main processing loop: {err}");
                }
            }
            Err(err) => eprintln!("Failed to daemonize the process: {err}"),
        };
    } else {
        // we're not daemoizing, do stuff forever
        if let Err(err) = worker_loop() {
            eprintln!("Error encountered during the main processing loop: {err}");
        }
    }

    Ok(())
}
