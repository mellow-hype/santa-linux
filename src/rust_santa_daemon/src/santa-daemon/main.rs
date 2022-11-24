/// Rust implementation of the Santa daemon
mod daemon;
mod netlink;
mod engine;
mod tracer;
mod cache;

use std::{
    error::Error,
    fs::OpenOptions,
    path::{PathBuf, Path}
};

use daemonize::Daemonize;
use clap::Parser;
use nix::unistd::Pid;
use nix::sys::wait::{WaitStatus, self};

use libsanta::{
    {SantaMode, Loggable, LoggerSource, Jsonify},
    uxpc::SantaXpcClient,
    consts::{SANTAD_NAME, XPC_CLIENT_PATH},
    engine_types::{PolicyDecision, PolicyEnginePathTarget},
    commands::{
        SantaCtlCommand,
        CommandTypes,
        RuleAction,
        RuleCommand,
        FileInfoCommand,
        StatusCommand,
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

// Check for a uxpc message and handle it if there is one
fn santactl_worker(mut daemon: SantaDaemon) -> SantaDaemon {
    if let Some(data) = daemon.xpc_rx.recv() {
        if let Ok(payload) = serde_json::from_str::<SantaCtlCommand>(&data) {
            match &payload.ctype {
                CommandTypes::Rule => {
                    if let Ok(cmd) = serde_json::from_str::<RuleCommand>(&payload.command) {
                        let msg;
                        match cmd.action {
                            // Insert rules command
                            RuleAction::Insert => {
                                let what_happened = daemon.engine.rules.add_rule(&cmd.target, cmd.policy);
                                match cmd.target {
                                    RuleCommandInputType::Hash(hash) => {
                                        msg = format!(
                                            "{} rule for hash {}: {}", 
                                            what_happened, hash, cmd.policy
                                        );
                                    },
                                    RuleCommandInputType::Path(p) => {
                                        msg = format!(
                                            "{} rule for file {}: {}", 
                                            what_happened, p.display(), cmd.policy
                                        );
                                    },
                                }
                            },
                            // Remove rules command
                            RuleAction::Remove => {
                                if let Some(what_happened) = 
                                    daemon.engine.rules.remove_rule(&cmd.target) {
                                        match cmd.target {
                                            RuleCommandInputType::Hash(hash) => {
                                                msg = format!(
                                                    "{} rule for hash: {}", what_happened, hash);
                                            },
                                            RuleCommandInputType::Path(p) => {
                                                msg = format!(
                                                    "{} rule for hash of file: {}", 
                                                    what_happened, p.display()
                                                );
                                            },
                                        }
                                } else {
                                    match cmd.target {
                                        RuleCommandInputType::Hash(hash) => {
                                            msg = format!("No rule for hash '{}'", hash);
                                        },
                                        RuleCommandInputType::Path(p) => {
                                            msg = format!(
                                                "No rule for hash of file: {}", p.display()
                                            );
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
                            eprintln!(
                                "{SANTAD_NAME}: Failed to send message to XPC client - {err}"
                            );
                        }
                        return daemon;
                    }
                },
                CommandTypes::FileInfo => {
                    if let Ok(cmd) = serde_json::from_str::<FileInfoCommand>(&payload.command) {
                        let path = PathBuf::from(&cmd.path);
                        if !path.exists() {
                            eprintln!(
                                "{SANTAD_NAME}:FileInfoHandler | File not found - {}", 
                                cmd.path.display()
                            )
                        }
                        let target = PolicyEnginePathTarget::FilePath(path);
                        let answer = daemon.check(&target).jsonify_pretty();
                        let mut xclient = SantaXpcClient::new(XPC_CLIENT_PATH);
                        if let Err(err) = xclient.send(answer.as_bytes()) {
                            eprintln!(
                                "{SANTAD_NAME}: Failed to send message to XPC client - {err}"
                            );
                        }
                        return daemon
                    }
                },
                CommandTypes::Status => {
                    if let Ok(_) = serde_json::from_str::<StatusCommand>(&payload.command) {
                        let status = daemon.status().jsonify_pretty();
                        let mut xclient = SantaXpcClient::new(XPC_CLIENT_PATH);
                        if let Err(err) = xclient.send(status.as_bytes()) {
                            eprintln!("{SANTAD_NAME}: Failed to send message to XPC client - {err}");
                        }
                    } 
                },
            }
        } else {
            eprintln!("Invalid message format for : {}", data);
        }
    };
    daemon
}

// Check for a netlink message and handle it if there is one
fn netlink_worker(mut daemon: SantaDaemon) -> SantaDaemon {
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
                            Err(e) => {
                                eprintln!("{}", e.to_string());
                                return daemon
                            }
                        };

                        match tracer::attacher(Pid::from_raw(pid)) {
                            Ok(_) => {
                                // println!("{SANTAD_NAME}: attached to pid {pid}");
                                match wait::waitpid(Pid::from_raw(pid), None) {
                                    Ok(WaitStatus::Exited(_,code)) => {
                                        // what should we do if the process exited?
                                        eprintln!(
                                            "{}: pid {} exited with code {}",
                                            SANTAD_NAME, pid, code
                                        );
                                    },
                                    Ok(WaitStatus::Stopped(p, _sig)) => {
                                        // this means we attached and have control of the process
                                        // println!("{SANTAD_NAME}: pid {pid} stopped with {}", sig);
                                        let target = PolicyEnginePathTarget::from(pid as u32);
                                        // get an answer
                                        let answer = daemon.check(&target);
                                        // log the answer
                                        answer.log(LoggerSource::SantaDaemon);

                                        // kill the process if it should be blocked
                                        if let PolicyDecision::Block = answer.decision {
                                            if let Err(_e) = tracer::detacher(p) {
                                                eprintln!("{SANTAD_NAME}: {_e}");
                                            };
                                            // println!("{SANTAD_NAME}: detached from pid {pid}");
                                            daemon.engine.kill(p.as_raw());
                                            println!("{SANTAD_NAME}: killed pid {p}");
                                            return daemon
                                        } else {
                                            if let Err(_e) = tracer::detacher(p) {
                                                eprintln!("{SANTAD_NAME}: {_e}")
                                            };
                                            // println!("{SANTAD_NAME}: detached from pid {pid}");
                                        }
                                    },
                                    Ok(_) => {
                                        eprintln!(
                                            "{}: Unexpected signal while waiting to attach pid {}", 
                                                SANTAD_NAME, pid);
                                    },
                                    Err(_) => {
                                        eprintln!("{}: error while waiting for pid {}",
                                                SANTAD_NAME, pid);
                                    }
                                }
                            }
                            Err(_e) => {
                                // we failed to attach to the process with ptrace, we'll let it 
                                // race the daemon for now
                                eprintln!("{SANTAD_NAME}: {_e}");
                                let target = PolicyEnginePathTarget::from(pid as u32);
                                let answer = daemon.check(&target);
                                // log the answer
                                answer.log(LoggerSource::SantaDaemon);
                                // kill the process if it should be blocked
                                if let PolicyDecision::Block = answer.decision {
                                    daemon.engine.kill(pid);
                                }
                                return daemon
                            }
                        }
                    },
                    _ => {
                        eprintln!("{SANTAD_NAME}: received unknown command");
                    }
                }
            }
        },
        Err(err) => eprintln!("{SANTAD_NAME}: netlink recv error - {err}"),
    }
    daemon
}

/// The main worker loop that handles incoming messages
fn worker_loop() -> Result<(), Box<dyn Error>> {
    // instantiate the daemon instance
    let mut daemon = SantaDaemon::new(SantaMode::Monitor)?;

    // do stuff forever
    loop {
        // Check for messages from the kernel on the netlink socket
        daemon = santactl_worker(daemon);
        // Check for messages from santactl on the unix socket
        daemon = netlink_worker(daemon);
    };
}


/// Main
fn main() -> Result<(), ()> {
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
