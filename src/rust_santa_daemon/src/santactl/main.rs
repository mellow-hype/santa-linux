use std::thread;
use std::{time::Duration, path::PathBuf};
use clap::{Parser, Subcommand};

// Local imports
use libsanta::{
    Jsonify,
    consts::{XPC_SOCKET_PATH, XPC_CLIENT_PATH},
    rules::RuleTypes,
    uxpc::{SantaXpcClient, SantaXpcServer},
    commands::{
        CommandTypes,
        SantaCtlCommand,
        RuleAction,
        StatusCommand,
        FileInfoCommand,
        RuleCommandInputType,
        RuleCommand
    },
};

#[allow(dead_code)]
fn sender_msg_thread<T: Jsonify>(msg: T) {
    // create the client socket and send the message
    let mut client = SantaXpcClient::new(XPC_SOCKET_PATH);
    let serial_bytes = msg.jsonify();
    client.send(serial_bytes.as_bytes()).unwrap();

    // sleep to give the listener a chance to recv the message
    thread::sleep(Duration::from_millis(1));
}

// Validator for sha256 hash strings given in args
fn hash_validator(s: &str) -> Result<String, String> {
    if s.len() > 64 {
        return Err("Invalid hash: too long".to_string());
    } else if s.len() < 64 {
        return Err("Invalid hash: too short".to_string());
    }
    let x = "abcdef1234567890ABCDEF";
    for hash_c in s.chars() {
        if !x.contains(hash_c) {
            return Err("Invalid character in hash".to_string())
        }
    }
    Ok(s.to_string())
}

/// santactl is used to interact with the santa-daemon
#[derive(Parser)]
struct Cli {
    /// Subcommands 
    #[command(subcommand)]
    command: SubCommands,
}

// Top-level Santactl subcommands
#[derive(Subcommand)]
pub enum SubCommands {
    /// Get status info from the daemon
    Status,
    /// Analyze and get info on a target file
    Fileinfo {
        path: PathBuf,
    },
    /// Manage the daemon's ruleset
    Rule {
        #[command(subcommand)]
        action: RuleSubCommands,
    }
}

// Santactl rule subcommands
#[derive(Subcommand)]
pub enum RuleSubCommands {
    /// Show rules
    Show,
    /// Insert a rule
    #[command(group(clap::ArgGroup::new("ver")
        .required(true)
        .args(["block", "allow"])
        ),
        group(clap::ArgGroup::new("ver2")
            .required(true)
            .args(["file", "sha"])
        )
    )]
    Insert {
        /// Create an allow rule
        #[arg(short, long, action, required=false)]
        allow: bool,
        /// Create an block rule
        #[arg(short, long, action, required=false)]
        block: bool,
        /// Insert a rule by hashing the given file
        #[arg(short, long, required=false, value_parser = clap::value_parser!(PathBuf))]
        file: Option<PathBuf>,
        /// Insert a rule for a SHA256 hash
        #[arg(short, long, value_name="SHA256", required=false, value_parser = hash_validator)]
        sha: Option<String>,
    },
    /// Remove a rule
    Remove {
        hash: String,
    },
}

fn main() {
    let args = Cli::parse();
    let cmd;
    match &args.command {
        SubCommands::Status => {
            let stat = StatusCommand {};
            cmd = SantaCtlCommand {
                ctype: CommandTypes::Status,
                command: stat.jsonify(),
            };
        }
        SubCommands::Fileinfo { path } => {
            if !path.exists() {
                eprintln!("Path not found: {}\n", path.display());
                return
            }
            
            let fileinfo = FileInfoCommand { path: path.to_owned() };
            cmd = SantaCtlCommand {
                ctype: CommandTypes::FileInfo,
                command: fileinfo.jsonify(),
            };
        }
        SubCommands::Rule { action } => {
            match action {
                // Insert rule command
                RuleSubCommands::Insert { file: path, sha: hash, allow, block:_ } => {
                    if let Some(p) = path {
                        // we have to have been given a path
                        if !p.exists() {
                            eprintln!("Path not found: {}", p.display());
                            return
                        }
                        let rulecmd = RuleCommand {
                            action: RuleAction::Insert,
                            target: RuleCommandInputType::Path(p.clone()),
                            policy: (if *allow {RuleTypes::Allow} else {RuleTypes::Block}),
                        };
                        cmd = SantaCtlCommand {
                            ctype: CommandTypes::Rule,
                            command: rulecmd.jsonify(),
                        }
                    } else if let Some(h) = hash {
                        let rulecmd = RuleCommand {
                            action: RuleAction::Insert,
                            target: RuleCommandInputType::Hash(h.clone()),
                            policy: (if *allow {RuleTypes::Allow} else {RuleTypes::Block}),
                            // policy: *rule,
                        };
                        cmd = SantaCtlCommand {
                            ctype: CommandTypes::Rule,
                            command: rulecmd.jsonify(),
                        }
                    } else {
                        unreachable!()
                    } 
                },
                // Remove rule command
                RuleSubCommands::Remove { hash } => {
                    let rule = RuleTypes::Allow; // won't be used
                    let rulecmd = RuleCommand {
                        action: RuleAction::Remove,
                        target: RuleCommandInputType::Hash(String::from(hash)),
                        policy: rule,
                    };
                    cmd = SantaCtlCommand {
                        ctype: CommandTypes::Rule,
                        command: rulecmd.jsonify(),
                    }
                },
                RuleSubCommands::Show {} => {
                    let rulecmd = RuleCommand {
                        action: RuleAction::Show,
                        target: RuleCommandInputType::Hash(String::from("")),
                        policy: RuleTypes::Allow, // won't be used, but need a value
                    };
                    cmd = SantaCtlCommand {
                        ctype: CommandTypes::Rule,
                        command: rulecmd.jsonify(),
                    }
                },
            }
        }
    }

    // create the XPC server socket
    let server = SantaXpcServer::new(XPC_CLIENT_PATH, false);

    // send the command msg in a thread
    thread::spawn(move || {
        // create the client socket and send the message
        let mut client = SantaXpcClient::new(XPC_SOCKET_PATH);
        let serial_bytes = cmd.jsonify();
        client.send(serial_bytes.as_bytes()).unwrap();

        // sleep to give the listener a chance to recv the message
        thread::sleep(Duration::from_millis(1));
    });

    // sleep to give the sender thread a chance to send the message
    thread::sleep(Duration::from_millis(1));

    // wait for the response
    if let Some(result) = server.recv() {
        println!("{result}");
    }
}
