use std::time::Duration;
use std::thread;
use clap::{Parser, Subcommand};

// Local imports
use libsanta::Jsonify;
use libsanta::consts::{XPC_SOCKET_PATH, XPC_CLIENT_PATH};
use libsanta::engine::PolicyRule;
use libsanta::uxpc::{SantaXpcClient, SantaXpcServer};
use libsanta::commands::{CommandTypes, SantaCtlCommand, RuleAction, StatusCommand, FileInfoCommand, RuleCommand};

/// santactl is used to interact with the santa-daemon
#[derive(Parser)]
struct Cli {
    /// Subcommands 
    #[command(subcommand)]
    command: SubCommands,
}

#[derive(Subcommand)]
pub enum RuleSubCommands {
    /// Show rules
    Show,
    /// Insert rules
    Insert {
        /// Rule type
        #[arg(value_enum)]
        rule: PolicyRule,
        /// SHA256 hash
        hash: String,
    },
    /// Delete rules
    Delete {
        hash: String,
    },
}

#[derive(Subcommand)]
pub enum SubCommands {
    /// Get status info from the daemon
    Status,
    /// Analyze and get info on a target file
    Fileinfo {
        #[arg(short, long)]
        path: String,
    },
    /// Manage the daemon's ruleset
    Rule {
        #[command(subcommand)]
        action: RuleSubCommands,
    }
}

#[allow(dead_code)]
fn sender_thread_v2<T: Jsonify>(msg: T) {
    // create the client socket and send the message
    let mut client = SantaXpcClient::new(String::from(XPC_SOCKET_PATH));
    let serial_bytes = msg.jsonify();
    client.send(serial_bytes.as_bytes()).unwrap();

    // sleep to give the listener a chance to recv the message
    thread::sleep(Duration::from_millis(50));
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
            let fileinfo = FileInfoCommand { path: String::from(path)};
            cmd = SantaCtlCommand {
                ctype: CommandTypes::FileInfo,
                command: fileinfo.jsonify(),
            };
        }
        SubCommands::Rule { action } => {
            match action {
                RuleSubCommands::Insert { hash, rule } => {
                    let rulecmd = RuleCommand {
                        action: RuleAction::Insert,
                        hash: String::from(hash),
                        policy: *rule,
                    };
                    cmd = SantaCtlCommand {
                        ctype: CommandTypes::Rule,
                        command: rulecmd.jsonify(),
                    }
                },
                RuleSubCommands::Delete { hash } => {
                    let rule = PolicyRule::Allow; // won't be used
                    let rulecmd = RuleCommand {
                        action: RuleAction::Remove,
                        hash: String::from(hash),
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
                        hash: String::from(""),
                        policy: PolicyRule::Allow, // won't be used, but need a value
                    };
                    cmd = SantaCtlCommand {
                        ctype: CommandTypes::Rule,
                        command: rulecmd.jsonify(),
                    }
                },
            }
        }
    }

    let path = String::from(XPC_CLIENT_PATH);
    let server = SantaXpcServer::new(path, false);
    // send the command msg in a thread
    thread::spawn(move || {
        sender_thread_v2(cmd);
    });

    // sleep to give the sender thread a chance to send the message
    thread::sleep(Duration::from_millis(50));

    // wait for the response
    if let Some(asdf) = server.recv() {
        println!("{asdf}");
    }
}
