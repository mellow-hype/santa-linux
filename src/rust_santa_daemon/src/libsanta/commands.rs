use crate::engine::PolicyRule;
use crate::Jsonify;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum CommandTypes {
    Status,
    FileInfo,
    Rule,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum RuleAction {
    Insert,
    Remove,
    Display,
    Unknown,
}

impl From<String> for RuleAction {
    fn from(action: String) -> RuleAction {
        match &action[..] {
            "show" => {
                RuleAction::Display
            },
            "insert" => {
                RuleAction::Display
            },
            "delete" => {
                RuleAction::Display
            },
            _ => {RuleAction::Unknown},
        }

    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RuleCommand {
    action: RuleAction,
    hash: Option<String>,
    policy: Option<PolicyRule>,
}
impl Jsonify for RuleCommand {}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StatusCommand {}
impl Jsonify for StatusCommand {}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileInfoCommand { pub path: String }
impl Jsonify for FileInfoCommand {}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SantaCtlCommand {
    pub ctype: CommandTypes,
    pub command: String,
}
impl Jsonify for SantaCtlCommand {}