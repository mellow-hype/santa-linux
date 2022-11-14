use crate::engine::PolicyRule;
use crate::Jsonify;
use serde::{Deserialize, Serialize};
use clap::Subcommand;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum CommandTypes {
    Status,
    FileInfo,
    Rule,
}

#[derive(Subcommand, Serialize, Deserialize, Debug, Clone, Copy)]
pub enum RuleAction {
    Insert,
    Remove,
    Show,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RuleCommand {
    pub action: RuleAction,
    pub hash: String,
    pub policy: PolicyRule,
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