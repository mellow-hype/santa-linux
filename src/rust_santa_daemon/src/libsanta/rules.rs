// std imports
use std::fmt;
use std::fs;
use std::path::PathBuf;
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use rustc_hash::FxHashMap;

// local imports
use crate::Jsonify;
use crate::commands::RuleCommandInputType;
use crate::consts::{SANTAD_NAME, RULES_DB_PATH, SANTA_BASE_PATH};
use crate::engine_types::PolicyDecision;
use crate::hash_file_at_path;


/// Read the default rules database file
fn read_rules_db_file() -> Result<FxHashMap<String, RuleTypes>, String> {
    // Read the file
    if let Ok(rules_json) = fs::read_to_string(RULES_DB_PATH) {
        // Read the JSON contents of the file as a hashmap.
        let rules = serde_json::from_str(&rules_json);
        if let Ok(rules_json) = rules {
            return Ok(rules_json)
        } else {
            let msg = format!("{SANTAD_NAME}: Failed to parse JSON to hashmap");
            eprintln!("{}", msg.to_string());
            Err(msg.to_string())
        }
    // Something went wrong
    } else {
        let msg = format!("{SANTAD_NAME}: Failed to read file to string: {RULES_DB_PATH}");
        eprintln!("{}", msg);
        Err(msg.to_string())
    }
}

/// Write a RuleDb instance out to the default rules path
fn write_json_to_file<J: Jsonify>(rules: &J, path: &str) {
    // do some checks to be sure parent dirs all exist before we do fs::write()
    let filepath = PathBuf::from(path);
    if !filepath.exists() {
        // this expect is safe because the try_exists() call would return true if path was "/"
        // (which is the only path that would cause the parent() call to fail)
        let parent = filepath.parent().expect("path should not be /");
        if !parent.exists() {
            if let Err(_) = std::fs::create_dir_all(parent) {
                eprintln!("{SANTAD_NAME}: Could not create directory at {}", parent.display());
            }
        }

    }
    // serialize the rules to pretty json and write to the file
    let current_rules_json = format!("{}\n", rules.jsonify_pretty());
    // this expect is safe because parent dirs that didn't exist should have been created above
    fs::write(path, current_rules_json).expect("parent dirs should exist");
}

/// PolicyRule: an emum for the different type of rules that can exist
#[derive(Deserialize, Serialize, Debug, Clone, Copy, ValueEnum)]
pub enum RuleTypes {
    Allow,
    Block,
}
/// Display trait for PolicyRule
impl fmt::Display for RuleTypes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleTypes::Allow => write!(f, "ALLOW"),
            RuleTypes::Block => write!(f, "BLOCK"),
        }
    }
}

/// PolicyEngineRuleTarget: ffff that represents the different types of rule targets
pub enum PolicyEngineRuleTarget {
    Path(PathBuf),
    ShaHash(String),
}


#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct RulesDb (pub FxHashMap<String, RuleTypes>);
impl Jsonify for RulesDb {}

impl RulesDb {
    pub fn new() -> RulesDb {
        // check if the rules file exits
        let rules_filepath = std::path::PathBuf::from(RULES_DB_PATH);
        if !rules_filepath.exists() {
            // it doesn't so lets check if the parent directory exists and create it if not
            let santa_path = std::path::PathBuf::from(SANTA_BASE_PATH);
            if !santa_path.exists() {
                if let Err(_) = std::fs::create_dir(santa_path) {
                    eprintln!("Could not create santa directory at {SANTA_BASE_PATH}");
                }
            }
            // create an empty rules file
            if let Err(_) = std::fs::File::create(rules_filepath.as_path()) {
                eprintln!("Could not create empty rules file");
            }
            // return the empty db, we don't need to read an empty rules db
            RulesDb(FxHashMap::default())
        } else {
            // the rules DB file already existed, read it
            if let Ok(rules) = read_rules_db_file() {
                RulesDb(rules)
            } else {
                RulesDb(FxHashMap::default())
            }
        }
    }
    /// Sync the daemon's ruleset back to the rules db file
    fn sync_rules(&self) {
        write_json_to_file(self, RULES_DB_PATH)
    }

    /// Add a new rule
    pub fn add_rule(&mut self, hash: &RuleCommandInputType, rule: RuleTypes) -> String {
        match hash {
            RuleCommandInputType::Hash(val) => {
                println!("{SANTAD_NAME}: adding {} rule for hash {val}",
                        PolicyDecision::from(rule).to_string());

                let _ = match self.0.insert(val.to_string(), rule) {
                    Some(old) => {
                        // we updated an existing rule
                        self.sync_rules();
                        return format!("Updated existing {}", old.to_string())
                    }, 
                    None => {
                        // we inserted a new rule
                        self.sync_rules();
                        return "Inserted".to_string()
                    },
                };
            },
            RuleCommandInputType::Path(val) => {
                if let Some(hash) = hash_file_at_path(&val) {
                    let _ = match self.0.insert(hash.to_string(), rule) {
                        Some(old) => {
                            // we updated an existing rule
                            self.sync_rules();
                            return format!("Updated existing {}", old)
                        }, 
                        None => {
                            // we inserted a new rule
                            self.sync_rules();
                            return "Inserted".to_string()
                        },
                    };
                } else {
                    eprintln!("failed to hash file at path: {}", val.display());
                    return "Failed to insert".to_string()
                }
            },
        }
    }

    /// Remove a rule
    pub fn remove_rule(&mut self, hash: &RuleCommandInputType) -> Option<&'static str> {
        match hash {
            RuleCommandInputType::Hash(val) => {
                println!("{SANTAD_NAME}: removing rule for hash {val}");
                if let Some(_) = self.0.remove(val) {
                    self.sync_rules();
                    return Some("Removed")
                }
                None
            },
            RuleCommandInputType::Path(val) => {
                if let Some(hash) = hash_file_at_path(&val) {
                    if let Some(_) = self.0.remove(&hash) {
                        self.sync_rules();
                        return Some("Removed")
                    }
                    None
                } else {
                    eprintln!("failed to hash file at path: {}", val.display());
                    return Some("Failed to hash file at path while attempting to remove")
                }
            },
        }
    }
}
