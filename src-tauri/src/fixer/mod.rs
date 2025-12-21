use anyhow::{Context, Result};
use colored::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use crate::registry::RegistryHelper;

/// Expands environment variables in a path string.
/// Supports Windows-style `%VAR%` syntax.
fn expand_env_vars(path: &str) -> String {
    let mut result = path.to_string();
    while let Some(start) = result.find('%') {
        if let Some(end) = result[start + 1..].find('%') {
            let var_name = &result[start + 1..start + 1 + end];
            if let Ok(value) = env::var(var_name) {
                let pattern = format!("%{}%", var_name);
                result = result.replace(&pattern, &value);
            } else {
                break;
            }
        } else {
            break;
        }
    }

    result
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PathBackup {
    pub timestamp: String,
    pub user_path: String,
    pub system_path: Option<String>,
}

pub struct PathFixer {
    backup_dir: PathBuf,
}

impl PathFixer {
    pub fn new() -> Result<Self> {
        let local_app_data =
            env::var("LOCALAPPDATA").context("Failed to get LOCALAPPDATA environment variable")?;

        let backup_dir = PathBuf::from(local_app_data).join("spath").join("backups");

        fs::create_dir_all(&backup_dir).context("Failed to create backup directory")?;

        Ok(Self { backup_dir })
    }

    pub fn create_backup(&self) -> Result<PathBuf> {
        let user_path = RegistryHelper::read_user_path_raw()
            .context("Failed to read user PATH from registry")?;

        let system_path = RegistryHelper::read_system_path_raw().ok();
        let backup = PathBackup {
            timestamp: chrono::Local::now().format("%Y%m%d_%H%M%S").to_string(),
            user_path,
            system_path,
        };

        let backup_file = self
            .backup_dir
            .join(format!("path_backup_{}.json", backup.timestamp));
        let json = serde_json::to_string_pretty(&backup).context("Failed to serialize backup")?;
        fs::write(&backup_file, json).context("Failed to write backup file")?;

        println!(
            "{} {}",
            "Backup created:".green().bold(),
            backup_file.display()
        );
        Ok(backup_file)
    }

    pub fn fix_user_path(&self, dry_run: bool) -> Result<FixResults> {
        let current_path = RegistryHelper::read_user_path_raw()
            .context("Failed to read user PATH from registry")?;

        log::debug!("Current USER PATH: {}", current_path);
        let paths = RegistryHelper::parse_path_string(&current_path);
        log::info!("Found {} paths in USER PATH", paths.len());
        let mut fixed_paths = Vec::new();
        let mut changes = Vec::new();
        let mut seen = HashSet::new();

        for (i, path) in paths.iter().enumerate() {
            let trimmed = path.trim();
            log::debug!("Processing path {}: '{}'", i, trimmed);

            if seen.contains(trimmed) {
                log::info!("Found duplicate: {}", trimmed);
                changes.push(format!("Removed duplicate: {}", trimmed));
                continue;
            }
            seen.insert(trimmed.to_string());

            let path_to_check = trimmed.trim_matches('"');
            let exists = Path::new(path_to_check).exists();

            let should_remove = if !exists {
                if trimmed.contains('%') {
                    let expanded = expand_env_vars(trimmed);
                    let expanded_exists = Path::new(&expanded).exists();
                    !expanded_exists || expanded == trimmed
                } else {
                    true
                }
            } else {
                false
            };

            if should_remove {
                log::info!("Removing non-existent path: {}", trimmed);
                changes.push(format!("Removed non-existent: {}", trimmed));
                continue;
            }

            if trimmed.contains(' ') && !trimmed.starts_with('"') {
                log::info!("Found unquoted path with spaces: {}", trimmed);
                let quoted = format!("\"{}\"", trimmed);
                changes.push(format!("Added quotes: {} -> {}", trimmed, quoted));
                fixed_paths.push(quoted);
            } else {
                fixed_paths.push(trimmed.to_string());
            }
        }

        let new_path = fixed_paths.join(";");
        let changed = new_path != current_path;

        if !dry_run && changed {
            self.create_backup()?;
            RegistryHelper::write_user_path(&new_path)
                .context("Failed to write new PATH to registry")?;

            println!();
            println!("{}", "PATH has been fixed.".green().bold());
            println!(
                "{}",
                "  Note: You may need to restart applications for changes to take effect.".yellow()
            );
        }
        Ok(FixResults { changes })
    }

    pub fn list_backups(&self) -> Result<Vec<PathBuf>> {
        let mut backups = Vec::new();

        if !self.backup_dir.exists() {
            return Ok(backups);
        }

        for entry in fs::read_dir(&self.backup_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                backups.push(path);
            }
        }

        backups.sort();
        backups.reverse();

        Ok(backups)
    }

    pub fn restore_backup(&self, backup_file: &PathBuf) -> Result<()> {
        self.validate_backup_path(backup_file)?;
        let json = fs::read_to_string(backup_file).context("Failed to read backup file")?;

        let backup: PathBackup =
            serde_json::from_str(&json).context("Failed to parse backup file")?;

        RegistryHelper::write_user_path(&backup.user_path)
            .context("Failed to restore PATH from backup")?;

        println!("{}", "PATH restored from backup.".green().bold());
        println!(
            "{}",
            "  Note: You may need to restart applications for changes to take effect.".yellow()
        );

        Ok(())
    }

    /// Validates that the backup file path is safe to use.
    /// Prevents path traversal attacks by ensuring:
    /// 1. File is within the backup directory
    /// 2. File has .json extension
    /// 3. File name matches expected pattern
    fn validate_backup_path(&self, backup_file: &Path) -> Result<()> {
        use anyhow::bail;
        let canonical_backup_dir = self
            .backup_dir
            .canonicalize()
            .context("Failed to resolve backup directory path")?;

        let canonical_file = backup_file
            .canonicalize()
            .context("Backup file does not exist or path is invalid")?;

        if !canonical_file.starts_with(&canonical_backup_dir) {
            bail!(
                "Security error: Backup file must be located in {}\n\
                 Use 'spath list-backups' to see available backups.",
                self.backup_dir.display()
            );
        }

        if backup_file.extension().and_then(|s| s.to_str()) != Some("json") {
            bail!("Security error: Backup file must have .json extension");
        }

        if let Some(file_name) = backup_file.file_name().and_then(|s| s.to_str()) {
            if !file_name.starts_with("path_backup_") {
                bail!(
                    "Security error: Invalid backup file name format.\n\
                     Expected: path_backup_YYYYMMDD_HHMMSS.json"
                );
            }
        } else {
            bail!("Security error: Invalid backup file name");
        }

        Ok(())
    }
}

pub struct FixResults {
    pub changes: Vec<String>,
}
