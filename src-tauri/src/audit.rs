//! Audit logging for PATH modifications.
//!
//! This module provides functionality to track all PATH changes
//! for security auditing and troubleshooting purposes.

use anyhow::{Context, Result};
use chrono::{Local, TimeZone};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

/// Type of operation performed on PATH
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    Scan,
    Fix,
    Backup,
    Restore,
    Clean,
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub action: AuditAction,
    // "USER" or "SYSTEM"
    pub target: String,
    pub changes_count: usize,
    pub changes: Vec<String>,
    pub success: bool,
    pub error: Option<String>,
}

pub struct AuditLogger {
    log_file: PathBuf,
}

impl AuditLogger {
    /// Creates a new audit logger instance
    pub fn new() -> Result<Self> {
        let local_app_data =
            env::var("LOCALAPPDATA").context("Failed to get LOCALAPPDATA environment variable")?;

        let log_dir = PathBuf::from(local_app_data).join("spath").join("logs");
        fs::create_dir_all(&log_dir).context("Failed to create log directory")?;

        let log_file = log_dir.join("audit.log");

        let logger = Self { log_file };

        // Automatically cleanup old entries (keep last 90 days)
        // Ignore errors during cleanup to not fail initialization
        let _ = logger.cleanup_old_entries(90);

        Ok(logger)
    }

    /// Logs a successful operation
    pub fn log_success(
        &self,
        action: AuditAction,
        target: &str,
        changes: Vec<String>,
    ) -> Result<()> {
        let entry = AuditEntry {
            timestamp: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            action,
            target: target.to_string(),
            changes_count: changes.len(),
            changes,
            success: true,
            error: None,
        };

        self.write_entry(&entry)
    }

    /// Logs a failed operation
    pub fn log_failure(&self, action: AuditAction, target: &str, error: String) -> Result<()> {
        let entry = AuditEntry {
            timestamp: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            action,
            target: target.to_string(),
            changes_count: 0,
            changes: Vec::new(),
            success: false,
            error: Some(error),
        };

        self.write_entry(&entry)
    }

    /// Writes an entry to the audit log
    fn write_entry(&self, entry: &AuditEntry) -> Result<()> {
        let json = serde_json::to_string(entry).context("Failed to serialize audit entry")?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_file)
            .context("Failed to open audit log file")?;

        writeln!(file, "{}", json).context("Failed to write to audit log")?;

        log::info!(
            "Audit log entry written: {:?} on {}",
            entry.action,
            entry.target
        );

        Ok(())
    }

    /// Reads all audit log entries
    pub fn read_entries(&self) -> Result<Vec<AuditEntry>> {
        if !self.log_file.exists() {
            return Ok(Vec::new());
        }

        let content =
            fs::read_to_string(&self.log_file).context("Failed to read audit log file")?;

        let mut entries = Vec::new();
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }

            match serde_json::from_str::<AuditEntry>(line) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    log::warn!("Failed to parse audit log line: {}", e);
                    continue;
                }
            }
        }

        Ok(entries)
    }

    /// Gets recent audit entries (last N entries)
    pub fn get_recent(&self, count: usize) -> Result<Vec<AuditEntry>> {
        let mut entries = self.read_entries()?;
        entries.reverse(); // Most recent first
        entries.truncate(count);
        Ok(entries)
    }

    /// Clears old audit log entries (keeps last N days)
    pub fn cleanup_old_entries(&self, keep_days: i64) -> Result<()> {
        let entries = self.read_entries()?;
        let cutoff = Local::now() - chrono::Duration::days(keep_days);

        let filtered: Vec<AuditEntry> = entries
            .into_iter()
            .filter(|entry| {
                if let Ok(timestamp) =
                    chrono::NaiveDateTime::parse_from_str(&entry.timestamp, "%Y-%m-%d %H:%M:%S")
                {
                    let entry_time = Local.from_local_datetime(&timestamp).unwrap();
                    entry_time > cutoff
                } else {
                    true
                }
            })
            .collect();

        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(&self.log_file)
            .context("Failed to open audit log file for cleanup")?;

        for entry in filtered {
            let json = serde_json::to_string(&entry)?;
            writeln!(file, "{}", json)?;
        }

        log::info!("Cleaned up audit log, keeping last {} days", keep_days);

        Ok(())
    }
}
