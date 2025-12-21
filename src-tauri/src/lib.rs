use serde::{Deserialize, Serialize};

mod analyzer;
mod audit;
mod fixer;
mod migrator;
mod registry;
mod scanner;
mod verifier;

use analyzer::SystemAnalyzer;
use audit::{AuditAction, AuditLogger};
use fixer::PathFixer;
use migrator::PathMigrator;
use scanner::{IssueLevel, PathScanner};
use verifier::PathVerifier;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathIssue {
    pub path: String,
    pub level: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub total_paths: usize,
    pub issues: Vec<PathIssue>,
    pub health_score: u8,
    pub critical_count: usize,
    pub warning_count: usize,
    pub info_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathEntry {
    pub path: String,
    pub location: String,
    pub category: String,
    pub exists: bool,
    pub has_spaces: bool,
    pub is_quoted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub entries: Vec<PathEntry>,
    pub system_count: usize,
    pub user_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupInfo {
    pub filename: String,
    pub timestamp: String,
    pub full_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub timestamp: String,
    pub action: String,
    pub target: String,
    pub changes_count: usize,
    pub changes: Vec<String>,
    pub success: bool,
    pub error: Option<String>,
}

#[tauri::command]
fn scan_path(scan_system: bool, verbose: bool) -> Result<ScanResult, String> {
    log::info!(
        "scan_path called with scan_system={}, verbose={}",
        scan_system,
        verbose
    );

    let scanner = PathScanner::new_with_system(scan_system).map_err(|e| {
        log::error!("Failed to create scanner: {}", e);
        e.to_string()
    })?;
    let results = scanner.scan().map_err(|e| {
        log::error!("Failed to scan: {}", e);
        e.to_string()
    })?;

    let target = if scan_system { "SYSTEM" } else { "USER" };

    if let Ok(audit) = AuditLogger::new() {
        let _ = audit.log_success(
            AuditAction::Scan,
            target,
            vec![format!(
                "Scanned {} paths, found {} issues",
                results.paths.len(),
                results.issues.len()
            )],
        );
    }

    let mut issues = Vec::new();
    let mut critical_count = 0;
    let mut warning_count = 0;
    let mut info_count = 0;

    for issue in &results.issues {
        let level = match issue.level {
            IssueLevel::Critical => {
                critical_count += 1;
                "critical"
            }
            IssueLevel::Warning => {
                warning_count += 1;
                "warning"
            }
            IssueLevel::Info => {
                info_count += 1;
                if !verbose {
                    continue;
                }
                "info"
            }
        };

        issues.push(PathIssue {
            path: issue.path.clone(),
            level: level.to_string(),
            message: issue.message.clone(),
        });
    }

    let total = results.paths.len();
    let health_score = if total == 0 {
        100
    } else {
        let penalty = (critical_count * 20 + warning_count * 5) as u8;
        100u8.saturating_sub(penalty)
    };

    Ok(ScanResult {
        total_paths: total,
        issues,
        health_score,
        critical_count,
        warning_count,
        info_count,
    })
}

#[tauri::command]
fn analyze_path() -> Result<AnalysisResult, String> {
    log::info!("analyze_path called");
    let analyzer = SystemAnalyzer::new().map_err(|e| {
        log::error!("Failed to create analyzer: {}", e);
        e.to_string()
    })?;
    let results = analyzer.analyze().map_err(|e| {
        log::error!("Failed to analyze: {}", e);
        e.to_string()
    })?;

    let entries: Vec<PathEntry> = results
        .entries
        .iter()
        .map(|e| {
            let location = match e.location {
                analyzer::PathLocation::System => "SYSTEM",
                analyzer::PathLocation::User => "USER",
            };
            let category = match e.category {
                analyzer::PathCategory::SystemProgram => "System",
                analyzer::PathCategory::UserProgram => "User",
                analyzer::PathCategory::ProgramData => "ProgramData",
                analyzer::PathCategory::Ambiguous => "Other",
            };

            PathEntry {
                path: e.path.clone(),
                location: location.to_string(),
                category: category.to_string(),
                exists: e.exists,
                has_spaces: e.has_spaces,
                is_quoted: e.is_quoted,
            }
        })
        .collect();

    let system_count = entries.iter().filter(|e| e.location == "SYSTEM").count();
    let user_count = entries.iter().filter(|e| e.location == "USER").count();

    Ok(AnalysisResult {
        entries,
        system_count,
        user_count,
    })
}

#[tauri::command]
fn list_backups() -> Result<Vec<BackupInfo>, String> {
    log::info!("list_backups called");
    let fixer = PathFixer::new().map_err(|e| {
        log::error!("Failed to create fixer: {}", e);
        e.to_string()
    })?;
    let backups = fixer.list_backups().map_err(|e| e.to_string())?;

    Ok(backups
        .iter()
        .map(|path| {
            let filename = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            let timestamp = filename
                .strip_prefix("path_backup_")
                .and_then(|s| s.strip_suffix(".json"))
                .unwrap_or("")
                .to_string();

            BackupInfo {
                filename,
                timestamp,
                full_path: path.to_string_lossy().to_string(),
            }
        })
        .collect())
}

#[tauri::command]
fn create_backup() -> Result<String, String> {
    log::info!("create_backup called");
    let fixer = PathFixer::new().map_err(|e| {
        log::error!("Failed to create fixer: {}", e);
        e.to_string()
    })?;

    let path = fixer.create_backup().map_err(|e| {
        if let Ok(audit) = AuditLogger::new() {
            let _ = audit.log_failure(AuditAction::Backup, "USER", e.to_string());
        }
        e.to_string()
    })?;

    if let Ok(audit) = AuditLogger::new() {
        let _ = audit.log_success(
            AuditAction::Backup,
            "USER",
            vec![format!("Created backup: {}", path.display())],
        );
    }

    Ok(path.to_string_lossy().to_string())
}

#[tauri::command]
fn fix_user_path(dry_run: bool) -> Result<Vec<String>, String> {
    log::info!("fix_user_path called with dry_run={}", dry_run);
    let fixer = PathFixer::new().map_err(|e| {
        log::error!("Failed to create fixer: {}", e);
        e.to_string()
    })?;

    let results = fixer.fix_user_path(dry_run).map_err(|e| {
        log::error!("Failed to fix path: {}", e);
        if let Ok(audit) = AuditLogger::new() {
            let _ = audit.log_failure(AuditAction::Fix, "USER", e.to_string());
        }
        e.to_string()
    })?;

    log::info!("fix_user_path returned {} changes", results.changes.len());
    for (i, change) in results.changes.iter().enumerate() {
        log::debug!("Change {}: {}", i, change);
    }

    if !dry_run && !results.changes.is_empty() {
        if let Ok(audit) = AuditLogger::new() {
            let _ = audit.log_success(AuditAction::Fix, "USER", results.changes.clone());
        }
    }

    Ok(results.changes)
}

#[tauri::command]
fn restore_backup(backup_path: String) -> Result<(), String> {
    log::info!("restore_backup called with path: {}", backup_path);
    let fixer = PathFixer::new().map_err(|e| {
        log::error!("Failed to create fixer: {}", e);
        e.to_string()
    })?;

    let path = std::path::PathBuf::from(&backup_path);
    fixer.restore_backup(&path).map_err(|e| {
        if let Ok(audit) = AuditLogger::new() {
            let _ = audit.log_failure(AuditAction::Restore, "USER", e.to_string());
        }
        e.to_string()
    })?;

    if let Ok(audit) = AuditLogger::new() {
        let _ = audit.log_success(
            AuditAction::Restore,
            "USER",
            vec![format!("Restored from: {}", backup_path)],
        );
    }

    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Debug)
        .init();

    log::info!("Starting spath GUI application");

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            scan_path,
            analyze_path,
            list_backups,
            create_backup,
            fix_user_path,
            restore_backup,
            get_audit_log,
            verify_path,
            clean_path
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[tauri::command]
fn get_audit_log(count: usize) -> Result<Vec<AuditLogEntry>, String> {
    log::info!("get_audit_log called with count={}", count);

    let audit = AuditLogger::new().map_err(|e| {
        log::error!("Failed to create audit logger: {}", e);
        e.to_string()
    })?;

    let entries = audit.get_recent(count).map_err(|e| {
        log::error!("Failed to read audit log: {}", e);
        e.to_string()
    })?;

    let result: Vec<AuditLogEntry> = entries
        .into_iter()
        .map(|e| AuditLogEntry {
            timestamp: e.timestamp,
            action: format!("{:?}", e.action),
            target: e.target,
            changes_count: e.changes_count,
            changes: e.changes,
            success: e.success,
            error: e.error,
        })
        .collect();

    Ok(result)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResult {
    pub path: String,
    pub is_exploitable: bool,
    pub exploit_files: Vec<String>,
    pub threat_level: String,
}

#[tauri::command]
fn verify_path() -> Result<Vec<VerifyResult>, String> {
    log::info!("verify_path called");

    let scanner = PathScanner::new().map_err(|e| {
        log::error!("Failed to create scanner: {}", e);
        e.to_string()
    })?;

    let scan_results = scanner.scan().map_err(|e| {
        log::error!("Failed to scan PATH: {}", e);
        e.to_string()
    })?;

    let verifier = PathVerifier::new().map_err(|e| {
        log::error!("Failed to create verifier: {}", e);
        e.to_string()
    })?;

    let verify_results = verifier.verify(&scan_results.issues).map_err(|e| {
        log::error!("Failed to verify issues: {}", e);
        e.to_string()
    })?;

    let results: Vec<VerifyResult> = verify_results
        .into_iter()
        .map(|r| VerifyResult {
            path: r.path,
            is_exploitable: r.is_exploitable,
            exploit_files: r.exploit_files,
            threat_level: format!("{:?}", r.threat_level),
        })
        .collect();

    Ok(results)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanResult {
    pub removed_duplicates: Vec<String>,
    pub total_removed: usize,
}

#[tauri::command]
fn clean_path(dry_run: bool) -> Result<CleanResult, String> {
    log::info!("clean_path called with dry_run={}", dry_run);

    let migrator = PathMigrator::new().map_err(|e| {
        log::error!("Failed to create migrator: {}", e);
        e.to_string()
    })?;

    let result = migrator.clean_user_path(dry_run).map_err(|e| {
        log::error!("Failed to clean PATH: {}", e);

        if let Ok(audit) = AuditLogger::new() {
            let _ = audit.log_failure(AuditAction::Fix, "USER", e.to_string());
        }

        e.to_string()
    })?;

    if !dry_run && result.total_removed > 0 {
        if let Ok(audit) = AuditLogger::new() {
            let changes: Vec<String> = result
                .removed_duplicates
                .iter()
                .map(|p| format!("Removed duplicate: {}", p))
                .collect();
            let _ = audit.log_success(AuditAction::Fix, "USER", changes);
        }
    }

    Ok(CleanResult {
        removed_duplicates: result.removed_duplicates,
        total_removed: result.total_removed,
    })
}
