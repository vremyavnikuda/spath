use anyhow::{Context, Result};
use std::env;
use std::path::Path;

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

/// Checks if an unquoted path with spaces could be exploited.
/// Returns true if the path could be vulnerable to DLL hijacking or similar attacks.
///
/// For example, `"C:\Program Files\App\bin"` could be exploited by creating:
/// - `C:\Program.exe` (would be executed instead of `C:\Program Files\...`)
/// - `C:\Program Files\App.exe` (would be executed instead of `C:\Program Files\App\...`)
fn check_path_exploitable(path: &str) -> bool {
    let path_lower = path.to_lowercase();
    let exploitable_patterns = [
        "c:\\program files",
        "c:\\program files (x86)",
        "c:\\windows ",
    ];

    for pattern in &exploitable_patterns {
        if path_lower.starts_with(pattern) {
            return true;
        }
    }

    false
}

#[derive(Debug, Clone)]
pub enum IssueLevel {
    Critical,
    Warning,
    Info,
}

#[derive(Debug, Clone)]
pub struct PathIssue {
    pub path: String,
    pub level: IssueLevel,
    pub message: String,
}

pub struct ScanResults {
    pub paths: Vec<String>,
    pub issues: Vec<PathIssue>,
}

pub struct PathScanner {
    scan_system: bool,
}

impl PathScanner {
    pub fn new() -> Result<Self> {
        Ok(Self { scan_system: false })
    }

    pub fn new_with_system(scan_system: bool) -> Result<Self> {
        Ok(Self { scan_system })
    }

    pub fn scan(&self) -> Result<ScanResults> {
        let path_var = if self.scan_system {
            RegistryHelper::read_system_path_raw()
                .context("Failed to read SYSTEM PATH from registry")?
        } else {
            RegistryHelper::read_user_path_raw()
                .context("Failed to read USER PATH from registry")?
        };

        let path_type = if self.scan_system { "SYSTEM" } else { "USER" };
        log::debug!("Scanner reading {} PATH: {}", path_type, path_var);
        let paths: Vec<String> = RegistryHelper::parse_path_string(&path_var);
        let mut issues = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for (i, path) in paths.iter().enumerate() {
            let trimmed = path.trim();
            log::debug!("Scanner checking path {}: '{}'", i, trimmed);
            let has_spaces = trimmed.contains(' ');
            let is_quoted = trimmed.starts_with('"');
            let path_to_check = if trimmed.contains('%') {
                let expanded = expand_env_vars(trimmed);
                expanded.trim_matches('"').to_string()
            } else {
                trimmed.trim_matches('"').to_string()
            };
            let exists = Path::new(&path_to_check).exists();
            let is_absolute =
                trimmed.contains(':') || trimmed.starts_with('"') || trimmed.contains('%');

            if seen.contains(trimmed) {
                log::info!("Scanner found duplicate: {}", trimmed);
                issues.push(PathIssue {
                    path: path.clone(),
                    level: IssueLevel::Warning,
                    message: "Duplicate path entry".to_string(),
                });
            }
            seen.insert(trimmed.to_string());

            // Check for spaces without quotes
            // Unquoted paths with spaces can be a security risk if they can be exploited
            // by creating malicious directories (e.g., "C:\Program.exe" for "C:\Program Files")
            if has_spaces && !is_quoted {
                if exists {
                    let is_exploitable = check_path_exploitable(trimmed);

                    if is_exploitable {
                        log::warn!("Scanner found exploitable unquoted path: {}", trimmed);
                        issues.push(PathIssue {
                            path: path.clone(),
                            level: IssueLevel::Critical,
                            message: "Path contains spaces without quotes and could be exploited by creating malicious files/directories".to_string(),
                        });
                    } else {
                        log::info!(
                            "Scanner found unquoted path with spaces (exists): {}",
                            trimmed
                        );
                        issues.push(PathIssue {
                            path: path.clone(),
                            level: IssueLevel::Info,
                            message: "Path contains spaces but is not quoted. Consider adding quotes for better compatibility.".to_string(),
                        });
                    }
                } else {
                    log::info!(
                        "Scanner found unquoted path with spaces (not exists): {}",
                        trimmed
                    );
                    issues.push(PathIssue {
                        path: path.clone(),
                        level: IssueLevel::Warning,
                        message: "Path contains spaces, is not quoted, and does not exist"
                            .to_string(),
                    });
                }
            } else if has_spaces && is_quoted && exists {
                issues.push(PathIssue {
                    path: path.clone(),
                    level: IssueLevel::Info,
                    message: "Path is properly quoted".to_string(),
                });
            }

            if !exists {
                issues.push(PathIssue {
                    path: path.clone(),
                    level: IssueLevel::Warning,
                    message: "Path does not exist".to_string(),
                });
            } else {
                let path_obj = Path::new(&path_to_check);
                if path_obj.is_file() {
                    issues.push(PathIssue {
                        path: path.clone(),
                        level: IssueLevel::Info,
                        message: "PATH entry points to a file instead of a directory".to_string(),
                    });
                }
            }

            if !is_absolute && !trimmed.is_empty() {
                issues.push(PathIssue {
                    path: path.clone(),
                    level: IssueLevel::Warning,
                    message: "Relative path detected - should use absolute paths".to_string(),
                });
            }
        }

        Ok(ScanResults { paths, issues })
    }
}
