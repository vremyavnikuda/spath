use anyhow::Result;
use std::path::Path;

use crate::scanner::{IssueLevel, PathIssue};

#[derive(Debug, Clone, serde::Serialize)]
pub struct VerifyResult {
    pub path: String,
    pub is_exploitable: bool,
    pub exploit_files: Vec<String>,
    pub threat_level: ThreatLevel,
}

#[derive(Debug, Clone, serde::Serialize)]
pub enum ThreatLevel {
    Potential,
    RealThreat,
}

pub struct PathVerifier;

impl PathVerifier {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }

    /// Verify if critical issues are actually exploitable
    pub fn verify(&self, issues: &[PathIssue]) -> Result<Vec<VerifyResult>> {
        let mut results = Vec::new();
        let critical_issues: Vec<_> = issues
            .iter()
            .filter(|issue| matches!(issue.level, IssueLevel::Critical))
            .collect();

        for issue in critical_issues {
            let exploit_paths = self.generate_exploit_paths(&issue.path);
            let mut found_exploits = Vec::new();

            for exploit_path in &exploit_paths {
                if Path::new(exploit_path).exists() {
                    found_exploits.push(exploit_path.clone());
                }
            }

            let threat_level = if found_exploits.is_empty() {
                ThreatLevel::Potential
            } else {
                ThreatLevel::RealThreat
            };

            results.push(VerifyResult {
                path: issue.path.clone(),
                is_exploitable: !found_exploits.is_empty(),
                exploit_files: found_exploits,
                threat_level,
            });
        }

        Ok(results)
    }

    /// Generates potential exploit file paths for an unquoted path with spaces.
    ///
    /// For example, `"C:\Program Files\App\bin"` could be exploited by:
    /// - `C:\Program.exe`, `C:\Program.com`, `C:\Program.bat`, `C:\Program.cmd`
    /// - `C:\Program Files\App.exe`, etc.
    fn generate_exploit_paths(&self, path: &str) -> Vec<String> {
        let mut exploits = Vec::new();
        let path_lower = path.to_lowercase();
        let clean_path = path.trim_matches('"');
        let parts: Vec<&str> = clean_path.split(' ').collect();

        if parts.len() < 2 {
            return exploits;
        }

        if path_lower.starts_with("c:\\program files") {
            exploits.push("C:\\Program.exe".to_string());
            exploits.push("C:\\Program.com".to_string());
            exploits.push("C:\\Program.bat".to_string());
            exploits.push("C:\\Program.cmd".to_string());
        }

        if path_lower.contains("\\common files") {
            exploits.push("C:\\Program Files\\Common.exe".to_string());
            exploits.push("C:\\Program Files\\Common.com".to_string());
            exploits.push("C:\\Program Files (x86)\\Common.exe".to_string());
            exploits.push("C:\\Program Files (x86)\\Common.com".to_string());
        }

        let mut accumulated = String::new();
        for (i, part) in parts.iter().enumerate() {
            if i > 0 {
                accumulated.push(' ');
            }
            accumulated.push_str(part);

            if i < parts.len() - 1 {
                for ext in &[".exe", ".com", ".bat", ".cmd"] {
                    exploits.push(format!("{}{}", accumulated, ext));
                }
            }
        }

        exploits
    }
}
