use anyhow::{Context, Result};
use std::env;
use std::path::Path;

use crate::registry::RegistryHelper;

#[derive(Debug, Clone)]
pub enum PathLocation {
    System,
    User,
}

#[derive(Debug, Clone)]
pub enum PathCategory {
    // C:\Program Files, C:\Windows
    SystemProgram,
    // C:\Users\username\...
    UserProgram,
    // C:\ProgramData
    ProgramData,
    // Unclear
    Ambiguous,
}

#[derive(Debug, Clone)]
pub struct PathEntry {
    pub path: String,
    pub location: PathLocation,
    pub category: PathCategory,
    pub has_spaces: bool,
    pub is_quoted: bool,
    pub exists: bool,
}

pub struct SystemAnalyzer {
    current_username: String,
}

impl SystemAnalyzer {
    pub fn new() -> Result<Self> {
        let current_username = env::var("USERNAME").context("Failed to get current username")?;

        Ok(Self { current_username })
    }

    pub fn analyze(&self) -> Result<AnalysisResults> {
        let system_paths = self.read_system_path()?;
        let user_paths = self.read_user_path()?;

        let mut entries = Vec::new();

        // Analyze SYSTEM PATH
        for path in system_paths {
            let entry = self.analyze_path(&path, PathLocation::System);
            entries.push(entry);
        }

        // Analyze USER PATH
        for path in user_paths {
            let entry = self.analyze_path(&path, PathLocation::User);
            entries.push(entry);
        }

        Ok(AnalysisResults {
            entries,
            current_username: self.current_username.clone(),
        })
    }

    fn read_system_path(&self) -> Result<Vec<String>> {
        RegistryHelper::read_system_path()
    }

    fn read_user_path(&self) -> Result<Vec<String>> {
        RegistryHelper::read_user_path()
    }

    fn analyze_path(&self, path: &str, location: PathLocation) -> PathEntry {
        let trimmed = path.trim_matches('"');
        let has_spaces = path.contains(' ');
        let is_quoted = path.starts_with('"') && path.ends_with('"');
        let exists = Path::new(trimmed).exists();

        let category = self.categorize_path(trimmed);

        PathEntry {
            path: path.to_string(),
            location,
            category,
            has_spaces,
            is_quoted,
            exists,
        }
    }

    fn categorize_path(&self, path: &str) -> PathCategory {
        let lower = path.to_lowercase();

        // System programs
        if lower.starts_with("c:\\windows")
            || lower.starts_with("c:\\program files")
            || lower.starts_with("c:\\program files (x86)")
        {
            return PathCategory::SystemProgram;
        }

        // User programs
        if lower.contains(&format!(
            "c:\\users\\{}",
            self.current_username.to_lowercase()
        )) || lower.contains("\\appdata\\")
            || lower.contains("\\.cargo\\")
            || lower.contains("\\.dotnet\\")
            || lower.contains("\\.npm\\")
            || lower.contains("\\.bun\\")
            || lower.contains("\\.local\\")
        {
            return PathCategory::UserProgram;
        }

        // ProgramData (shared but not system)
        if lower.starts_with("c:\\programdata") {
            return PathCategory::ProgramData;
        }

        PathCategory::Ambiguous
    }
}

pub struct AnalysisResults {
    pub entries: Vec<PathEntry>,
    #[allow(dead_code)]
    pub current_username: String,
}
