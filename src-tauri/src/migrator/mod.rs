use anyhow::{Context, Result};
use std::collections::HashSet;

use crate::registry::RegistryHelper;

#[derive(Debug, Clone, serde::Serialize)]
pub struct CleanResult {
    pub removed_duplicates: Vec<String>,
    pub total_removed: usize,
}

pub struct PathMigrator;

impl PathMigrator {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }

    /// Clean `PATH` by removing duplicates
    pub fn clean_user_path(&self, dry_run: bool) -> Result<CleanResult> {
        let current_path = RegistryHelper::read_user_path_raw()
            .context("Failed to read USER PATH from registry")?;

        let paths = RegistryHelper::parse_path_string(&current_path);
        let mut seen = HashSet::new();
        let mut cleaned_paths = Vec::new();
        let mut removed = Vec::new();

        for path in paths {
            let normalized = path.trim_matches('"').to_lowercase();

            if seen.contains(&normalized) {
                log::info!("Removing duplicate: {}", path);
                removed.push(path);
            } else {
                seen.insert(normalized);
                cleaned_paths.push(path);
            }
        }

        if !dry_run && !removed.is_empty() {
            let new_path = cleaned_paths.join(";");
            RegistryHelper::write_user_path(&new_path)
                .context("Failed to write USER PATH to registry")?;
        }

        Ok(CleanResult {
            removed_duplicates: removed.clone(),
            total_removed: removed.len(),
        })
    }
}
