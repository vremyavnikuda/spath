//! Common registry operations for PATH management.
//!
//! This module provides unified access to Windows Registry for reading and writing
//! PATH environment variables, eliminating code duplication across modules.
//!
//! ## Race Condition Protection
//!
//! Write operations use file-based locking via `fs2` crate to prevent concurrent
//! modifications to PATH by multiple spath processes. Lock files are stored in
//! `%LOCALAPPDATA%\spath\locks\`.

use anyhow::{bail, Context, Result};
use fs2::FileExt;
use std::fs::{self, File};
use std::path::PathBuf;
use winreg::enums::*;
use winreg::RegKey;

/// Registry key paths
const SYSTEM_ENV_KEY: &str = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment";
const USER_ENV_KEY: &str = "Environment";

/// Maximum length for PATH environment variable in Windows.
/// Windows has a limit of 2047 characters for environment variables set via registry.
/// See: <https://devblogs.microsoft.com/oldnewthing/20100203-00/?p=15083>
pub const MAX_PATH_LENGTH: usize = 2047;

/// Lock file names for preventing race conditions
const USER_PATH_LOCK: &str = "user_path.lock";

/// RAII guard for file lock. Automatically releases lock when dropped.
pub struct PathLockGuard {
    _file: File,
}

impl PathLockGuard {
    /// Acquires an exclusive lock on the specified lock file.
    /// Blocks until the lock is acquired.
    fn acquire(lock_name: &str) -> Result<Self> {
        let lock_dir = get_lock_dir()?;
        fs::create_dir_all(&lock_dir).context("Failed to create lock directory")?;

        let lock_path = lock_dir.join(lock_name);
        let file = File::create(&lock_path).context("Failed to create lock file")?;

        file.lock_exclusive()
            .context("Failed to acquire exclusive lock. Another spath process may be running.")?;

        Ok(Self { _file: file })
    }
}

/// Returns the directory for lock files: %LOCALAPPDATA%\spath\locks\
fn get_lock_dir() -> Result<PathBuf> {
    let local_app_data =
        std::env::var("LOCALAPPDATA").context("LOCALAPPDATA environment variable not set")?;
    Ok(PathBuf::from(local_app_data).join("spath").join("locks"))
}

/// Helper for Windows Registry PATH operations.
pub struct RegistryHelper;

impl RegistryHelper {
    /// Reads SYSTEM PATH as raw string.
    /// May fail without administrator rights.
    pub fn read_system_path_raw() -> Result<String> {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let env_key = hklm
            .open_subkey(SYSTEM_ENV_KEY)
            .context("Failed to open system environment key. Try running as administrator.")?;

        env_key
            .get_value("Path")
            .context("Failed to read system PATH")
    }

    /// Reads SYSTEM PATH as `Vec<String>` (parsed by semicolon).
    /// May fail without administrator rights.
    pub fn read_system_path() -> Result<Vec<String>> {
        let path = Self::read_system_path_raw()?;
        Ok(Self::parse_path_string(&path))
    }

    /// Reads USER PATH as raw string.
    pub fn read_user_path_raw() -> Result<String> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let env_key = hkcu
            .open_subkey(USER_ENV_KEY)
            .context("Failed to open user environment key")?;

        env_key
            .get_value("Path")
            .context("Failed to read user PATH")
    }

    /// Reads USER PATH as `Vec<String>` (parsed by semicolon).
    pub fn read_user_path() -> Result<Vec<String>> {
        let path = Self::read_user_path_raw()?;
        Ok(Self::parse_path_string(&path))
    }

    /// Validates that PATH length does not exceed Windows limit.
    ///
    /// # Errors
    /// Returns an error if the path exceeds MAX_PATH_LENGTH (2047 characters).
    pub fn validate_path_length(path: &str) -> Result<()> {
        if path.len() > MAX_PATH_LENGTH {
            bail!(
                "PATH exceeds maximum length of {} characters (current: {} characters). \
                Consider removing unused paths.",
                MAX_PATH_LENGTH,
                path.len()
            );
        }
        Ok(())
    }

    /// Writes USER PATH to registry with exclusive locking.
    ///
    /// Uses file-based locking to prevent race conditions when multiple
    /// spath processes try to modify PATH simultaneously.
    ///
    /// # Errors
    /// Returns an error if:
    /// - Lock cannot be acquired (another process is modifying PATH)
    /// - PATH exceeds maximum length (2047 characters)
    /// - Registry key cannot be opened for writing
    /// - Value cannot be written to registry
    pub fn write_user_path(path: &str) -> Result<()> {
        // Acquire exclusive lock before modifying
        let _lock = PathLockGuard::acquire(USER_PATH_LOCK)
            .context("Failed to acquire lock for USER PATH modification")?;

        Self::validate_path_length(path)?;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let env_key = hkcu
            .open_subkey_with_flags(USER_ENV_KEY, KEY_WRITE)
            .context("Failed to open user environment key for writing")?;

        env_key
            .set_value("Path", &path)
            .context("Failed to write user PATH to registry")
    }

    /// Parses PATH string into `Vec<String>`, filtering empty entries.
    pub fn parse_path_string(path: &str) -> Vec<String> {
        path.split(';')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect()
    }
}
