//! Reversible deletes.
//!
//! The previous implementation ran `sudo rm -f <plist>` on a path taken
//! straight from parsed data, with no undo. Disabling the wrong LaunchDaemon
//! can leave a machine without VPN, audio drivers or backups, so "delete" now
//! moves the plist into a quarantine directory and records enough metadata to
//! put it back.

use crate::models::StartupItem;
use crate::privileged::{self, Request, ALLOWED_PRIVILEGED_DIRS};
use crate::sudo::SudoSession;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: String,
    pub label: String,
    pub name: String,
    pub original_path: PathBuf,
    pub stored_path: PathBuf,
    pub needs_root: bool,
    /// Unix seconds.
    pub removed_at: u64,
}

pub fn quarantine_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join("Library/Application Support/LaunchFleet/quarantine")
}

fn manifest_path() -> PathBuf {
    quarantine_dir().join("manifest.json")
}

pub fn list() -> Vec<QuarantineEntry> {
    let Ok(data) = fs::read(manifest_path()) else {
        return Vec::new();
    };
    serde_json::from_slice(&data).unwrap_or_default()
}

fn write_manifest(entries: &[QuarantineEntry]) -> Result<(), String> {
    let dir = quarantine_dir();
    fs::create_dir_all(&dir).map_err(|e| format!("cannot create quarantine dir: {}", e))?;
    let json = serde_json::to_vec_pretty(entries).map_err(|e| e.to_string())?;
    fs::write(manifest_path(), json).map_err(|e| format!("cannot write manifest: {}", e))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Build a collision-free destination filename inside the quarantine dir.
fn stored_path_for(item: &StartupItem, src: &Path) -> PathBuf {
    let stem = src
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| item.label.clone());
    quarantine_dir().join(format!("{}-{}", now_secs(), stem))
}

/// Move an item's plist into quarantine. Root-owned plists go through the
/// privileged helper, which re-validates the source path against the allowlist.
pub fn quarantine(item: &StartupItem, sudo: &SudoSession) -> Result<PathBuf, String> {
    let src = item
        .plist_path
        .as_ref()
        .ok_or_else(|| "This item has no backing plist file to remove.".to_string())?;

    if !src.exists() {
        return Err(format!("{} no longer exists.", src.display()));
    }

    let dest = stored_path_for(item, src);
    fs::create_dir_all(quarantine_dir())
        .map_err(|e| format!("cannot create quarantine dir: {}", e))?;

    if item.needs_root() {
        // Fail fast with a clear message; the helper enforces this again.
        privileged::validate_in_allowed_dirs(src, ALLOWED_PRIVILEGED_DIRS)?;
        sudo.request_checked(Request::Quarantine {
            src: src.clone(),
            dest: dest.clone(),
        })?;
    } else {
        fs::rename(src, &dest).map_err(|e| format!("cannot move {}: {}", src.display(), e))?;
    }

    let mut entries = list();
    entries.retain(|e| e.id != item.id);
    entries.push(QuarantineEntry {
        id: item.id.clone(),
        label: item.label.clone(),
        name: item.name.clone(),
        original_path: src.clone(),
        stored_path: dest.clone(),
        needs_root: item.needs_root(),
        removed_at: now_secs(),
    });
    write_manifest(&entries)?;

    Ok(dest)
}

/// Put a quarantined plist back where it came from.
pub fn restore(id: &str, sudo: &SudoSession) -> Result<PathBuf, String> {
    let entries = list();
    let entry = entries
        .iter()
        .find(|e| e.id == id)
        .ok_or_else(|| format!("No quarantined item with id {}", id))?
        .clone();

    if !entry.stored_path.exists() {
        return Err(format!(
            "Quarantined file {} is missing.",
            entry.stored_path.display()
        ));
    }
    if entry.original_path.exists() {
        return Err(format!(
            "{} already exists — refusing to overwrite.",
            entry.original_path.display()
        ));
    }

    if entry.needs_root {
        if !sudo.is_active() {
            return Err("Enable System Mode to restore a system-level item.".to_string());
        }
        sudo.request_checked(Request::Restore {
            src: entry.stored_path.clone(),
            dest: entry.original_path.clone(),
        })?;
    } else {
        fs::rename(&entry.stored_path, &entry.original_path)
            .map_err(|e| format!("cannot restore: {}", e))?;
    }

    let remaining: Vec<QuarantineEntry> =
        entries.into_iter().filter(|e| e.id != id).collect();
    write_manifest(&remaining)?;

    Ok(entry.original_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quarantine_dir_is_under_application_support() {
        let d = quarantine_dir();
        assert!(d.to_string_lossy().contains("Application Support/LaunchFleet"));
    }

    #[test]
    fn stored_path_is_namespaced_and_unique_per_source() {
        let item = StartupItem::new("com.example.x".into(), crate::models::ItemType::LaunchDaemon);
        let p = stored_path_for(&item, Path::new("/Library/LaunchDaemons/com.example.x.plist"));
        assert!(p.starts_with(quarantine_dir()));
        assert!(p.to_string_lossy().ends_with("com.example.x.plist"));
    }

    #[test]
    fn empty_manifest_when_missing() {
        // Should never panic even with no quarantine dir present.
        let _ = list();
    }
}
