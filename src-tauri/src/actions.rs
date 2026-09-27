use crate::models::{StartupItem, ToggleMethod};
use crate::privileged::Request;
use crate::quarantine;
use crate::sm_login;
use crate::sudo::SudoSession;
use serde::Serialize;
use std::process::{Command, Output};

#[derive(Debug, Clone, Serialize)]
pub enum ResultKind {
    /// Action completed successfully
    Done,
    /// Item must be toggled in System Settings (no programmatic API)
    SystemSettingsRequired,
    /// Needs System Mode (privileged helper) to be activated
    SudoRequired,
    /// Item cannot be modified (Apple, cron, read-only)
    NotToggleable,
    /// Generic failure
    Failed,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActionResult {
    pub success: bool,
    pub message: String,
    pub kind: ResultKind,
}

impl ActionResult {
    pub fn done(msg: impl Into<String>) -> Self {
        Self {
            success: true,
            message: msg.into(),
            kind: ResultKind::Done,
        }
    }
    pub fn fail(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            message: msg.into(),
            kind: ResultKind::Failed,
        }
    }
    pub fn system_settings(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            message: msg.into(),
            kind: ResultKind::SystemSettingsRequired,
        }
    }
    pub fn sudo_required(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            message: msg.into(),
            kind: ResultKind::SudoRequired,
        }
    }
    pub fn not_toggleable(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            message: msg.into(),
            kind: ResultKind::NotToggleable,
        }
    }
}

/// `Command::output()` returns `Ok` for a process that exited non-zero, so the
/// status has to be inspected explicitly. Not doing this was why the UI used to
/// report "Disabled X" for operations that never happened.
fn check(out: std::io::Result<Output>, what: &str) -> Result<Output, String> {
    let out = out.map_err(|e| format!("failed to run {}: {}", what, e))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let detail = if !stderr.trim().is_empty() {
            stderr.trim().to_string()
        } else if !stdout.trim().is_empty() {
            stdout.trim().to_string()
        } else {
            format!("exit code {}", out.status.code().unwrap_or(-1))
        };
        return Err(format!("{} failed: {}", what, detail));
    }
    Ok(out)
}

fn current_uid() -> u32 {
    // Replaces the unmaintained `users` crate (RUSTSEC-2023-0040); `libc` was
    // already a dependency.
    unsafe { libc::getuid() }
}

// ───────── Public dispatch ─────────

pub fn enable_item(item: &StartupItem, sudo: &SudoSession) -> ActionResult {
    set_item_enabled(item, true, sudo)
}

pub fn disable_item(item: &StartupItem, sudo: &SudoSession) -> ActionResult {
    set_item_enabled(item, false, sudo)
}

fn set_item_enabled(item: &StartupItem, enable: bool, sudo: &SudoSession) -> ActionResult {
    if item.foreign_user {
        return ActionResult::not_toggleable(format!(
            "\"{}\" belongs to another user account (uid {}) and cannot be changed from this session.",
            item.name,
            item.uid.unwrap_or(-1)
        ));
    }

    match item.toggle_method {
        ToggleMethod::Launchctl => set_launchd_enabled(item, enable, sudo),
        ToggleMethod::AppleScript => set_via_applescript(item, enable),
        ToggleMethod::SMLoginItem => set_via_sm_login(item, enable),
        ToggleMethod::SystemSettingsOnly => ActionResult::system_settings(format!(
            "\"{}\" must be toggled in System Settings.",
            item.name
        )),
        ToggleMethod::LoginHook => {
            if enable {
                ActionResult::not_toggleable(
                    "Login hooks must be re-enabled with: defaults write com.apple.loginwindow LoginHook <path>",
                )
            } else {
                disable_login_hook(&item.label)
            }
        }
        ToggleMethod::ReadOnly => ActionResult::not_toggleable(format!(
            "\"{}\" cannot be modified by LaunchFleet.",
            item.name
        )),
    }
}

pub fn delete_item(item: &StartupItem, sudo: &SudoSession) -> ActionResult {
    if item.foreign_user {
        return ActionResult::not_toggleable(format!(
            "\"{}\" belongs to another user account and cannot be removed from this session.",
            item.name
        ));
    }

    match item.toggle_method {
        ToggleMethod::Launchctl => delete_launchd_item(item, sudo),
        ToggleMethod::AppleScript => set_via_applescript(item, false),
        ToggleMethod::SMLoginItem => set_via_sm_login(item, false),
        ToggleMethod::SystemSettingsOnly => ActionResult::system_settings(format!(
            "\"{}\" must be removed in System Settings.",
            item.name
        )),
        ToggleMethod::LoginHook => disable_login_hook(&item.label),
        ToggleMethod::ReadOnly => ActionResult::not_toggleable(format!(
            "\"{}\" cannot be deleted by LaunchFleet.",
            item.name
        )),
    }
}

// ───────── launchctl-based toggle ─────────

/// Toggling used to work by writing a `Disabled` key into the vendor's plist
/// with `defaults write`. That has three problems:
///   1. `defaults` rewrites the file as a *binary* plist, destroying the
///      original XML formatting and comments;
///   2. it tightens the mode from 0644 to 0600 on a file owned by someone else;
///   3. `Disabled` is only the *initial* value — launchd's authoritative state
///      lives in its override database.
/// `launchctl enable|disable` is the documented mechanism and touches no files.
fn set_launchd_enabled(item: &StartupItem, enable: bool, sudo: &SudoSession) -> ActionResult {
    let needs_root = item.needs_root();

    if needs_root && !sudo.is_active() {
        return ActionResult::sudo_required(format!(
            "\"{}\" is a system-level item. Enable System Mode to manage it.",
            item.name
        ));
    }

    let uid = current_uid();
    let domain = item.launchd_domain(uid);
    let service_target = format!("{}/{}", domain, item.label);

    if needs_root {
        // ── privileged path ──
        if let Err(e) = sudo.request_checked(Request::SetEnabled {
            domain: domain.clone(),
            label: item.label.clone(),
            enabled: enable,
        }) {
            return ActionResult::fail(format!("launchctl {} failed: {}", verb(enable), e));
        }

        if enable {
            let Some(plist) = item.plist_path.clone() else {
                return ActionResult::fail("No backing plist to bootstrap.");
            };
            // bootstrap reports EALREADY when the service is already loaded;
            // that is success for our purposes.
            match sudo.request(Request::Bootstrap { domain, plist }) {
                Ok(r) if r.ok() || is_already_loaded(&r.error_text()) => {}
                Ok(r) => {
                    return ActionResult::fail(format!(
                        "Enabled in launchd, but bootstrap failed: {}",
                        r.error_text()
                    ))
                }
                Err(e) => return ActionResult::fail(e),
            }
        } else {
            match sudo.request(Request::Bootout {
                domain,
                label: item.label.clone(),
            }) {
                Ok(r) if r.ok() || is_not_loaded(&r.error_text()) => {}
                Ok(r) => {
                    return ActionResult::fail(format!(
                        "Disabled in launchd, but bootout failed: {}",
                        r.error_text()
                    ))
                }
                Err(e) => return ActionResult::fail(e),
            }
        }
    } else {
        // ── unprivileged path ──
        if let Err(e) = check(
            Command::new("/bin/launchctl")
                .arg(verb(enable))
                .arg(&service_target)
                .output(),
            &format!("launchctl {}", verb(enable)),
        ) {
            return ActionResult::fail(e);
        }

        if enable {
            let Some(plist) = item.plist_path.as_ref() else {
                return ActionResult::fail("No backing plist to bootstrap.");
            };
            let out = Command::new("/bin/launchctl")
                .arg("bootstrap")
                .arg(&domain)
                .arg(plist)
                .output();
            if let Err(e) = check(out, "launchctl bootstrap") {
                if !is_already_loaded(&e) {
                    return ActionResult::fail(e);
                }
            }
        } else {
            let out = Command::new("/bin/launchctl")
                .arg("bootout")
                .arg(&service_target)
                .output();
            if let Err(e) = check(out, "launchctl bootout") {
                if !is_not_loaded(&e) {
                    return ActionResult::fail(e);
                }
            }
        }
    }

    ActionResult::done(format!(
        "{} \"{}\"",
        if enable { "Enabled" } else { "Disabled" },
        item.name
    ))
}

fn verb(enable: bool) -> &'static str {
    if enable {
        "enable"
    } else {
        "disable"
    }
}

/// launchd returns EALREADY / "service already loaded" when bootstrapping a
/// service that is already up.
fn is_already_loaded(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("already loaded") || m.contains("ealready") || m.contains("service already")
}

/// bootout on a service that is not running is not a real failure.
fn is_not_loaded(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("no such process")
        || m.contains("could not find service")
        || m.contains("not loaded")
        || m.contains("esrch")
}

fn delete_launchd_item(item: &StartupItem, sudo: &SudoSession) -> ActionResult {
    let needs_root = item.needs_root();

    if needs_root && !sudo.is_active() {
        return ActionResult::sudo_required(format!(
            "\"{}\" is a system-level item. Enable System Mode to remove it.",
            item.name
        ));
    }

    if item.plist_path.is_none() {
        return ActionResult::fail("No backing plist file to remove.");
    }

    // Stop it first; a still-running service would be restarted by launchd.
    let uid = current_uid();
    let domain = item.launchd_domain(uid);
    if needs_root {
        let _ = sudo.request(Request::Bootout {
            domain: domain.clone(),
            label: item.label.clone(),
        });
    } else {
        let _ = Command::new("/bin/launchctl")
            .arg("bootout")
            .arg(format!("{}/{}", domain, item.label))
            .output();
    }

    match quarantine::quarantine(item, sudo) {
        Ok(_) => ActionResult::done(format!(
            "Moved \"{}\" to LaunchFleet's quarantine. You can restore it from the Quarantine panel.",
            item.name
        )),
        Err(e) => ActionResult::fail(e),
    }
}

// ───────── AppleScript-based toggle (legacy login items) ─────────

fn set_via_applescript(item: &StartupItem, enable: bool) -> ActionResult {
    if enable {
        return ActionResult::system_settings(format!(
            "To enable \"{}\", add it via System Settings > Login Items.",
            item.name
        ));
    }

    let candidates: Vec<String> = [Some(&item.name), Some(&item.label), item.bundle_id.as_ref()]
        .iter()
        .filter_map(|o| o.map(|s| s.to_string()))
        .collect();

    let mut last_error = String::new();

    for candidate in &candidates {
        let escaped = candidate.replace('\\', "\\\\").replace('"', "\\\"");
        let script = format!(
            r#"tell application "System Events" to delete login item "{}""#,
            escaped
        );
        match Command::new("osascript").arg("-e").arg(&script).output() {
            Ok(out) if out.status.success() => {
                return ActionResult::done(format!("Disabled \"{}\"", item.name));
            }
            Ok(out) => {
                last_error = String::from_utf8_lossy(&out.stderr).trim().to_string();
            }
            Err(e) => last_error = e.to_string(),
        }
    }

    // -1743 is errAEEventNotPermitted: the app lacks Automation consent for
    // System Events. Surfacing this is important — it used to be reported as a
    // generic "open System Settings", hiding a fixable permission problem.
    if last_error.contains("-1743") || last_error.contains("not allowed to send Apple events") {
        return ActionResult::fail(format!(
            "macOS blocked LaunchFleet from controlling System Events. \
             Grant access under System Settings > Privacy & Security > Automation, \
             then try \"{}\" again.",
            item.name
        ));
    }

    ActionResult::system_settings(format!(
        "\"{}\" can't be toggled via AppleScript. Open System Settings to manage it.",
        item.name
    ))
}

// ───────── SMLoginItemSetEnabled (app-bundled helpers) ─────────

fn set_via_sm_login(item: &StartupItem, enable: bool) -> ActionResult {
    let bundle_id = match &item.bundle_id {
        Some(b) => b.clone(),
        None => extract_bundle_from_btm_id(&item.label).unwrap_or_else(|| item.label.clone()),
    };

    match sm_login::set_login_item_enabled(&bundle_id, enable) {
        Ok(true) => ActionResult::done(format!(
            "{} \"{}\"",
            if enable { "Enabled" } else { "Disabled" },
            item.name
        )),
        Ok(false) => {
            let fallback = set_via_applescript(item, enable);
            if matches!(fallback.kind, ResultKind::Done | ResultKind::Failed) {
                fallback
            } else {
                ActionResult::system_settings(format!(
                    "\"{}\" couldn't be toggled programmatically. Open System Settings to manage it.",
                    item.name
                ))
            }
        }
        Err(e) => ActionResult::fail(format!("ServiceManagement failed: {}", e)),
    }
}

/// Extract a bundle id from a BTM-style identifier like
/// `4.2BUA8C4S2C.com.1password.browser-helper` -> `com.1password.browser-helper`.
pub fn extract_bundle_from_btm_id(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.splitn(3, '.').collect();
    if parts.len() < 3 {
        return None;
    }
    if !parts[0].chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if parts[1].len() < 6 || parts[1].len() > 12 {
        return None;
    }
    Some(parts[2].to_string())
}

// ───────── Login Hook ─────────

fn disable_login_hook(label: &str) -> ActionResult {
    let key = if label.contains("loginhook") {
        "LoginHook"
    } else {
        "LogoutHook"
    };

    match check(
        Command::new("defaults")
            .arg("delete")
            .arg("com.apple.loginwindow")
            .arg(key)
            .output(),
        "defaults delete",
    ) {
        Ok(_) => ActionResult::done(format!("Removed {} hook", key)),
        Err(e) => ActionResult::fail(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_bundle_id_from_btm_identifier() {
        assert_eq!(
            extract_bundle_from_btm_id("4.2BUA8C4S2C.com.1password.browser-helper").as_deref(),
            Some("com.1password.browser-helper")
        );
    }

    #[test]
    fn rejects_non_btm_identifiers() {
        assert_eq!(extract_bundle_from_btm_id("com.example.app"), None);
        assert_eq!(extract_bundle_from_btm_id("short"), None);
        assert_eq!(extract_bundle_from_btm_id("4.ABC.com.x"), None);
    }

    #[test]
    fn recognises_launchd_already_loaded() {
        assert!(is_already_loaded("Bootstrap failed: 37: Operation already in progress (EALREADY)"));
        assert!(is_already_loaded("service already loaded"));
        assert!(!is_already_loaded("Input/output error"));
    }

    #[test]
    fn recognises_launchd_not_loaded() {
        assert!(is_not_loaded("Boot-out failed: 3: No such process"));
        assert!(is_not_loaded("Could not find service in domain"));
        assert!(!is_not_loaded("Permission denied"));
    }

    #[test]
    fn check_turns_nonzero_exit_into_error() {
        let out = Command::new("/bin/sh").arg("-c").arg("exit 3").output();
        let r = check(out, "test cmd");
        assert!(r.is_err(), "non-zero exit must not be treated as success");
    }

    #[test]
    fn check_accepts_zero_exit() {
        let out = Command::new("/bin/sh").arg("-c").arg("exit 0").output();
        assert!(check(out, "test cmd").is_ok());
    }
}
