use crate::models::{ItemStatus, ItemType, StartupItem};
use std::process::Command;

pub fn collect() -> Vec<StartupItem> {
    let mut items = Vec::new();

    if let Some(path) = read_hook_preference("LoginHook") {
        let mut item = StartupItem::new("com.user.loginhook".to_string(), ItemType::LoginHook);
        item.program = Some(path.clone());
        item.path = Some(std::path::PathBuf::from(&path));
        item.status = ItemStatus::Enabled;
        item.description = Some("Login Hook".to_string());
        items.push(item);
    }

    if let Some(path) = read_hook_preference("LogoutHook") {
        let mut item = StartupItem::new("com.user.logouthook".to_string(), ItemType::LoginHook);
        item.program = Some(path.clone());
        item.path = Some(std::path::PathBuf::from(&path));
        item.status = ItemStatus::Enabled;
        item.description = Some("Logout Hook".to_string());
        items.push(item);
    }

    items
}

fn read_hook_preference(key: &str) -> Option<String> {
    let output = Command::new("defaults")
        .arg("read")
        .arg("com.apple.loginwindow")
        .arg(key)
        .output()
        .ok()?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let value = stdout.trim().trim_matches('"');
        if !value.is_empty() {
            return Some(value.to_string());
        }
    }

    None
}
