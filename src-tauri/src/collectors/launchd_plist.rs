//! Shared launchd plist parsing for LaunchAgents and LaunchDaemons.

use crate::models::{ItemStatus, ItemType, RunningState, StartupItem};
use plist::Value;
use std::fs;
use std::path::Path;

/// Parse a launchd job description.
///
/// `plist::Value::from_reader` already handles both XML and binary plists, so
/// the previous "read bytes, fail, re-wrap the same bytes as a string, try
/// again" fallback could never succeed where the first attempt failed.
pub fn parse(path: &Path, item_type: ItemType) -> Option<StartupItem> {
    let data = fs::read(path).ok()?;
    let val = Value::from_reader(std::io::Cursor::new(data)).ok()?;
    let dict = val.into_dictionary()?;

    // A job without a Label cannot be addressed via launchctl at all. Fall back
    // to the filename, which is what launchd itself effectively does.
    let label = dict
        .get("Label")
        .and_then(|v| v.as_string())
        .map(String::from)
        .or_else(|| path.file_stem().map(|s| s.to_string_lossy().into_owned()))?;

    let mut item = StartupItem::new(label, item_type);
    item.plist_path = Some(path.to_path_buf());
    if matches!(
        item_type,
        ItemType::LaunchDaemon | ItemType::SystemLaunchAgent
    ) {
        item.requires_sudo = true;
    }

    if let Some(program) = dict.get("Program").and_then(|v| v.as_string()) {
        item.program = Some(program.to_string());
        item.path = Some(std::path::PathBuf::from(program));
    }

    if let Some(args) = dict.get("ProgramArguments").and_then(|v| v.as_array()) {
        item.arguments = args
            .iter()
            .filter_map(|v| v.as_string().map(String::from))
            .collect();

        if item.program.is_none() && !item.arguments.is_empty() {
            item.program = Some(item.arguments[0].clone());
            item.path = Some(std::path::PathBuf::from(&item.arguments[0]));
        }
    }

    if let Some(working_dir) = dict.get("WorkingDirectory").and_then(|v| v.as_string()) {
        item.working_directory = Some(working_dir.to_string());
    }

    item.run_at_load = dict.get("RunAtLoad").and_then(|v| v.as_boolean());
    item.keep_alive = parse_keep_alive(dict.get("KeepAlive"));

    item.status = if dict.get("Disabled").and_then(|v| v.as_boolean()) == Some(true) {
        ItemStatus::Disabled
    } else {
        ItemStatus::Enabled
    };

    if let Some(interval) = dict
        .get("StartInterval")
        .and_then(|v| v.as_unsigned_integer())
    {
        item.start_interval = Some(interval);
    }

    item.running = RunningState::Unknown;
    Some(item)
}

/// `KeepAlive` is frequently a *dictionary* of conditions rather than a bool
/// (e.g. `{ SuccessfulExit = false; }`). `as_boolean()` returns `None` for
/// those, which previously made conditionally-restarting jobs look like they
/// had no keepalive at all and understated their impact rating.
fn parse_keep_alive(v: Option<&Value>) -> Option<bool> {
    match v {
        Some(Value::Boolean(b)) => Some(*b),
        Some(Value::Dictionary(_)) => Some(true),
        _ => None,
    }
}

pub fn collect_dir(dir: &Path, item_type: ItemType) -> Vec<StartupItem> {
    let mut items = Vec::new();

    let Ok(entries) = fs::read_dir(dir) else {
        return items;
    };

    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "plist") {
            if let Some(item) = parse(&path, item_type) {
                items.push(item);
            }
        }
    }

    items
}

#[cfg(test)]
mod tests {
    use super::*;
    use plist::Dictionary;

    fn write_plist(dir: &Path, name: &str, body: &str) -> std::path::PathBuf {
        let p = dir.join(name);
        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>{}</dict></plist>"#,
            body
        );
        fs::write(&p, xml).unwrap();
        p
    }

    fn tmpdir() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("lf-test-{}", std::process::id()));
        let _ = fs::create_dir_all(&d);
        d
    }

    #[test]
    fn parses_basic_agent() {
        let dir = tmpdir();
        let p = write_plist(
            &dir,
            "basic.plist",
            "<key>Label</key><string>com.example.agent</string>\
             <key>Program</key><string>/usr/bin/true</string>\
             <key>RunAtLoad</key><true/>",
        );
        let item = parse(&p, ItemType::UserLaunchAgent).unwrap();
        assert_eq!(item.label, "com.example.agent");
        assert_eq!(item.program.as_deref(), Some("/usr/bin/true"));
        assert_eq!(item.run_at_load, Some(true));
        assert_eq!(item.status, ItemStatus::Enabled);
        let _ = fs::remove_file(p);
    }

    #[test]
    fn keep_alive_dictionary_counts_as_enabled() {
        let dir = tmpdir();
        let p = write_plist(
            &dir,
            "ka.plist",
            "<key>Label</key><string>com.example.ka</string>\
             <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>",
        );
        let item = parse(&p, ItemType::UserLaunchAgent).unwrap();
        assert_eq!(
            item.keep_alive,
            Some(true),
            "dictionary KeepAlive must not be read as 'no keepalive'"
        );
        let _ = fs::remove_file(p);
    }

    #[test]
    fn disabled_key_is_honoured() {
        let dir = tmpdir();
        let p = write_plist(
            &dir,
            "dis.plist",
            "<key>Label</key><string>com.example.dis</string><key>Disabled</key><true/>",
        );
        let item = parse(&p, ItemType::UserLaunchAgent).unwrap();
        assert_eq!(item.status, ItemStatus::Disabled);
        let _ = fs::remove_file(p);
    }

    #[test]
    fn program_arguments_fill_in_missing_program() {
        let dir = tmpdir();
        let p = write_plist(
            &dir,
            "args.plist",
            "<key>Label</key><string>com.example.args</string>\
             <key>ProgramArguments</key><array><string>/bin/sh</string><string>-c</string><string>echo</string></array>",
        );
        let item = parse(&p, ItemType::UserLaunchAgent).unwrap();
        assert_eq!(item.program.as_deref(), Some("/bin/sh"));
        assert_eq!(item.arguments.len(), 3);
        let _ = fs::remove_file(p);
    }

    #[test]
    fn binary_plists_are_supported() {
        let dir = tmpdir();
        let p = dir.join("bin.plist");
        let mut d = Dictionary::new();
        d.insert("Label".into(), Value::String("com.example.bin".into()));
        Value::Dictionary(d)
            .to_file_binary(&p)
            .expect("write binary plist");

        let item = parse(&p, ItemType::LaunchDaemon).unwrap();
        assert_eq!(item.label, "com.example.bin");
        assert!(item.requires_sudo, "daemons must require root");
        let _ = fs::remove_file(p);
    }

    #[test]
    fn missing_label_falls_back_to_filename() {
        let dir = tmpdir();
        let p = write_plist(&dir, "com.fallback.job.plist", "<key>RunAtLoad</key><true/>");
        let item = parse(&p, ItemType::UserLaunchAgent).unwrap();
        assert_eq!(item.label, "com.fallback.job");
        let _ = fs::remove_file(p);
    }

    #[test]
    fn malformed_plist_is_skipped_not_panicking() {
        let dir = tmpdir();
        let p = dir.join("bad.plist");
        fs::write(&p, b"this is not a plist").unwrap();
        assert!(parse(&p, ItemType::UserLaunchAgent).is_none());
        let _ = fs::remove_file(p);
    }

    #[test]
    fn collect_dir_on_missing_directory_is_empty() {
        assert!(collect_dir(Path::new("/nonexistent/launchfleet"), ItemType::LaunchDaemon).is_empty());
    }
}
