use crate::models::{ItemStatus, ItemType, RunningState, StartupItem, ToggleMethod};
use std::process::Command;

pub fn collect() -> Vec<StartupItem> {
    let output = match Command::new("sfltool").arg("dumpbtm").output() {
        Ok(out) => out,
        Err(_) => return Vec::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_btm(&stdout, current_uid())
}

fn current_uid() -> i64 {
    unsafe { libc::getuid() as i64 }
}

#[derive(Default, Debug)]
struct BtmItem {
    name: Option<String>,
    developer_name: Option<String>,
    item_type: Option<String>,
    disposition: Option<String>,
    identifier: Option<String>,
    uuid: Option<String>,
    url: Option<String>,
    executable_path: Option<String>,
    bundle_identifier: Option<String>,
    parent_identifier: Option<String>,
    team_identifier: Option<String>,
    /// Which `Records for UID <n>` section this record appeared under.
    uid: Option<i64>,
}

/// Parse `sfltool dumpbtm`.
///
/// `dumpbtm` reports records for **every** UID on the machine (0, 88, -2, the
/// console user, ...). The previous parser ignored the section headers, so
/// root's and `_windowserver`'s login items were presented as if they were the
/// current user's — and toggling them could never work, because
/// `SMLoginItemSetEnabled` and System Events only act on the calling session.
pub fn parse_btm(output: &str, current_uid: i64) -> Vec<StartupItem> {
    let mut items: Vec<StartupItem> = Vec::new();
    let mut current: Option<BtmItem> = None;
    let mut parent_lookup: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    let mut section_uid: Option<i64> = None;

    macro_rules! flush {
        () => {
            if let Some(btm) = current.take() {
                record_parent(&btm, &mut parent_lookup);
                if let Some(item) = btm_to_startup(btm, current_uid) {
                    items.push(item);
                }
            }
        };
    }

    for line in output.lines() {
        let trimmed = line.trim_start();

        // Section header: " Records for UID 501 : <uuid>"
        if let Some(uid) = parse_uid_header(trimmed) {
            flush!();
            section_uid = Some(uid);
            continue;
        }

        // Record header: " #12:"
        if line.starts_with(" #") && line.trim_end().ends_with(':') {
            flush!();
            let mut fresh = BtmItem::default();
            fresh.uid = section_uid;
            current = Some(fresh);
            continue;
        }

        if line.starts_with("===") {
            flush!();
            continue;
        }

        let Some(ref mut item) = current else {
            continue;
        };

        if let Some((key, value)) = trimmed.split_once(':') {
            let key = key.trim();
            let value = value.trim();
            if value.is_empty() || value == "(null)" {
                continue;
            }
            match key {
                "Name" => item.name = Some(value.to_string()),
                "Developer Name" => item.developer_name = Some(value.to_string()),
                "Type" => item.item_type = Some(value.to_string()),
                "Disposition" => item.disposition = Some(value.to_string()),
                "Identifier" => item.identifier = Some(value.to_string()),
                "UUID" => item.uuid = Some(value.to_string()),
                "URL" => item.url = Some(value.to_string()),
                "Executable Path" => item.executable_path = Some(value.to_string()),
                "Bundle Identifier" => item.bundle_identifier = Some(value.to_string()),
                "Parent Identifier" => item.parent_identifier = Some(value.to_string()),
                "Team Identifier" => item.team_identifier = Some(value.to_string()),
                _ => {}
            }
        }
    }

    flush!();

    for item in &mut items {
        if let Some(ref pid) = item.parent_app.clone() {
            if let Some(name) = parent_lookup.get(pid) {
                item.parent_app = Some(name.clone());
            }
        }
    }

    items
}

/// Matches `Records for UID 501 : 99E9347E-...` and negative UIDs like `-2`.
fn parse_uid_header(line: &str) -> Option<i64> {
    let rest = line.strip_prefix("Records for UID")?;
    let rest = rest.trim_start();
    let token: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '-')
        .collect();
    token.parse::<i64>().ok()
}

fn record_parent(btm: &BtmItem, parent_lookup: &mut std::collections::HashMap<String, String>) {
    if let (Some(id), Some(name)) = (&btm.identifier, &btm.name) {
        parent_lookup.insert(id.clone(), name.clone());
    }
}

fn btm_to_startup(btm: BtmItem, current_uid: i64) -> Option<StartupItem> {
    let type_str = btm.item_type.as_deref().unwrap_or("");
    if type_str.starts_with("developer") {
        return None;
    }

    let label = btm
        .bundle_identifier
        .clone()
        .or_else(|| btm.identifier.clone())
        .or_else(|| btm.name.clone())?;

    let display_name = btm.name.clone().unwrap_or_else(|| label.clone());

    let mut item = StartupItem::new(label.clone(), ItemType::LoginItem);
    item.name = display_name;
    item.bundle_id = btm.bundle_identifier.clone();
    item.btm_type = btm.item_type.clone();
    item.parent_app = btm.parent_identifier.clone();
    item.uid = btm.uid;
    item.foreign_user = matches!(btm.uid, Some(u) if u != current_uid);

    item.toggle_method = if type_str.starts_with("legacy daemon") || type_str.starts_with("legacy agent")
    {
        ToggleMethod::Launchctl
    } else if type_str.starts_with("login item") {
        ToggleMethod::SMLoginItem
    } else if type_str.starts_with("app") {
        ToggleMethod::AppleScript
    } else {
        ToggleMethod::SystemSettingsOnly
    };

    let disp = btm.disposition.as_deref().unwrap_or("");
    item.status = if disp.contains("disabled") {
        ItemStatus::Disabled
    } else if disp.contains("enabled") {
        ItemStatus::Enabled
    } else {
        ItemStatus::Unknown
    };

    if let Some(path_str) = btm.executable_path.as_ref() {
        item.program = Some(path_str.clone());
        item.path = Some(std::path::PathBuf::from(path_str));
    } else if let Some(url) = btm.url.as_ref() {
        let path_str = url.strip_prefix("file://").unwrap_or(url);
        let decoded = url_decode(path_str);
        item.program = Some(decoded.clone());
        item.path = Some(std::path::PathBuf::from(decoded));
    }

    if matches!(item.toggle_method, ToggleMethod::Launchctl) {
        if let Some(url) = btm.url.as_ref() {
            let path_str = url.strip_prefix("file://").unwrap_or(url);
            let decoded = url_decode(path_str);
            if decoded.ends_with(".plist") {
                item.plist_path = Some(std::path::PathBuf::from(&decoded));
                if decoded.starts_with("/Library/") || decoded.starts_with("/System/") {
                    item.requires_sudo = true;
                }
            }
        }
    }

    let dev_name = btm.developer_name.clone();
    item.is_apple = item.label.starts_with("com.apple.")
        || dev_name.as_deref() == Some("Apple Inc.")
        || btm.team_identifier.as_deref() == Some("Apple");

    if item.is_apple {
        item.toggle_method = ToggleMethod::ReadOnly;
    }

    let mut desc_parts = Vec::new();
    if let Some(t) = btm.item_type {
        desc_parts.push(t);
    }
    if let Some(d) = dev_name {
        desc_parts.push(format!("by {}", d));
    }
    if let Some(uid) = btm.uid {
        if uid != current_uid {
            desc_parts.push(format!("uid {}", uid));
        }
    }
    if !desc_parts.is_empty() {
        item.description = Some(desc_parts.join(" · "));
    }

    item.running = RunningState::Unknown;

    Some(item)
}

/// Percent-decode a URL path.
///
/// The previous version did `result.push(byte as char)`, which maps each
/// decoded byte to U+00XX (Latin-1). `%C3%A9` became "Ã©" instead of "é", the
/// mangled path then failed `Path::exists()`, and every app with a non-ASCII
/// name was wrongly flagged as an orphan. Decode into bytes, then interpret the
/// whole buffer as UTF-8.
pub fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
========================
 Records for UID -2 : FFFFEEEE-DDDD-CCCC-BBBB-AAAAFFFFFFFE
========================

 Items:

 #1:
                 UUID: 11111111-2222-3333-4444-555555555555
                 Name: Ghost Helper
       Developer Name: Some Vendor
                 Type: login item (0x10)
          Disposition: [enabled, allowed, visible] (0xd)
           Identifier: com.ghost.helper
    Bundle Identifier: com.ghost.helper

========================
 Records for UID 501 : CCCCCCCC-DDDD-EEEE-FFFF-000000000000
========================

 Items:

 #1:
                 UUID: AAAAAAAA-E1EF-41E7-AA91-65372813D384
                 Name: Café Player
       Developer Name: Café Inc.
                 Type: app (0x1)
          Disposition: [enabled, allowed, visible] (0xd)
           Identifier: com.cafe.player
    Bundle Identifier: com.cafe.player
                  URL: file:///Applications/Caf%C3%A9%20Player.app/

 #2:
                 UUID: BBBBBBBB-E1EF-41E7-AA91-65372813D384
                 Name: Apple Thing
       Developer Name: Apple Inc.
                 Type: login item (0x10)
          Disposition: [disabled, allowed, visible] (0x2)
           Identifier: com.apple.thing
    Bundle Identifier: com.apple.thing
"#;

    #[test]
    fn parses_uid_section_headers() {
        assert_eq!(
            parse_uid_header("Records for UID 501 : 99E9347E-1533"),
            Some(501)
        );
        assert_eq!(
            parse_uid_header("Records for UID -2 : FFFFEEEE"),
            Some(-2)
        );
        assert_eq!(parse_uid_header("Items:"), None);
    }

    #[test]
    fn assigns_records_to_the_right_uid() {
        let items = parse_btm(SAMPLE, 501);
        let ghost = items.iter().find(|i| i.label == "com.ghost.helper").unwrap();
        assert_eq!(ghost.uid, Some(-2));
        assert!(
            ghost.foreign_user,
            "records from another UID must be marked foreign"
        );

        let cafe = items.iter().find(|i| i.label == "com.cafe.player").unwrap();
        assert_eq!(cafe.uid, Some(501));
        assert!(!cafe.foreign_user);
    }

    #[test]
    fn decodes_non_ascii_paths_as_utf8() {
        assert_eq!(
            url_decode("/Applications/Caf%C3%A9%20Player.app/"),
            "/Applications/Café Player.app/"
        );
    }

    #[test]
    fn url_decode_leaves_plain_paths_alone() {
        assert_eq!(url_decode("/Applications/Safari.app"), "/Applications/Safari.app");
    }

    #[test]
    fn non_ascii_app_path_survives_parsing() {
        let items = parse_btm(SAMPLE, 501);
        let cafe = items.iter().find(|i| i.label == "com.cafe.player").unwrap();
        assert_eq!(
            cafe.path.as_ref().unwrap().to_string_lossy(),
            "/Applications/Café Player.app/"
        );
    }

    #[test]
    fn apple_items_are_read_only() {
        let items = parse_btm(SAMPLE, 501);
        let apple = items.iter().find(|i| i.label == "com.apple.thing").unwrap();
        assert!(apple.is_apple);
        assert_eq!(apple.toggle_method, crate::models::ToggleMethod::ReadOnly);
        assert_eq!(apple.status, ItemStatus::Disabled);
    }

    #[test]
    fn skips_developer_umbrella_records() {
        let input = " #1:\n                 Type: developer (0x20)\n           Identifier: Some Dev\n                 Name: Some Dev\n";
        assert!(parse_btm(input, 501).is_empty());
    }
}
