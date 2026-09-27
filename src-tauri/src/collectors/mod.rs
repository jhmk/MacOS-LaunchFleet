pub mod cron;
pub mod hooks;
pub mod launch_agents;
pub mod launch_daemons;
pub mod launchd_plist;
pub mod login_items;

use crate::models::{RunningState, StartupItem};
use crate::privileged::Request;
use crate::sudo::SudoSession;
use std::collections::{HashMap, HashSet};
use std::process::Command;

pub fn collect_all(sudo: Option<&SudoSession>) -> Vec<StartupItem> {
    let mut items = Vec::new();

    items.extend(login_items::collect());
    items.extend(launch_agents::collect_user());
    items.extend(launch_agents::collect_system());
    items.extend(launch_daemons::collect());
    items.extend(hooks::collect());
    items.extend(cron::collect());

    for item in &mut items {
        item.compute_impact();
    }

    assign_ids(&mut items);
    mark_orphans(&mut items);
    mark_running(&mut items, sudo);

    items
}

/// Give every item a globally unique, stable id.
///
/// `base_id()` is derived from the plist path (or label + uid), which is unique
/// in practice, but `sfltool dumpbtm` really does emit duplicate identifiers —
/// verified on a real machine, where a licensing helper appeared under the same
/// string as both `Identifier` and `Bundle Identifier`. Anything still colliding
/// gets a deterministic `#n` suffix so the frontend can never address two
/// different items with the same key.
fn assign_ids(items: &mut [StartupItem]) {
    let mut seen: HashMap<String, u32> = HashMap::new();
    for item in items.iter_mut() {
        let base = item.base_id();
        let counter = seen.entry(base.clone()).or_insert(0);
        item.id = if *counter == 0 {
            base.clone()
        } else {
            format!("{}#{}", base, counter)
        };
        *counter += 1;
    }
}

fn mark_orphans(items: &mut [StartupItem]) {
    for item in items.iter_mut() {
        if let Some(ref path) = item.path {
            item.is_orphan = !path.exists();
        } else if let Some(ref program) = item.program {
            item.is_orphan = !std::path::Path::new(program).exists();
        }
    }
}

/// Determine which services are actually loaded.
///
/// `launchctl list` only covers the caller's GUI domain. Verified on a real
/// machine: of three installed third-party LaunchDaemons (audio hardware, VPN
/// and a filesystem extension), zero appeared in `launchctl list` — so every
/// daemon used to render as "○ idle".
/// System-domain state requires root, so we only report it when System Mode is
/// active, and otherwise leave daemons as `Unknown` rather than lying.
fn mark_running(items: &mut [StartupItem], sudo: Option<&SudoSession>) {
    let user_services = Command::new("/bin/launchctl")
        .arg("list")
        .output()
        .ok()
        .map(|o| parse_service_table(&String::from_utf8_lossy(&o.stdout)))
        .unwrap_or_default();

    let system_services: Option<HashSet<String>> = sudo
        .filter(|s| s.is_active())
        .and_then(|s| {
            s.request(Request::PrintDomain {
                domain: "system".into(),
            })
            .ok()
        })
        .filter(|r| r.ok())
        .map(|r| parse_service_table(&r.stdout));

    for item in items.iter_mut() {
        if item.needs_root() {
            item.running = match &system_services {
                Some(set) => {
                    if set.contains(&item.label) {
                        RunningState::Running
                    } else {
                        RunningState::Stopped
                    }
                }
                None => RunningState::Unknown,
            };
        } else {
            item.running = if user_services.contains(&item.label) {
                RunningState::Running
            } else {
                RunningState::Stopped
            };
        }
    }
}

/// Extract loaded service labels from either `launchctl list` or the
/// `services = { ... }` block of `launchctl print <domain>`. Both render rows
/// as `<pid-or-dash> <last-exit-status> <label>`.
fn parse_service_table(output: &str) -> HashSet<String> {
    let mut set = HashSet::new();
    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 3 {
            continue;
        }
        let pid_field = parts[0];
        let is_pid = pid_field == "-" || pid_field.parse::<i64>().is_ok();
        // Second column is an exit status; this also filters the "PID Status
        // Label" header emitted by `launchctl list`.
        let is_status = parts[1].parse::<i64>().is_ok();
        if is_pid && is_status {
            set.insert(parts[2].to_string());
        }
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ItemType;

    #[test]
    fn parses_launchctl_list_output() {
        let out = "PID\tStatus\tLabel\n1011\t0\tcom.apple.progressd\n-\t0\tcom.apple.SafariHistoryServiceAgent\n";
        let set = parse_service_table(out);
        assert!(set.contains("com.apple.progressd"));
        assert!(set.contains("com.apple.SafariHistoryServiceAgent"));
        assert!(!set.contains("Label"), "header row must be ignored");
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn parses_launchctl_print_services_block() {
        let out = "\tservices = {\n\t\t 1234\t0\tcom.example.daemon\n\t\t    -\t0\tcom.other.daemon\n\t}\n";
        let set = parse_service_table(out);
        assert!(set.contains("com.example.daemon"));
        assert!(set.contains("com.other.daemon"));
    }

    #[test]
    fn assign_ids_disambiguates_collisions() {
        let mut items = vec![
            StartupItem::new("com.dup.thing".into(), ItemType::LoginItem),
            StartupItem::new("com.dup.thing".into(), ItemType::LoginItem),
            StartupItem::new("com.unique.thing".into(), ItemType::LoginItem),
        ];
        assign_ids(&mut items);

        let ids: HashSet<&str> = items.iter().map(|i| i.id.as_str()).collect();
        assert_eq!(ids.len(), 3, "ids must be unique even for identical labels");
        assert!(!items[0].id.is_empty());
        assert_ne!(items[0].id, items[1].id);
    }

    #[test]
    fn assign_ids_is_deterministic() {
        let build = || {
            vec![
                StartupItem::new("com.a.b".into(), ItemType::LoginItem),
                StartupItem::new("com.a.b".into(), ItemType::LoginItem),
            ]
        };
        let mut first = build();
        let mut second = build();
        assign_ids(&mut first);
        assign_ids(&mut second);
        assert_eq!(first[0].id, second[0].id);
        assert_eq!(first[1].id, second[1].id);
    }
}
