use super::launchd_plist;
use crate::models::{ItemType, StartupItem};
use std::path::Path;

const DAEMON_DIRS: &[&str] = &["/Library/LaunchDaemons"];

pub fn collect() -> Vec<StartupItem> {
    let mut items = Vec::new();
    for dir_path in DAEMON_DIRS {
        items.extend(launchd_plist::collect_dir(
            Path::new(dir_path),
            ItemType::LaunchDaemon,
        ));
    }
    items
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privileged::{validate_in_allowed_dirs, ALLOWED_PRIVILEGED_DIRS};

    #[test]
    fn every_daemon_requires_root() {
        for item in collect() {
            assert!(item.requires_sudo, "{} must require root", item.label);
        }
    }

    #[test]
    fn daemon_plists_are_inside_the_privileged_allowlist() {
        // Guards against a collector change that would make delete/quarantine
        // start rejecting legitimate items.
        for item in collect() {
            let Some(p) = item.plist_path.as_ref() else {
                continue;
            };
            assert!(
                validate_in_allowed_dirs(p, ALLOWED_PRIVILEGED_DIRS).is_ok(),
                "{} should be operable by the privileged helper",
                p.display()
            );
        }
    }
}
