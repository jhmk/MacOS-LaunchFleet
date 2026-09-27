use super::launchd_plist;
use crate::models::{ItemType, StartupItem};
use std::path::{Path, PathBuf};

pub fn collect_user() -> Vec<StartupItem> {
    launchd_plist::collect_dir(&home_launch_agents_dir(), ItemType::UserLaunchAgent)
}

pub fn collect_system() -> Vec<StartupItem> {
    launchd_plist::collect_dir(Path::new("/Library/LaunchAgents"), ItemType::SystemLaunchAgent)
}

fn home_launch_agents_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/unknown".to_string());
    Path::new(&home).join("Library/LaunchAgents")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_agents_are_not_root_owned() {
        for item in collect_user() {
            assert!(
                !item.requires_sudo,
                "{} lives in the user's home and must not need root",
                item.label
            );
        }
    }

    #[test]
    fn system_agents_require_root() {
        for item in collect_system() {
            assert!(item.requires_sudo, "{} must require root", item.label);
        }
    }
}
