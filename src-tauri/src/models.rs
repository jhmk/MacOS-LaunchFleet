use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ItemType {
    LoginItem,
    UserLaunchAgent,
    SystemLaunchAgent,
    LaunchDaemon,
    LoginHook,
    CronJob,
}

impl ItemType {
    pub fn label(&self) -> &'static str {
        match self {
            ItemType::LoginItem => "Login Item",
            ItemType::UserLaunchAgent => "User Agent",
            ItemType::SystemLaunchAgent => "System Agent",
            ItemType::LaunchDaemon => "Daemon",
            ItemType::LoginHook => "Login Hook",
            ItemType::CronJob => "Cron",
        }
    }
}

impl fmt::Display for ItemType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ItemStatus {
    Enabled,
    Disabled,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunningState {
    Running,
    Stopped,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImpactLevel {
    High,
    Medium,
    Low,
    Minimal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToggleMethod {
    /// User/system launchd plist that we can directly modify
    Launchctl,
    /// Legacy login items visible to System Events (AppleScript)
    AppleScript,
    /// App-bundled helper - try SMLoginItemSetEnabled
    SMLoginItem,
    /// Modern BTM agent/daemon - no programmatic API, must use System Settings
    SystemSettingsOnly,
    /// Login/logout hook via defaults
    LoginHook,
    /// Apple, cron, etc - cannot be modified
    ReadOnly,
}

impl ImpactLevel {
    pub fn label(&self) -> &'static str {
        match self {
            ImpactLevel::High => "HIGH",
            ImpactLevel::Medium => "MED",
            ImpactLevel::Low => "LOW",
            ImpactLevel::Minimal => "MIN",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartupItem {
    /// Stable, globally unique key. `label` is NOT unique: `sfltool dumpbtm`
    /// emits the same identifier as both `Identifier` and `Bundle Identifier`,
    /// and a launchd `Label` may legitimately repeat across
    /// ~/Library/LaunchAgents, /Library/LaunchAgents and /Library/LaunchDaemons.
    /// Looking items up by label could act on the wrong one — which mattered a
    /// great deal for the Delete button.
    pub id: String,
    pub label: String,
    pub name: String,
    pub item_type: ItemType,
    pub status: ItemStatus,
    pub running: RunningState,
    pub is_apple: bool,
    pub is_orphan: bool,
    pub impact: ImpactLevel,
    pub requires_sudo: bool,
    pub path: Option<PathBuf>,
    pub program: Option<String>,
    pub arguments: Vec<String>,
    pub run_at_load: Option<bool>,
    pub keep_alive: Option<bool>,
    pub description: Option<String>,
    pub working_directory: Option<String>,
    pub start_interval: Option<u64>,
    pub plist_path: Option<PathBuf>,
    pub btm_type: Option<String>,
    pub parent_app: Option<String>,
    pub bundle_id: Option<String>,
    pub toggle_method: ToggleMethod,
    /// UID of the BTM record this came from. `sfltool dumpbtm` reports records
    /// for every user on the system (0, 88, -2, ...), and the login-item APIs
    /// only ever act on the calling user's session.
    pub uid: Option<i64>,
    /// True when the record belongs to another user and therefore cannot be
    /// toggled from this session.
    pub foreign_user: bool,
}

impl StartupItem {
    pub fn new(label: String, item_type: ItemType) -> Self {
        let is_apple = label.starts_with("com.apple.") || label.starts_with("com.Apple.");

        let name = Self::extract_name(&label);

        let requires_sudo = matches!(
            &item_type,
            ItemType::SystemLaunchAgent | ItemType::LaunchDaemon
        );

        let toggle_method = match &item_type {
            ItemType::LoginItem => ToggleMethod::SystemSettingsOnly,
            ItemType::UserLaunchAgent | ItemType::SystemLaunchAgent | ItemType::LaunchDaemon => {
                ToggleMethod::Launchctl
            }
            ItemType::LoginHook => ToggleMethod::LoginHook,
            ItemType::CronJob => ToggleMethod::ReadOnly,
        };

        Self {
            id: String::new(),
            name,
            label,
            status: ItemStatus::Unknown,
            running: RunningState::Unknown,
            is_apple,
            is_orphan: false,
            impact: ImpactLevel::Low,
            requires_sudo,
            path: None,
            program: None,
            arguments: Vec::new(),
            run_at_load: None,
            keep_alive: None,
            description: None,
            working_directory: None,
            start_interval: None,
            plist_path: None,
            btm_type: None,
            parent_app: None,
            bundle_id: None,
            toggle_method,
            item_type,
            uid: None,
            foreign_user: false,
        }
    }

    /// Deterministic identity for this item, derived from whatever uniquely
    /// distinguishes it. Disambiguated against collisions by `collect_all`.
    pub fn base_id(&self) -> String {
        let discriminator = match &self.plist_path {
            Some(p) => p.to_string_lossy().into_owned(),
            None => match self.uid {
                Some(uid) => format!("{}@{}", self.label, uid),
                None => self.label.clone(),
            },
        };
        format!("{:?}|{}", self.item_type, discriminator)
    }

    fn extract_name(label: &str) -> String {
        // Try to make a friendlier name
        let parts: Vec<&str> = label.split('.').collect();

        // Common patterns like com.spotify.client -> "Spotify Client"
        if parts.len() >= 3 && (parts[0] == "com" || parts[0] == "org" || parts[0] == "net") {
            let app_part = parts[1];
            let mut result = capitalize(app_part);
            if parts.len() > 2 {
                let rest = parts[2..].join(" ");
                result.push(' ');
                result.push_str(&capitalize(&rest));
            }
            return result;
        }

        label.split('.').next_back().unwrap_or(label).to_string()
    }

    pub fn compute_impact(&mut self) {
        self.impact = match &self.item_type {
            ItemType::LoginItem => {
                // A login item that launches a full app at every login is not
                // "Minimal"; weight by what the BTM record actually is.
                let t = self.btm_type.as_deref().unwrap_or("");
                if t.starts_with("app") {
                    ImpactLevel::Medium
                } else if t.starts_with("legacy daemon") || t.starts_with("daemon") {
                    ImpactLevel::High
                } else if t.starts_with("legacy agent") || t.starts_with("agent") {
                    ImpactLevel::Medium
                } else {
                    ImpactLevel::Minimal
                }
            }
            ItemType::UserLaunchAgent | ItemType::SystemLaunchAgent => {
                if self.run_at_load == Some(true) && self.keep_alive == Some(true) {
                    ImpactLevel::High
                } else if self.run_at_load == Some(true) {
                    ImpactLevel::Medium
                } else if self.start_interval.is_some() {
                    ImpactLevel::Low
                } else {
                    ImpactLevel::Medium
                }
            }
            ItemType::LaunchDaemon => {
                if self.run_at_load == Some(true) {
                    ImpactLevel::High
                } else {
                    ImpactLevel::Medium
                }
            }
            ItemType::LoginHook => ImpactLevel::Medium,
            ItemType::CronJob => ImpactLevel::Low,
        };
    }

    /// launchd service target domain for this item.
    pub fn launchd_domain(&self, uid: u32) -> String {
        if self.requires_sudo
            || matches!(
                self.item_type,
                ItemType::SystemLaunchAgent | ItemType::LaunchDaemon
            )
        {
            "system".to_string()
        } else {
            format!("gui/{}", uid)
        }
    }

    pub fn needs_root(&self) -> bool {
        self.requires_sudo
            || matches!(
                self.item_type,
                ItemType::SystemLaunchAgent | ItemType::LaunchDaemon
            )
    }
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_name_handles_reverse_dns() {
        assert_eq!(
            StartupItem::extract_name("com.spotify.client"),
            "Spotify Client"
        );
        assert_eq!(
            StartupItem::extract_name("org.mozilla.updater"),
            "Mozilla Updater"
        );
    }

    #[test]
    fn extract_name_falls_back_to_last_component() {
        assert_eq!(StartupItem::extract_name("somedaemon"), "somedaemon");
        assert_eq!(StartupItem::extract_name("a.b"), "b");
    }

    #[test]
    fn base_id_distinguishes_same_label_in_different_domains() {
        let mut a = StartupItem::new("com.example.helper".into(), ItemType::UserLaunchAgent);
        a.plist_path = Some(PathBuf::from("/Users/x/Library/LaunchAgents/h.plist"));

        let mut b = StartupItem::new("com.example.helper".into(), ItemType::LaunchDaemon);
        b.plist_path = Some(PathBuf::from("/Library/LaunchDaemons/h.plist"));

        assert_ne!(a.base_id(), b.base_id());
    }

    #[test]
    fn base_id_distinguishes_btm_records_per_uid() {
        let mut a = StartupItem::new("com.example.app".into(), ItemType::LoginItem);
        a.uid = Some(501);
        let mut b = StartupItem::new("com.example.app".into(), ItemType::LoginItem);
        b.uid = Some(0);

        assert_ne!(a.base_id(), b.base_id());
    }

    #[test]
    fn daemons_target_the_system_domain() {
        let d = StartupItem::new("com.example.d".into(), ItemType::LaunchDaemon);
        assert_eq!(d.launchd_domain(501), "system");

        let a = StartupItem::new("com.example.a".into(), ItemType::UserLaunchAgent);
        assert_eq!(a.launchd_domain(501), "gui/501");
    }
}
