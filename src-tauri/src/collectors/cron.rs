use crate::models::{ItemStatus, ItemType, RunningState, StartupItem};
use std::process::Command;

pub fn collect() -> Vec<StartupItem> {
    let mut items = Vec::new();

    if let Ok(output) = Command::new("crontab").arg("-l").output() {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            items.extend(parse_crontab(&stdout));
        }
    }

    collect_periodic_jobs(&mut items);

    items
}

/// Parse a user crontab.
///
/// Handles `@`-shortcuts (`@reboot`, `@daily`, ...) in addition to the 5-field
/// time spec. `@reboot` in particular is a genuine startup item, and the
/// previous 6-field minimum silently dropped it — exactly the kind of hidden
/// auto-starter this app exists to surface.
pub fn parse_crontab(text: &str) -> Vec<StartupItem> {
    let mut items = Vec::new();
    let mut job_index = 0usize;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // Environment assignments such as PATH=/usr/bin are not jobs.
        if is_env_assignment(trimmed) {
            continue;
        }

        let (schedule, command) = match split_cron_line(trimmed) {
            Some(v) => v,
            None => continue,
        };

        let mut item = StartupItem::new(format!("com.user.cron.{}", job_index), ItemType::CronJob);
        job_index += 1;

        item.name = format!("cron: {}", first_token(&command));
        item.program = Some(command.clone());
        item.description = Some(format!("Cron: {} | {}", schedule, command));
        item.status = ItemStatus::Enabled;
        item.running = RunningState::Unknown;
        // Only @reboot actually runs at startup.
        item.run_at_load = Some(schedule.eq_ignore_ascii_case("@reboot"));
        items.push(item);
    }

    items
}

fn is_env_assignment(line: &str) -> bool {
    match line.split_once('=') {
        Some((lhs, _)) => {
            !lhs.trim().is_empty()
                && !lhs.contains(char::is_whitespace)
                && lhs
                    .trim()
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        None => false,
    }
}

fn split_cron_line(line: &str) -> Option<(String, String)> {
    if line.starts_with('@') {
        let mut it = line.splitn(2, char::is_whitespace);
        let schedule = it.next()?.to_string();
        let command = it.next()?.trim().to_string();
        if command.is_empty() {
            return None;
        }
        return Some((schedule, command));
    }

    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 6 {
        return None;
    }
    Some((parts[..5].join(" "), parts[5..].join(" ")))
}

fn first_token(command: &str) -> String {
    command
        .split_whitespace()
        .next()
        .and_then(|t| t.rsplit('/').next())
        .unwrap_or(command)
        .to_string()
}

fn collect_periodic_jobs(items: &mut Vec<StartupItem>) {
    let periodic_dirs = [
        "/etc/periodic/daily",
        "/etc/periodic/weekly",
        "/etc/periodic/monthly",
    ];

    for dir in &periodic_dirs {
        let path = std::path::Path::new(dir);
        if !path.exists() {
            continue;
        }

        let Ok(entries) = std::fs::read_dir(path) else {
            continue;
        };

        for entry in entries.filter_map(|e| e.ok()) {
            let filename = entry.file_name();
            let filename = filename.to_string_lossy();
            let frequency = path
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or_default();

            let mut item = StartupItem::new(
                format!("com.apple.periodic.{}.{}", frequency, filename),
                ItemType::CronJob,
            );
            item.path = Some(entry.path());
            item.program = Some(entry.path().to_string_lossy().into_owned());
            item.description = Some(format!("Periodic ({}) script", frequency));
            item.status = ItemStatus::Enabled;
            item.is_apple = true;
            item.running = RunningState::Unknown;
            items.push(item);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_standard_five_field_jobs() {
        let items = parse_crontab("0 3 * * * /usr/local/bin/backup.sh --full\n");
        assert_eq!(items.len(), 1);
        assert_eq!(
            items[0].program.as_deref(),
            Some("/usr/local/bin/backup.sh --full")
        );
        assert_eq!(items[0].run_at_load, Some(false));
    }

    #[test]
    fn parses_reboot_shortcut() {
        let items = parse_crontab("@reboot /Users/me/startup.sh\n");
        assert_eq!(items.len(), 1, "@reboot jobs must not be dropped");
        assert_eq!(items[0].run_at_load, Some(true));
        assert_eq!(items[0].program.as_deref(), Some("/Users/me/startup.sh"));
    }

    #[test]
    fn ignores_comments_blank_lines_and_env() {
        let items = parse_crontab("# comment\n\nPATH=/usr/bin:/bin\nMAILTO=\"me@x\"\n");
        assert!(items.is_empty());
    }

    #[test]
    fn job_ids_are_contiguous_and_ignore_comments() {
        let items = parse_crontab("# c\n0 1 * * * a\n# another\n0 2 * * * b\n");
        assert_eq!(items[0].label, "com.user.cron.0");
        assert_eq!(items[1].label, "com.user.cron.1");
    }

    #[test]
    fn names_use_the_binary_basename() {
        let items = parse_crontab("@daily /opt/homebrew/bin/cleanup -v\n");
        assert_eq!(items[0].name, "cron: cleanup");
    }
}
