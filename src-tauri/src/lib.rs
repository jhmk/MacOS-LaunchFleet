mod actions;
mod collectors;
pub mod models;
pub mod privileged;
mod quarantine;
mod sm_login;
mod sudo;

use models::StartupItem;
use quarantine::QuarantineEntry;
use serde::Serialize;
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;
use sudo::SudoSession;
use tauri::Manager;

pub struct AppState {
    pub sudo: SudoSession,
    pub items: Mutex<Vec<StartupItem>>,
}

impl AppState {
    /// Mutex poisoning should degrade, not kill the app.
    fn items(&self) -> std::sync::MutexGuard<'_, Vec<StartupItem>> {
        self.items
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn find(&self, id: &str) -> Option<StartupItem> {
        self.items().iter().find(|i| i.id == id).cloned()
    }
}

pub fn probe() -> Vec<StartupItem> {
    collectors::collect_all(None)
}

/// Entry point for the re-exec'd root helper (`--privileged-helper <dir>`).
pub fn run_privileged_helper(dir: &Path) -> ! {
    privileged::run_helper(dir)
}

#[derive(Serialize)]
pub struct StateInfo {
    pub system_mode: bool,
    pub item_count: usize,
    pub quarantined: usize,
}

/// Collecting touches `sfltool dumpbtm`, `launchctl list` and dozens of plists,
/// which takes seconds. These commands are `async` so Tauri runs them off the
/// main thread; as synchronous commands they blocked the UI for the whole scan.
#[tauri::command]
async fn list_items(state: tauri::State<'_, AppState>) -> Result<Vec<StartupItem>, String> {
    let items = collectors::collect_all(Some(&state.sudo));
    *state.items() = items.clone();
    Ok(items)
}

#[tauri::command]
async fn refresh_items(state: tauri::State<'_, AppState>) -> Result<Vec<StartupItem>, String> {
    let items = collectors::collect_all(Some(&state.sudo));
    *state.items() = items.clone();
    Ok(items)
}

#[tauri::command]
fn get_state_info(state: tauri::State<AppState>) -> StateInfo {
    StateInfo {
        system_mode: state.sudo.is_active(),
        item_count: state.items().len(),
        quarantined: quarantine::list().len(),
    }
}

#[tauri::command]
async fn enable_system_mode(state: tauri::State<'_, AppState>) -> Result<bool, String> {
    if state.sudo.is_active() {
        return Ok(true);
    }
    state.sudo.activate()?;
    Ok(true)
}

#[tauri::command]
async fn toggle_item(
    id: String,
    state: tauri::State<'_, AppState>,
) -> Result<actions::ActionResult, String> {
    let Some(item) = state.find(&id) else {
        return Ok(actions::ActionResult::fail(
            "This item no longer exists. Refresh and try again.",
        ));
    };

    Ok(match item.status {
        models::ItemStatus::Enabled => actions::disable_item(&item, &state.sudo),
        models::ItemStatus::Disabled => actions::enable_item(&item, &state.sudo),
        // Guessing "disable" on unknown state is not safe for a tool that can
        // switch off boot-critical daemons; make the caller decide.
        models::ItemStatus::Unknown => actions::ActionResult::fail(format!(
            "LaunchFleet can't determine whether \"{}\" is currently enabled, so it won't guess. \
             Use the explicit Enable/Disable buttons in the details panel.",
            item.name
        )),
    })
}

#[tauri::command]
async fn set_item_enabled(
    id: String,
    enabled: bool,
    state: tauri::State<'_, AppState>,
) -> Result<actions::ActionResult, String> {
    let Some(item) = state.find(&id) else {
        return Ok(actions::ActionResult::fail(
            "This item no longer exists. Refresh and try again.",
        ));
    };

    Ok(if enabled {
        actions::enable_item(&item, &state.sudo)
    } else {
        actions::disable_item(&item, &state.sudo)
    })
}

#[tauri::command]
async fn delete_item(
    id: String,
    state: tauri::State<'_, AppState>,
) -> Result<actions::ActionResult, String> {
    let Some(item) = state.find(&id) else {
        return Ok(actions::ActionResult::fail(
            "This item no longer exists. Refresh and try again.",
        ));
    };

    Ok(actions::delete_item(&item, &state.sudo))
}

#[tauri::command]
fn list_quarantined() -> Vec<QuarantineEntry> {
    quarantine::list()
}

#[tauri::command]
async fn restore_quarantined(
    id: String,
    state: tauri::State<'_, AppState>,
) -> Result<actions::ActionResult, String> {
    Ok(match quarantine::restore(&id, &state.sudo) {
        Ok(path) => actions::ActionResult::done(format!("Restored to {}", path.display())),
        Err(e) => actions::ActionResult::fail(e),
    })
}

#[tauri::command]
fn open_login_items_settings() -> Result<(), String> {
    Command::new("open")
        .arg("x-apple.systempreferences:com.apple.LoginItems-Settings.extension")
        .spawn()
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn reveal_in_finder(path: String) -> Result<(), String> {
    let p = std::path::Path::new(&path);
    if !p.exists() {
        return Err(format!("Path does not exist: {}", path));
    }
    Command::new("open")
        .arg("-R")
        .arg(&path)
        .spawn()
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app_state = AppState {
        sudo: SudoSession::new(),
        items: Mutex::new(Vec::new()),
    };

    tauri::Builder::default()
        .manage(app_state)
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            // Native window material so the app sits correctly under the
            // Liquid Glass design language rather than painting its own
            // opaque chrome. Non-fatal: a failure here just means a plain
            // background.
            if let Some(window) = app.get_webview_window("main") {
                let _ = window_vibrancy::apply_vibrancy(
                    &window,
                    window_vibrancy::NSVisualEffectMaterial::Sidebar,
                    Some(window_vibrancy::NSVisualEffectState::FollowsWindowActiveState),
                    None,
                );
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_items,
            refresh_items,
            get_state_info,
            enable_system_mode,
            toggle_item,
            set_item_enabled,
            delete_item,
            list_quarantined,
            restore_quarantined,
            open_login_items_settings,
            reveal_in_finder,
        ])
        .on_window_event(|window, event| {
            // Tear the root helper down with the app rather than leaving a
            // privileged process behind.
            if let tauri::WindowEvent::Destroyed = event {
                let state: tauri::State<AppState> = window.state();
                state.sudo.shutdown();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
