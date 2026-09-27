// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Re-exec entry point for the root helper. Must be handled before anything
    // GUI-related: this process is running as uid 0 and must never create a
    // window, touch the user's defaults, or initialise Tauri.
    if args.len() > 2 && args[1] == "--privileged-helper" {
        launch_fleet_lib::run_privileged_helper(std::path::Path::new(&args[2]));
    }

    if args.len() > 1 && args[1] == "--probe" {
        // Test mode: print collector results to stdout, don't start GUI
        let items = launch_fleet_lib::probe();
        println!("Total items: {}", items.len());
        let mut by_type = std::collections::HashMap::new();
        for item in &items {
            *by_type.entry(format!("{:?}", item.item_type)).or_insert(0) += 1;
        }
        for (k, v) in by_type {
            println!("  {}: {}", k, v);
        }
        if let Some(first) = items.first() {
            println!("\nFirst item: {} ({})", first.name, first.label);
        }
        return;
    }

    launch_fleet_lib::run()
}
