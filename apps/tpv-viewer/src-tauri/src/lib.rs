//! The TreePView viewer backend.
//!
//! The viewer is the opposite of the collector in posture: it never runs on the
//! machine under investigation, so it is free to be large and to depend on a
//! browser engine. The one discipline it keeps is that a case is evidence — it
//! is opened read-only at the SQLite level, and the only table the viewer may
//! ever write is the regenerable findings table.

pub mod commands;
pub mod error;
pub mod open;

use commands::CaseState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(CaseState::default())
        .invoke_handler(tauri::generate_handler![
            commands::open_case,
            commands::close_case,
            commands::overview,
            commands::process_tree,
            commands::query_events,
            commands::histogram,
            commands::inspect_event,
            commands::inspect_entity,
            commands::manifest,
            commands::findings,
            commands::export_events,
            commands::verify,
        ])
        .setup(|app| {
            // A case passed on the command line opens straight away, so the
            // viewer can be wired up as the file association for `.tpv`.
            // Skip flags (`--color`, `--no-default-features`) that cargo/tauri
            // inject in `tauri dev`.
            if let Some(path) = std::env::args()
                .skip(1)
                .find(|a| a != "--" && !a.starts_with('-'))
            {
                use tauri::Manager;
                let state = app.state::<CaseState>();
                if let Ok(reader) = open::open_any(std::path::Path::new(&path)) {
                    *state.0.lock().expect("case lock poisoned") = Some(reader);
                }
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running TreePView");
}
