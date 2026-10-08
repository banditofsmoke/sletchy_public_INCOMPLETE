//! The Sletchy desktop shell (ADR-0008).
//!
//! Two commands, and the window may call only those two, because
//! `capabilities/main.json` grants nothing else and `build.rs` makes every command
//! deny-by-default:
//!
//! - `bridge_call(method, params)` - one allowlisted request to the Kernel
//! - `bridge_info()` - the connection's own state, for the Raw view
//!
//! No Tauri plugins are loaded: no shell, no filesystem, no HTTP.

mod bridge;
#[cfg(windows)]
mod job;
mod methods;
mod procs;

use std::sync::{Arc, Mutex};

use serde_json::Value;

struct Shell {
    bridge: Arc<Mutex<bridge::Bridge>>,
}

#[tauri::command]
async fn bridge_call(
    shell: tauri::State<'_, Shell>,
    method: String,
    params: Value,
) -> Result<Value, String> {
    let bridge = Arc::clone(&shell.bridge);
    // The Kernel may take a while (Stop everything); never block the window's thread on it.
    tauri::async_runtime::spawn_blocking(move || {
        let mut bridge = bridge.lock().map_err(|_| "the bridge lock was poisoned".to_string())?;
        Ok(bridge.call(&method, params))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn bridge_info(shell: tauri::State<'_, Shell>) -> Result<Value, String> {
    let bridge = Arc::clone(&shell.bridge);
    tauri::async_runtime::spawn_blocking(move || {
        bridge
            .lock()
            .map(|bridge| bridge.info())
            .map_err(|_| "the bridge lock was poisoned".to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

pub fn run() {
    let launch = bridge::Launch::from_repo();
    // LAW 0 section 2: all of Sletchy's state lives under `var/`. Left to itself,
    // WebView2 keeps its profile in %LOCALAPPDATA%\<identifier>, outside it - measured
    // on 2026-10-02, 232 files and 11 MB from one launch. So the window is built here,
    // not in tauri.conf.json, with its data directory pointed inside `var/`.
    let webview_data = launch.cwd.join("var").join("webview");

    tauri::Builder::default()
        .manage(Shell {
            bridge: Arc::new(Mutex::new(bridge::Bridge::new(launch))),
        })
        .invoke_handler(tauri::generate_handler![bridge_call, bridge_info])
        .setup(move |app| {
            tauri::WebviewWindowBuilder::new(app, "main", tauri::WebviewUrl::App("index.html".into()))
                .title("Sletchy")
                .inner_size(1180.0, 820.0)
                .min_inner_size(380.0, 560.0)
                .center()
                .data_directory(webview_data.clone())
                .build()?;
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("the Sletchy shell failed to start");
}
