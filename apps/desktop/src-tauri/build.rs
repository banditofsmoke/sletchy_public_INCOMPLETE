fn main() {
    // Declaring the app's commands in a manifest makes each one deny-by-default:
    // a window may call a command only if its capability file grants it (LAW 2, LAW 3).
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&["bridge_call", "bridge_info"]),
    ))
    .expect("tauri-build failed");
}
