// No console window in a release build.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    sletchy_desktop_lib::run();
}
