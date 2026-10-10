// Release builds must not spawn a console window on Windows. Harmless on macOS,
// and cheaper to keep than to remember when Windows support lands.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    truepass_app_lib::run()
}
