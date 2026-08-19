// Release builds detach from the console: the viewer is a desktop application
// and a stray terminal window behind it is noise, not diagnostics.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    tpv_viewer_lib::run()
}
