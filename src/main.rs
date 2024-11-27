// use sysinfo::{NetworkExt, ProcessorExt, System, SystemExt, DiskExt};
mod disk_monitor;
mod resource_monitor;
mod network_monitor;

use env_logger;


#[tokio::main]
async fn main() {
    env_logger::init();

    let config_path = "config.json";
    if !std::path::Path::new(config_path).exists() {
        panic!("Config file not found");
    }
    let config: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(config_path).expect("Failed to read config file"))
        .expect("Failed to parse config file");

    if config.get("disk_monitor").is_some() {
        disk_monitor::start_disk_monitor(config_path).await;
    }
    if config.get("resource_monitor").is_some() {
        let current_process_pid = sysinfo::get_current_pid().expect("Failed to get current PID");
        resource_monitor::start_resource_monitor(config_path, current_process_pid).await;
    }
    if config.get("network_monitor").is_some()  {
        network_monitor::start_network_monitor(config_path).await;
    }
    // Keep the main thread alive
    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}
