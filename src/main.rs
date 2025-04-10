mod disk_monitor;
mod resource_monitor;
mod network_monitor;

use env_logger;
use log::{info, warn};

#[tokio::main]
async fn main() {
    env_logger::init();
    info!("Starting DoH: Distributed jObs Hypervisor");

    let config_path = "config.json";
    if !std::path::Path::new(config_path).exists() {
        panic!("Config file not found: {}", config_path);
    }
    
    let config: doh::Config = doh::read_config(config_path);
    
    // Start disk monitor if configured
    if let Some(_disk_config) = &config.disk_monitor {
        info!("Starting disk monitor");
        disk_monitor::start_disk_monitor(config_path).await;
    } else {
        info!("Disk monitor not configured - skipping");
    }

    // Start resource monitor if configured
    if let Some(_resource_config) = &config.resource_monitor {
        info!("Starting resource monitor");
        let current_process_pid = match sysinfo::get_current_pid() {
            Ok(pid) => pid,
            Err(e) => {
                warn!("Failed to get current PID, resource monitor may not exclude self process: {}", e);
                sysinfo::Pid::from(0)
            }
        };
        resource_monitor::start_resource_monitor(config_path, current_process_pid).await;
    } else {
        info!("Resource monitor not configured - skipping");
    }

    // Start network monitor if configured
    if let Some(_network_config) = &config.network_monitor {
        info!("Starting network monitor");
        network_monitor::start_network_monitor(config_path).await;
    } else {
        info!("Network monitor not configured - skipping");
    }

    // Start node monitor if configured (for node_monitor binary)
    if let Some(_node_config) = &config.node_monitor {
        info!("Node monitor configuration detected");
        // Node monitor is typically started from a separate binary
    }

    // Start job monitor if configured (for job_monitor binary)
    if let Some(_job_config) = &config.job_monitor {
        info!("Job monitor configuration detected");
        // Job monitor is typically started from a separate binary
    }

    info!("All monitors started. DoH is now running.");
    
    // Keep the main thread alive
    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}
