use std::fs;
use std::thread;
use std::time::Duration;
use sysinfo::Disks;
use log::warn;

use doh::{
    Config, 
    read_config, 
    format_bytes, 
    get_dir_size,
    notify_msg
};

pub async fn start_disk_monitor(config_path: &str) {
    let config: Config = read_config(config_path);
    let disk_config = config.disk_monitor;
    
    tokio::spawn(async move {
        // let mut sys = System::new_all();
        loop {
            let disks = Disks::new_with_refreshed_list();
            let mut msg_content = String::new();
            for disk in disks.list() {
                let mount_point = disk.mount_point().to_str().unwrap_or("Unknown").to_string();
                let available_space = disk.available_space();
                if (disk_config.mount_points.is_empty() || disk_config.mount_points.contains(&mount_point)) && available_space < disk_config.disk_space_threshold {
                    // println!("Warning: Disk space is below threshold: {} B available", available_space);
                    warn!(
                        "Warning: Disk space is below threshold on disk Filesystem {:?} Mounted on {:?}: {} available",
                        disk.name().to_str().unwrap_or("Unknown"),
                        mount_point,
                        format_bytes(available_space)
                    );
                    msg_content.push_str(&format!("Warning: Disk space is below threshold on disk Filesystem {:?} Mounted on {:?}: {} available\n",
                        disk.name().to_str().unwrap_or("Unknown"),
                        mount_point,
                        format_bytes(available_space)
                    ));
                }
                // Add SMART information and disk damage alarm here
            }
            if msg_content.len() > 0 {
                let _ = notify_msg(&config.notice_config, &disk_config.receiver, &msg_content);
                msg_content.clear();
            }

            // Check file increase/decrease data size
            for path_space in &disk_config.path_space {
                let path = &path_space.path;
                let space_threshold = path_space.space_threshold;
                if fs::metadata(path).is_ok() {
                    let metadata = fs::metadata(path).unwrap();
                    if metadata.is_dir() {
                        let total_size = get_dir_size(path);
                        if total_size > space_threshold.1 || total_size < space_threshold.0 {
                            warn!(
                                "Warning: Directory size exceeds threshold in path {:?}: {}",
                                path,
                                format_bytes(total_size)
                            );
                            msg_content.push_str(&format!("Warning: Directory size exceeds threshold in path {:?}: {}\n",
                                path,
                                format_bytes(total_size)
                            ));
                        }
                    } else {
                        if metadata.len() > space_threshold.1 || metadata.len() < space_threshold.0 {
                            warn!(
                                "Warning: File size exceeds threshold in path {:?}: {}",
                                path,
                                format_bytes(metadata.len())
                            );
                            msg_content.push_str(&format!("Warning: File size exceeds threshold in path {:?}: {}\n",
                                path,
                                format_bytes(metadata.len())
                            ));
                        }
                    }
                }
            }
            if msg_content.len() > 0 {
                let _ = notify_msg(&config.notice_config, &disk_config.receiver, &msg_content).await;
                msg_content.clear();
            }
            thread::sleep(Duration::from_secs(disk_config.check_interval));
        }
    });
}
