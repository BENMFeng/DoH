use std::fs;
use std::thread;
use std::time::Duration;
use std::process::Command;
use sysinfo::Disks;
use log::{warn, info, error};
use std::io::{Write, Read};
use std::fs::File;
use std::path::Path;
use std::time::Instant;
use rand::random;

use doh::{
    // Removed read_config from here as it's unused
    format_bytes, 
    get_dir_size,
    notify_msg
};

// Function to check SMART status of a disk
fn check_smart_status(device_path: &str) -> Result<String, String> {
    match Command::new("smartctl")
        .args(&["-a", device_path])
        .output() {
            Ok(output) => {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    
                    // Parse SMART output to extract relevant information
                    let mut smart_info = String::new();
                    
                    // Check overall SMART health
                    if stdout.contains("SMART overall-health self-assessment test result: PASSED") {
                        smart_info.push_str(&format!("SMART health status for {}: PASSED\n", device_path));
                    } else if stdout.contains("SMART overall-health self-assessment test result: FAILED") {
                        smart_info.push_str(&format!("⚠️ WARNING: SMART health status for {}: FAILED\n", device_path));
                    }
                    
                    // Extract important SMART attributes
                    let important_attrs = ["Reallocated_Sector_Ct", "Current_Pending_Sector", 
                                          "Offline_Uncorrectable", "UDMA_CRC_Error_Count",
                                          "Temperature", "Power_On_Hours"];
                    
                    for line in stdout.lines() {
                        for attr in &important_attrs {
                            if line.contains(attr) {
                                smart_info.push_str(&format!("{}\n", line.trim()));
                            }
                        }
                    }
                    
                    Ok(smart_info)
                } else {
                    Err(format!("Failed to get SMART info for {}: {}", 
                               device_path, 
                               String::from_utf8_lossy(&output.stderr)))
                }
            },
            Err(e) => Err(format!("Failed to execute smartctl: {}", e))
        }
}

// Function to check for bad sectors using badblocks
fn check_bad_sectors(device_path: &str) -> Result<String, String> {
    warn!("Checking for bad sectors on {}. This is a non-destructive read-only test.", device_path);
    
    match Command::new("badblocks")
        .args(&["-v", "-s", "-n", device_path])
        .output() {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                
                if stderr.contains("bad blocks found") || stdout.contains("bad blocks found") {
                    Ok(format!("⚠️ WARNING: Bad sectors found on {}\n{}\n{}", 
                              device_path, stdout, stderr))
                } else {
                    Ok(format!("No bad sectors found on {}", device_path))
                }
            },
            Err(e) => Err(format!("Failed to check bad sectors: {}", e))
        }
}

// Function to measure disk IO performance
fn measure_disk_performance(mount_point: &str) -> Result<String, String> {
    // Create a temporary file for testing
    let test_file_path = format!("{}/io_test_{}.tmp", mount_point, random::<u32>());
    let test_file_path = Path::new(&test_file_path);
    
    // Test parameters
    let block_size = 4096; // 4KB blocks
    let num_blocks = 1000; // Write 4MB in total
    let buffer = vec![0u8; block_size];
    
    // Measure sequential write performance
    let write_start = Instant::now();
    let mut total_bytes_written = 0;
    
    match File::create(test_file_path) {
        Ok(mut file) => {
            for _ in 0..num_blocks {
                match file.write_all(&buffer) {
                    Ok(_) => total_bytes_written += buffer.len(),
                    Err(e) => return Err(format!("Write error: {}", e)),
                }
            }
            
            let write_duration = write_start.elapsed();
            let write_throughput = (total_bytes_written as f64) / write_duration.as_secs_f64();
            let write_iops = (num_blocks as f64) / write_duration.as_secs_f64();
            
            // Measure sequential read performance
            let mut read_buffer = vec![0u8; block_size];
            let read_start = Instant::now();
            let mut total_bytes_read = 0;
            
            match File::open(test_file_path) {
                Ok(mut file) => {
                    for _ in 0..num_blocks {
                        match file.read_exact(&mut read_buffer) {
                            Ok(_) => total_bytes_read += read_buffer.len(),
                            Err(e) => {
                                let _ = std::fs::remove_file(test_file_path);
                                return Err(format!("Read error: {}", e));
                            }
                        }
                    }
                    
                    let read_duration = read_start.elapsed();
                    let read_throughput = (total_bytes_read as f64) / read_duration.as_secs_f64();
                    let read_iops = (num_blocks as f64) / read_duration.as_secs_f64();
                    
                    // Clean up test file
                    let _ = std::fs::remove_file(test_file_path);
                    
                    // Convert bytes/sec to MB/sec for easier reading
                    let write_throughput_mb = write_throughput / 1_000_000.0;
                    let read_throughput_mb = read_throughput / 1_000_000.0;
                    
                    Ok(format!(
                        "Disk performance for {}:\n\
                         - Write: {:.2} MB/s ({:.0} IOPS)\n\
                         - Read: {:.2} MB/s ({:.0} IOPS)",
                        mount_point,
                        write_throughput_mb,
                        write_iops,
                        read_throughput_mb,
                        read_iops
                    ))
                },
                Err(e) => {
                    let _ = std::fs::remove_file(test_file_path);
                    Err(format!("Failed to open file for reading: {}", e))
                }
            }
        },
        Err(e) => Err(format!("Failed to create test file: {}", e))
    }
}

pub async fn start_disk_monitor(config_path: &str) {
    let config = doh::read_config(config_path);
    
    if let Some(disk_config) = config.disk_monitor {
        tokio::spawn(async move {
            loop {
                let disks = Disks::new_with_refreshed_list();
                let mut msg_content = String::new();
                
                // Existing disk space monitoring
                for disk in disks.list() {
                    let mount_point = disk.mount_point().to_str().unwrap_or("Unknown").to_string();
                    let available_space = disk.available_space();
                    if (disk_config.mount_points.is_empty() || disk_config.mount_points.contains(&mount_point)) && available_space < disk_config.disk_space_threshold {
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
                    
                    // Add SMART information and disk health check
                    let device_name = disk.name().to_str().unwrap_or("Unknown");
                    if device_name.starts_with("/dev/") || device_name.starts_with("\\\\?\\") {
                        // Check SMART status
                        match check_smart_status(device_name) {
                            Ok(smart_info) => {
                                if smart_info.contains("WARNING") || smart_info.contains("FAILED") {
                                    warn!("{}", smart_info);
                                    msg_content.push_str(&format!("{}\n", smart_info));
                                } else {
                                    info!("{}", smart_info);
                                }
                            },
                            Err(e) => {
                                // SMART might not be available for all devices
                                info!("Could not check SMART status for {}: {}", device_name, e);
                            }
                        }
                        
                        // Only run bad sectors check if explicitly configured to do so
                        // as it can be time-consuming and load-intensive
                        if disk_config.check_bad_sectors.unwrap_or(false) {
                            match check_bad_sectors(device_name) {
                                Ok(result) => {
                                    if result.contains("WARNING") {
                                        warn!("{}", result);
                                        msg_content.push_str(&format!("{}\n", result));
                                    } else {
                                        info!("{}", result);
                                    }
                                },
                                Err(e) => {
                                    info!("Could not check for bad sectors on {}: {}", device_name, e);
                                }
                            }
                        }
                    }
                    
                    // Measure disk performance (IO/IOPS)
                    if disk_config.measure_performance.unwrap_or(false) {
                        match measure_disk_performance(&mount_point) {
                            Ok(perf_info) => {
                                info!("{}", perf_info);
                                
                                // Extract performance metrics
                                let write_throughput_mb = if let Some(write_mb) = perf_info.split("Write: ").nth(1)
                                    .and_then(|s| s.split(" MB/s").next())
                                    .and_then(|s| s.parse::<f64>().ok()) {
                                    write_mb
                                } else {
                                    0.0
                                };
                                
                                let write_iops = if let Some(write_iops_str) = perf_info.split("Write: ")
                                    .nth(1).and_then(|s| s.split("(").nth(1))
                                    .and_then(|s| s.split(" IOPS").next())
                                    .and_then(|s| s.parse::<f64>().ok()) {
                                    write_iops_str
                                } else {
                                    0.0
                                };
                                
                                let read_throughput_mb = if let Some(read_mb) = perf_info.split("Read: ").nth(1)
                                    .and_then(|s| s.split(" MB/s").next())
                                    .and_then(|s| s.parse::<f64>().ok()) {
                                    read_mb
                                } else {
                                    0.0
                                };
                                
                                let read_iops = if let Some(read_iops_str) = perf_info.split("Read: ")
                                    .nth(1).and_then(|s| s.split("(").nth(1))
                                    .and_then(|s| s.split(" IOPS").next())
                                    .and_then(|s| s.parse::<f64>().ok()) {
                                    read_iops_str
                                } else {
                                    0.0
                                };
                                
                                // Check against thresholds and add warnings if performance is poor
                                let mut perf_warnings = Vec::new();
                                
                                if let Some(min_write_throughput) = disk_config.min_write_throughput {
                                    if write_throughput_mb < min_write_throughput {
                                        perf_warnings.push(format!("Write throughput ({:.2} MB/s) below threshold ({:.2} MB/s)", 
                                                                  write_throughput_mb, min_write_throughput));
                                    }
                                }
                                
                                if let Some(min_read_throughput) = disk_config.min_read_throughput {
                                    if read_throughput_mb < min_read_throughput {
                                        perf_warnings.push(format!("Read throughput ({:.2} MB/s) below threshold ({:.2} MB/s)", 
                                                                  read_throughput_mb, min_read_throughput));
                                    }
                                }
                                
                                if let Some(min_write_iops) = disk_config.min_write_iops {
                                    if write_iops < min_write_iops {
                                        perf_warnings.push(format!("Write IOPS ({:.0}) below threshold ({:.0})", 
                                                                  write_iops, min_write_iops));
                                    }
                                }
                                
                                if let Some(min_read_iops) = disk_config.min_read_iops {
                                    if read_iops < min_read_iops {
                                        perf_warnings.push(format!("Read IOPS ({:.0}) below threshold ({:.0})", 
                                                                  read_iops, min_read_iops));
                                    }
                                }
                                
                                // Add warnings to message content if any thresholds were crossed
                                if !perf_warnings.is_empty() {
                                    msg_content.push_str(&format!("⚠️ Disk performance issues on {}:\n", mount_point));
                                    for warning in perf_warnings {
                                        msg_content.push_str(&format!("  - {}\n", warning));
                                    }
                                    msg_content.push_str(&format!("Full performance report:\n{}\n", perf_info));
                                }
                            },
                            Err(e) => {
                                error!("Failed to measure disk performance for {}: {}", mount_point, e);
                            }
                        }
                    }
                }
                
                if msg_content.len() > 0 {
                    if config.notice_config.is_some() {
                        let _ = notify_msg(&config.notice_config, &disk_config.receiver, &msg_content);
                    } else {
                        // Just log the message if notifications aren't configured
                        info!("Notification message (not sent - no notification config):\n{}", msg_content);
                    }
                    msg_content.clear();
                }

                // Existing path space checks
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
                    if config.notice_config.is_some() {
                        let _ = notify_msg(&config.notice_config, &disk_config.receiver, &msg_content);
                    } else {
                        // Just log the message if notifications aren't configured
                        info!("Notification message (not sent - no notification config):\n{}", msg_content);
                    }
                    msg_content.clear();
                }
                
                thread::sleep(Duration::from_secs(disk_config.check_interval));
            }
        });
    } else {
        warn!("Disk monitor configuration is missing or invalid");
    }
}
