// use serde::Deserialize;
use std::fs;
use std::thread;
use std::time::{Duration, SystemTime};
use regex;
use sysinfo::{System, Disks, Networks, Users};
use std::collections::HashMap;
use procfs::process::{FDTarget, Stat};
use log::{info, warn};

use doh::{
    Config, 
    read_config, 
    format_bytes, 
    is_address_in_list, 
    get_dir_size,
    notify_msg
};

#[tokio::main]
async fn main() {
    env_logger::init();

    let config: Config = read_config("config.json");
    
    // Moved these assignments inside the loop where they're used
    let users = Users::new_with_refreshed_list();
    
    tokio::spawn(async move {
        let mut sys = System::new_all();
        loop {
            sys.refresh_all();

            if let Some(node_config) = &config.node_monitor {
                info!("Monitoring Node: {}", node_config.node_id);

                let mut msg_content = String::new();
                
                for (pid, process) in sys.processes() {
                    let user_name = users.get_user_by_id(process.user_id().unwrap()).unwrap().name();
                    if node_config.include_users.contains(&user_name.to_string()) && !node_config.exclude_users.contains(&user_name.to_string()) {
                        let start_time = process.start_time();
                        let process_cmd: Vec<String> = process.cmd().iter().map(|s| s.to_string_lossy().into_owned()).collect();
                        let process_run_time = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH + Duration::from_secs(start_time)).unwrap().as_secs();
                        // Check run time
                        
                        if process_run_time > node_config.run_time {
                            warn!("Warning: User: {:?} Process {} ({}) has been running for more than {} seconds, already elpased: {} seconds",
                                user_name, pid, process_cmd.join(" "), node_config.run_time, process_run_time);
                            msg_content.push_str(&format!("Warning: User: {:?} Process {} ({}) has been running for more than {} seconds, already elpased: {} seconds\n", 
                                user_name, pid, process_cmd.join(" "), node_config.run_time, process_run_time));
                        }

                        // Check resource usage
                        if let Some(res_config) = &config.resource_monitor {
                            if process.cpu_usage() >= res_config.cpu_threshold || 
                               process.memory() >= res_config.memory_threshold || 
                               process.virtual_memory() >= res_config.virtual_memory_threshold {
                                
                                warn!("Warning: User: {:?} Process {} ({}): CPU usage: {}%, Memory usage: {}, Virtual Memory: {}",
                                    user_name, pid, process_cmd.join(" "), process.cpu_usage(),
                                    format_bytes(process.memory()), format_bytes(process.virtual_memory()));
                                
                                msg_content.push_str(&format!("Warning: User: {:?} Process {} ({}): CPU usage: {}%, Memory usage: {}, Virtual Memory: {}\n", 
                                    user_name, pid, process_cmd.join(" "), process.cpu_usage(),
                                    format_bytes(process.memory()), format_bytes(process.virtual_memory())));
                            }
                        
                            let read_bytes = process.disk_usage().total_read_bytes;
                            let write_bytes = process.disk_usage().total_written_bytes;
                            let iops = read_bytes + write_bytes; // Simplified IOPS calculation
                            
                            if iops > res_config.iops_threshold {
                                warn!("Warning: User: {:?} Process {} ({}) has high IOPS: {} bytes, read: {} bytes, write: {} bytes",
                                    user_name, pid, process_cmd.join(" "),
                                    format_bytes(iops), format_bytes(read_bytes), format_bytes(write_bytes));
                                
                                msg_content.push_str(&format!("Warning: User: {:?} Process {} ({}) has high IOPS: {} bytes, read: {} bytes, write: {} bytes\n", 
                                    user_name, pid, process_cmd.join(" "),
                                    format_bytes(iops), format_bytes(read_bytes), format_bytes(write_bytes)));
                            }
                        }
                    }
                }

                // Check disk space
                if let Some(disk_config) = &config.disk_monitor {
                    let disks = Disks::new_with_refreshed_list();
                    for disk in disks.list() {
                        let mount_point = disk.mount_point().to_str().unwrap_or("Unknown").to_string();
                        let available_space = disk.available_space();
                        
                        if (disk_config.mount_points.is_empty() || 
                            disk_config.mount_points.contains(&mount_point)) && 
                           available_space < disk_config.disk_space_threshold {
                            
                            warn!("Warning: Disk space is below threshold on disk Filesystem {:?} Mounted on {:?}: {}  available",
                                disk.name().to_str().unwrap_or("Unknown"),
                                mount_point, format_bytes(available_space));
                            
                            msg_content.push_str(&format!("Warning: Disk space is below threshold on disk Filesystem {:?} Mounted on {:?}: {} available\n", 
                                disk.name().to_str().unwrap_or("Unknown"),
                                mount_point, format_bytes(available_space)));
                        }
                    }
                }

                let networks = Networks::new_with_refreshed_list();
                for (interface_name, network) in &networks {
                    if let Some(net_config) = &config.network_monitor {
                        if network.received() > net_config.data_threshold || 
                           network.transmitted() > net_config.data_threshold {
                            
                            warn!("Warning: {} received {}, transmitted {}",
                                interface_name, format_bytes(network.received()),
                                format_bytes(network.transmitted()));
                            
                            msg_content.push_str(&format!("Warning: {} received {}, transmitted {}\n", 
                                interface_name, format_bytes(network.received()),
                                format_bytes(network.transmitted())));
                            
                            info!("Ip Networks: {:?}", network.ip_networks());
                            msg_content.push_str(&format!("Ip Networks: {:?}\n", network.ip_networks()));
                        }
                    }
                }

                if msg_content.len() > 0 {
                    let _ = notify_msg(&config.notice_config, &node_config.receiver, &msg_content).await;
                    msg_content = String::new();
                }

                // TCP and UDP monitoring
                let all_procs = procfs::process::all_processes().unwrap();

                // build up a map between socket inodes and process stat info:
                let mut map: HashMap<u64, Stat> = HashMap::new();
                for p in all_procs {
                    let Ok(process) = p else {
                        // process vanished
                        continue;
                    };
                    if let (Ok(stat), Ok(fds)) = (process.stat(), process.fd()) {
                        for fd in fds {
                            if let FDTarget::Socket(inode) = fd.unwrap().target {
                                map.insert(inode, stat.clone());
                            }
                        }
                    }
                }

                warn!("--------------------------------TCP--------------------------------");
                let mut msg_content_title = format!("--------------------------------TCP--------------------------------\n");
                
                let tcp = procfs::net::tcp().unwrap();
                let tcp6 = procfs::net::tcp6().unwrap();
                warn!("{:<26} {:<26} {:<15} {:<8} {}", "Local address", "Remote address", "State", "Inode", "PID/Program name");
                msg_content_title.push_str(&format!("{:<26} {:<26} {:<15} {:<8} {}\n", 
                    "Local address", "Remote address", "State", "Inode", "PID/Program name"));
                
                for entry in tcp.into_iter().chain(tcp6) {
                    let local_address = format!("{}", entry.local_address);
                    let remote_addr = format!("{}", entry.remote_address);
                    let state: String = format!("{:?}", entry.state);
                    
                    if let Some(net_config) = &config.network_monitor {
                        if regex::Regex::new(r"^\d+\.\d+\.\d+\.\d+:\d+$").unwrap().is_match(&remote_addr) && 
                           !is_address_in_list(&remote_addr, &net_config.exclude_ipv4_address) {
                            
                            if let Some(stat) = map.get(&entry.inode) {
                                warn!("{:<26} {:<26} {:<15} {:<12} {}/{}", 
                                    local_address, remote_addr, state, entry.inode, stat.pid, stat.comm);
                                msg_content.push_str(&format!("{:<26} {:<26} {:<15} {:<12} {}/{}\n", 
                                    local_address, remote_addr, state, entry.inode, stat.pid, stat.comm));
                            } else {
                                warn!("{:<26} {:<26} {:<15} {:<12} -", 
                                    local_address, remote_addr, state, entry.inode);
                                msg_content.push_str(&format!("{:<26} {:<26} {:<15} {:<12} -\n", 
                                    local_address, remote_addr, state, entry.inode));
                            }
                        }
                    }
                }
                
                if msg_content.len() > 0 {
                    msg_content_title.push_str(&msg_content);
                    msg_content = msg_content_title;
                    let _ = notify_msg(&config.notice_config, &node_config.receiver, &msg_content).await;
                    msg_content = String::new();
                }
                
                info!("--------------------------------UDP--------------------------------");
                msg_content_title = format!("--------------------------------UDP--------------------------------\n");
                
                let udp = procfs::net::udp().unwrap();
                let udp6 = procfs::net::udp6().unwrap();
                info!("{:<26} {:<26} {:<15} {:<8} {}", "Local address", "Remote address", "State", "Inode", "PID/Program name");
                msg_content_title.push_str(&format!("{:<26} {:<26} {:<15} {:<8} {}\n", 
                    "Local address", "Remote address", "State", "Inode", "PID/Program name"));
                
                for entry in udp.into_iter().chain(udp6) {
                    let local_address = format!("{}", entry.local_address);
                    let remote_addr = format!("{}", entry.remote_address);
                    let state = format!("{:?}", entry.state);

                    if let Some(net_config) = &config.network_monitor {
                        if regex::Regex::new(r"^\d+\.\d+\.\d+\.\d+:\d+$").unwrap().is_match(&remote_addr) && 
                           !is_address_in_list(&remote_addr, &net_config.exclude_ipv4_address) {
                            
                            if let Some(stat) = map.get(&entry.inode) {
                                warn!("{:<26} {:<26} {:<15} {:<12} {}/{}", 
                                    local_address, remote_addr, state, entry.inode, stat.pid, stat.comm);
                                msg_content.push_str(&format!("{:<26} {:<26} {:<15} {:<12} {}/{}\n", 
                                    local_address, remote_addr, state, entry.inode, stat.pid, stat.comm));
                            } else {
                                warn!("{:<26} {:<26} {:<15} {:<12} -", 
                                    local_address, remote_addr, state, entry.inode);
                                msg_content.push_str(&format!("{:<26} {:<26} {:<15} {:<12} -\n", 
                                    local_address, remote_addr, state, entry.inode));
                            }
                        }
                    }
                }
                
                if msg_content.len() > 0 {
                    msg_content_title.push_str(&msg_content);
                    msg_content = msg_content_title;
                    let _ = notify_msg(&config.notice_config, &node_config.receiver, &msg_content).await;
                    msg_content = String::new();
                }

                // Check file increase/decrease data size
                if let Some(disk_config) = &config.disk_monitor {
                    for path_space in &disk_config.path_space {
                        let path = &path_space.path;
                        let space_threshold = path_space.space_threshold;
                        if fs::metadata(path).is_ok() {
                            let metadata = fs::metadata(path).unwrap();
                            if metadata.is_dir() {
                                let total_size = get_dir_size(path);
                                if total_size > space_threshold.1 || total_size < space_threshold.0 {
                                    warn!("Warning: Directory size exceeds threshold in path {:?}: {}",
                                        path, format_bytes(total_size));
                                    msg_content.push_str(&format!("Warning: Directory size exceeds threshold in path {:?}: {}\n", 
                                        path, format_bytes(total_size)));
                                }
                            } else {
                                if metadata.len() > space_threshold.1 || metadata.len() < space_threshold.0 {
                                    warn!("Warning: File size exceeds threshold in path {:?}: {}",
                                        path, format_bytes(metadata.len()));
                                    msg_content.push_str(&format!("Warning: File size exceeds threshold in path {:?}: {}\n", 
                                        path, format_bytes(metadata.len())));
                                }
                            }
                        }
                    }
                }
                
                if msg_content.len() > 0 {
                    let _ = notify_msg(&config.notice_config, &node_config.receiver, &msg_content).await;
                    msg_content.clear();
                }

                thread::sleep(Duration::from_secs(node_config.check_interval));
            }
        }
    }).await.unwrap(); // Await the spawned task to prevent premature exit

    // Keep the main thread alive
    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}