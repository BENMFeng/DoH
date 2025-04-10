use std::thread;
use std::time::Duration;
use regex;
use sysinfo::{System, Networks};
use std::collections::HashMap;
use procfs::process::{FDTarget, Stat};
use log::{warn,info};

use doh::{
    format_bytes, 
    is_address_in_list,
    notify_msg
};

pub async fn start_network_monitor(config_path: &str) {
    let config = doh::read_config(config_path);
    if let Some(net_config) = config.network_monitor {
        tokio::spawn(async move  {
            let mut sys = System::new_all();
            loop {
                sys.refresh_all();

                let mut msg_content = String::new();

                // Print Network information
                info!("Network Information:");
                let networks = Networks::new_with_refreshed_list();
                for (interface_name, data) in &networks {
                    if data.received() > net_config.data_threshold || data.transmitted() > net_config.data_threshold {
                        warn!(
                            "Warning: {} received {}, transmitted {}",
                            interface_name,
                            format_bytes(data.received()),
                            format_bytes(data.transmitted())
                        );
                        warn!("Ip Networks: {:?}", data.ip_networks());

                        msg_content.push_str(&format!("Warning: {} received {}, transmitted {}\n",
                            interface_name,
                            format_bytes(data.received()),
                            format_bytes(data.transmitted())
                        ));
                        msg_content.push_str(&format!("Ip Networks: {:?}\n", data.ip_networks()));
                    }
                }

                if msg_content.len() > 0 {
                    if config.notice_config.is_some() {
                        let _ = notify_msg(&config.notice_config, &net_config.receiver, &msg_content).await;
                    } else {
                        info!("Notification message (not sent - no notification config):\n{}", msg_content);
                    }
                    msg_content.clear();
                }

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

                //TODO: write a function to get the socket info
                info!("--------------------------------TCP--------------------------------");
                let mut msg_content_title = format!("--------------------------------TCP--------------------------------\n");
                // get the tcp table
                let tcp = procfs::net::tcp().unwrap();
                let tcp6 = procfs::net::tcp6().unwrap();
                info!("{:<26} {:<26} {:<15} {:<8} {}", "Local address", "Remote address", "State", "Inode", "PID/Program name");
                msg_content_title.push_str(&format!("{:<26} {:<26} {:<15} {:<8} {}\n", "Local address", "Remote address", "State", "Inode", "PID/Program name"));
                for entry in tcp.into_iter().chain(tcp6) {
                    // find the process (if any) that has an open FD to this entry's inode
                    let local_address = format!("{}", entry.local_address);
                    let remote_addr = format!("{}", entry.remote_address);
                    let state: String = format!("{:?}", entry.state);
                    if regex::Regex::new(r"^\d+\.\d+\.\d+\.\d+:\d+$").unwrap().is_match(&remote_addr) && !is_address_in_list(&remote_addr, &net_config.exclude_ipv4_address) {
                        if let Some(stat) = map.get(&entry.inode) {
                            info!("{:<26} {:<26} {:<15} {:<12} {}/{}", local_address, remote_addr, state, entry.inode, stat.pid, stat.comm);
                            msg_content.push_str(&format!("{:<26} {:<26} {:<15} {:<12} {}/{}\n", local_address, remote_addr, state, entry.inode, stat.pid, stat.comm));
                        } else {
                            // We might not always be able to find the process assocated with this socket
                            info!("{:<26} {:<26} {:<15} {:<12} -", local_address, remote_addr, state, entry.inode);
                            msg_content.push_str(&format!("{:<26} {:<26} {:<15} {:<12} -\n", local_address, remote_addr, state, entry.inode));
                        }
                    }
                }
                if msg_content.len() > 0 {
                    if config.notice_config.is_some() {
                        msg_content_title.push_str(&msg_content);
                        msg_content = msg_content_title;
                        let _ = notify_msg(&config.notice_config, &net_config.receiver, &msg_content).await;
                    } else {
                        info!("Notification message (not sent - no notification config):\n{}", msg_content);
                    }
                    msg_content.clear();
                }
                info!("--------------------------------UDP--------------------------------");
                msg_content_title = format!("--------------------------------UDP--------------------------------\n");
                // get the tcp table
                let udp = procfs::net::udp().unwrap();
                let udp6 = procfs::net::udp6().unwrap();
                info!("{:<26} {:<26} {:<15} {:<8} {}", "Local address", "Remote address", "State", "Inode", "PID/Program name");
                msg_content_title.push_str(&format!("{:<26} {:<26} {:<15} {:<8} {}\n", "Local address", "Remote address", "State", "Inode", "PID/Program name"));
                for entry in udp.into_iter().chain(udp6) {
                    // find the process (if any) that has an open FD to this entry's inode
                    let local_address = format!("{}", entry.local_address);
                    let remote_addr = format!("{}", entry.remote_address);
                    let state = format!("{:?}", entry.state);

                    if regex::Regex::new(r"^\d+\.\d+\.\d+\.\d+:\d+$").unwrap().is_match(&remote_addr) && !is_address_in_list(&remote_addr, &net_config.exclude_ipv4_address) {
                        if let Some(stat) = map.get(&entry.inode) {
                            info!("{:<26} {:<26} {:<15} {:<12} {}/{}", local_address, remote_addr, state, entry.inode, stat.pid, stat.comm);
                            msg_content.push_str(&format!("{:<26} {:<26} {:<15} {:<12} {}/{}\n", local_address, remote_addr, state, entry.inode, stat.pid, stat.comm));
                        } else {
                            // We might not always be able to find the process assocated with this socket
                            info!("{:<26} {:<26} {:<15} {:<12} -", local_address, remote_addr, state, entry.inode);
                            msg_content.push_str(&format!("{:<26} {:<26} {:<15} {:<12} -\n", local_address, remote_addr, state, entry.inode));
                        }
                    }
                }
                if msg_content.len() > 0 {
                    if config.notice_config.is_some() {
                        msg_content_title.push_str(&msg_content);
                        msg_content = msg_content_title;
                        let _ = notify_msg(&config.notice_config, &net_config.receiver, &msg_content).await;
                    }
                    else {
                        info!("Notification message (not sent - no notification config):\n{}", msg_content);
                    }
                    msg_content.clear();
                }

                thread::sleep(Duration::from_secs(net_config.check_interval));
            }
        });
    } else {
        warn!("Network monitor configuration is missing or invalid");
    }
}