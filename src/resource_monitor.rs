use std::thread;
use std::time::Duration;
use sysinfo::{System, Users, Pid};
use log::{warn,info};

use doh::{
    Config, 
    ResourceMonitorConfig, 
    read_config, 
    format_bytes,
    notify_msg,
};

pub async fn start_resource_monitor(config_path: &str, exclude_pid: Pid) {
    let config: Config = read_config(config_path);
    let res_config: ResourceMonitorConfig = config.resource_monitor;
    let users = Users::new_with_refreshed_list();
    
    tokio::spawn(async move {
        let mut sys = System::new_all();
        loop {
            sys.refresh_all();

            let mut msg_content = String::new();
            let mut bool = false;
            // Print CPU information
            info!("CPU Information:");
            for (pid, process) in sys.processes() {
                if let Some(process) = sys.process(process.pid()) {
                    let mut exclude_pids = vec![exclude_pid];
                    if let Some(exclude_process) = sys.process(exclude_pid) {
                        if let Some(tasks) = exclude_process.tasks() {
                            for task_pid in tasks {
                                exclude_pids.push(*task_pid);
                            }
                        }
                    }
                    if exclude_pids.contains(pid) && res_config.exclude_self_process {
                        continue;
                    }
                    let read_bytes = process.disk_usage().total_read_bytes;
                    let write_bytes = process.disk_usage().total_written_bytes;
                    let iops = read_bytes + write_bytes; // Simplified IOPS calculation
                    let bool1 = process.cpu_usage() >= res_config.cpu_threshold || process.memory() >= res_config.memory_threshold || process.virtual_memory() >= res_config.virtual_memory_threshold;
                    let bool2 =  iops > res_config.iops_threshold;
                    if bool1 || bool2 {  
                        let process_cmd: Vec<String> = process.cmd().iter().map(|s| s.to_string_lossy().into_owned()).collect();
                        if bool1 {
                            warn!("User: {:?} Pid {:?} {:?} CPU usage: {:?}% RAM usage: {:?} Virtual Memory: {:?}", 
                                users.get_user_by_id(process.user_id().unwrap()).unwrap().name(), 
                                process.pid(), process_cmd.join(" "), process.cpu_usage(), 
                                format_bytes(process.memory()), 
                                format_bytes(process.virtual_memory()));
                            msg_content.push_str(&format!("User: {:?} Pid {:?} {:?} CPU usage: {:?}% RAM usage: {:?} Virtual Memory: {:?}\n",
                                users.get_user_by_id(process.user_id().unwrap()).unwrap().name(), 
                                process.pid(), process_cmd.join(" "), process.cpu_usage(), 
                                format_bytes(process.memory()), 
                                format_bytes(process.virtual_memory())));
                            if let Some(tasks) = process.tasks() {
                                // println!("Number of subprocesses: {}", tasks.len());
                                let mut i = 0;
                                for task_pid in tasks {
                                    if let Some(task) = sys.process(*task_pid)  {
                                        let cmd: Vec<String> = task.cmd().iter().map(|s| s.to_string_lossy().into_owned()).collect();
                                        if i == tasks.len() - 1 {
                                            warn!("└── [{:?}] {:?}", task.pid().as_u32(), cmd.join(" "));
                                            msg_content.push_str(&format!("└── [{:?}] {:?}\n", task.pid().as_u32(), cmd.join(" ")));
                                        } else {
                                            warn!("├── [{:?}] {:?}", task.pid().as_u32(), cmd.join(" "));
                                            msg_content.push_str(&format!("├── [{:?}] {:?}\n", task.pid().as_u32(), cmd.join(" ")));
                                        }
                                        i += 1;
                                    }
                                    
                                }
                            }
                        }
                        if bool2 {
                            warn!(
                                "Warning: User: {:?} Pid {} (command: {:?}) has high IOPS: {} bytes, read: {} bytes, write: {} bytes",
                                users.get_user_by_id(process.user_id().unwrap()).unwrap().name(),
                                pid,
                                process_cmd.join(" "),
                                format_bytes(iops),
                                format_bytes(read_bytes),
                                format_bytes(write_bytes)
                            );
                            msg_content.push_str(&format!("Warning: User: {:?} Pid {} (command: {:?}) has high IOPS: {} bytes, read: {} bytes, write: {} bytes\n",
                                users.get_user_by_id(process.user_id().unwrap()).unwrap().name(),
                                pid,
                                process_cmd.join(" "),
                                format_bytes(iops),
                                format_bytes(read_bytes),
                                format_bytes(write_bytes)
                            ));
                        }

                        bool = true;
                        // // Print RAM information
                        // info!("Sytem Information:");
                        // info!("NB CPUs: {}", sys.cpus().len());
                        // let mut total_cpu_usage = 0.0;
                        // for cpu in sys.cpus() {
                        //     total_cpu_usage += cpu.cpu_usage();
                        // }
                        // info!("CPU usage: {}% ", total_cpu_usage);
                        // info!("Total memory: {}", format_bytes(sys.total_memory()));
                        // info!("Used memory: {}", format_bytes(sys.used_memory()));
                        // info!("Free memory: {}", format_bytes(sys.free_memory()));
                        // if sys.total_memory()-sys.used_memory()-sys.free_memory() > 0 {
                        //     info!("buff/cache: {}", format_bytes(sys.total_memory()-sys.used_memory()-sys.free_memory()));
                        // }
                        // info!("Total swap: {}", format_bytes(sys.total_swap()));
                        // info!("Used swap: {}", format_bytes(sys.used_swap()));
                        // info!("Free swap: {}", format_bytes(sys.free_swap()));

                        // msg_content.push_str(&format!("NB CPUs: {}\n", sys.cpus().len()));
                        // msg_content.push_str(&format!("CPU usage: {}%\n", total_cpu_usage));
                        // msg_content.push_str(&format!("Total memory: {}\n", format_bytes(sys.total_memory())));
                        // msg_content.push_str(&format!("Used memory: {}\n", format_bytes(sys.used_memory())));
                        // msg_content.push_str(&format!("Free memory: {}\n", format_bytes(sys.free_memory())));
                        // if sys.total_memory()-sys.used_memory()-sys.free_memory() > 0 {
                        //     msg_content.push_str(&format!("buff/cache: {}\n", format_bytes(sys.total_memory()-sys.used_memory()-sys.free_memory())));
                        // }
                        // msg_content.push_str(&format!("Total swap: {}\n", format_bytes(sys.total_swap())));
                        // msg_content.push_str(&format!("Used swap: {}\n", format_bytes(sys.used_swap())));
                        // msg_content.push_str(&format!("Free swap: {}\n", format_bytes(sys.free_swap())));

                        // let _ = notify_msg(&config.notice_config, &res_config.receiver, &msg_content).await;

                        // thread::sleep(Duration::from_secs(res_config.check_interval));
                    }
                }
            }

            if bool {
                // Print RAM information
                info!("Sytem Information:");
                info!("NB CPUs: {}", sys.cpus().len());
                let mut total_cpu_usage = 0.0;
                for cpu in sys.cpus() {
                    total_cpu_usage += cpu.cpu_usage();
                }
                info!("CPU usage: {}% ", total_cpu_usage);
                info!("Total memory: {}", format_bytes(sys.total_memory()));
                info!("Used memory: {}", format_bytes(sys.used_memory()));
                info!("Free memory: {}", format_bytes(sys.free_memory()));
                if sys.total_memory()-sys.used_memory()-sys.free_memory() > 0 {
                    info!("buff/cache: {}", format_bytes(sys.total_memory()-sys.used_memory()-sys.free_memory()));
                }
                info!("Total swap: {}", format_bytes(sys.total_swap()));
                info!("Used swap: {}", format_bytes(sys.used_swap()));
                info!("Free swap: {}", format_bytes(sys.free_swap()));

                msg_content.push_str(&format!("NB CPUs: {}\n", sys.cpus().len()));
                msg_content.push_str(&format!("CPU usage: {}%\n", total_cpu_usage));
                msg_content.push_str(&format!("Total memory: {}\n", format_bytes(sys.total_memory())));
                msg_content.push_str(&format!("Used memory: {}\n", format_bytes(sys.used_memory())));
                msg_content.push_str(&format!("Free memory: {}\n", format_bytes(sys.free_memory())));
                if sys.total_memory()-sys.used_memory()-sys.free_memory() > 0 {
                    msg_content.push_str(&format!("buff/cache: {}\n", format_bytes(sys.total_memory()-sys.used_memory()-sys.free_memory())));
                }
                msg_content.push_str(&format!("Total swap: {}\n", format_bytes(sys.total_swap())));
                msg_content.push_str(&format!("Used swap: {}\n", format_bytes(sys.used_swap())));
                msg_content.push_str(&format!("Free swap: {}\n", format_bytes(sys.free_swap())));

                let _ = notify_msg(&config.notice_config, &res_config.receiver, &msg_content).await;
            }

            thread::sleep(Duration::from_secs(res_config.check_interval));

            
        }
    });
}
