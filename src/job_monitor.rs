use std::fs;
use std::process::Command;
use std::thread;
use std::time::{Duration,SystemTime};
use sysinfo::{System, Pid, Users};
use tokio::time::sleep;
use log::{info, warn};
use env_logger;

use doh::{
    Config, 
    read_config, 
    format_bytes, 
    get_dir_size, 
    notify_msg
};

#[tokio::main]
async fn main() {
    env_logger::init();

    // 从 config.json 读取配置
    let config: Config = read_config("config.json");
    // let fs_config = config.fs_config;

    let current_process_pid = sysinfo::get_current_pid().expect("Failed to get current PID");

    // 启动 shell 脚本
    let start_time = SystemTime::now();
    let script_path = &config.job_monitor.script_path;
    let child = Command::new("sh")
        .arg(script_path)
        .spawn()
        .expect("Failed to start script");

    let pid = child.id();
    info!("Started script (script: {}) with PID: {}", script_path, pid);

    let _ = notify_msg(&config.notice_config, &config.job_monitor.receiver, &format!("Started script (script: {}) with PID: {}", script_path, pid)).await;

    let config_clone = config.clone();
    tokio::spawn(async move {
        let config = config_clone;
        let mut sys = System::new_all();
        loop {
            sys.refresh_all();

            let mut msg_content = String::new();
            // 监控主进程及其子进程
            if let Some(process) = sys.process(Pid::from_u32(pid)) {
                monitor_process(&config, &sys, process);
            }

            // Check file increase/decrease data size
            for path_space in &config.disk_monitor.path_space {
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
                let _ = notify_msg(&config.notice_config, &config.disk_monitor.receiver, &msg_content).await;
                msg_content.clear();
            }

            thread::sleep(Duration::from_secs(config.job_monitor.check_interval));
        }
    });

    
    // 保持主线程活跃
    loop {
        let mut sys = System::new_all();
        sys.refresh_all();

        // 检查主进程及子进程是否仍在运行
        let mut main_process_running = false;
        let mut sub_processes_running = false;
        if let Some(process) = sys.process(Pid::from_u32(pid)) {
            if process.status() != sysinfo::ProcessStatus::Zombie {
                main_process_running = true;
            }
        } else {
            for process in sys.processes() {
                if process.1.parent() == Some(Pid::from_u32(pid)) {
                    sub_processes_running = true;
                    break;
                }
            }
        }
        if (sys.process(current_process_pid).is_none() || !main_process_running) && !sub_processes_running {
            info!("Pid: {:?} End. Total time taken: {:?}", pid, start_time.elapsed().unwrap());
            warn!("Monitored script and all child processes have completed. Exiting main thread and sub-tasks.");
            let _ = notify_msg(&config.notice_config, &config.job_monitor.receiver, &format!("Pid: {:?} End. Total time taken: {:.?}", pid, start_time.elapsed().unwrap())).await;
            for process in sys.processes() {
                if process.1.parent() == Some(current_process_pid) {
                    // let _ = Command::new("kill")
                    // .arg("-9")
                    // .arg(process.1.pid().to_string())
                    // .output()
                    // .expect("Failed to kill subprocess");
                    process.1.kill();
                }
            }
            break;
        }
        sleep(Duration::from_secs(1)).await;
    }
    
}

fn monitor_process(config: &Config, sys: &System, process: &sysinfo::Process) {
    let res_config = &config.resource_monitor;
    let process_cmd: Vec<String> = process.cmd().iter().map(|s| s.to_string_lossy().into_owned()).collect();
    let users = Users::new_with_refreshed_list();
    let user_name = users.get_user_by_id(process.user_id().unwrap()).unwrap().name();
    if process.cpu_usage() >= res_config.cpu_threshold || process.memory() >= res_config.memory_threshold || process.virtual_memory() >= res_config.virtual_memory_threshold {
        let mut msg_content = format!("User: {:?} Process {} ({}): CPU usage: {}%, Memory usage: {}, Virtual Memory: {}\n",
            user_name,
            process.pid(),
            process_cmd.join(" "),
            process.cpu_usage(),
            format_bytes(process.memory()),
            format_bytes(process.virtual_memory())
        );
        let process_cmd: Vec<String> = process.cmd().iter().map(|s| s.to_string_lossy().into_owned()).collect();
        warn!(
            "Warning: User: {:?} Process {} ({}): CPU usage: {}%, Memory usage: {}, Virtual Memory: {}",
            user_name,
            process.pid(),
            process_cmd.join(" "),
            process.cpu_usage(),
            format_bytes(process.memory()),
            format_bytes(process.virtual_memory())
        );
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
        // sys.refresh_cpu_usage(); 
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
        if msg_content.len() > 0 {
            let _ = notify_msg(&config.notice_config, &res_config.receiver, &msg_content);
            msg_content.clear();
        }
    }

    let read_bytes = process.disk_usage().total_read_bytes;
    let write_bytes = process.disk_usage().total_written_bytes;
    let iops = read_bytes + write_bytes; // Simplified IOPS calculation
    if iops > res_config.iops_threshold {
        warn!(
            "Warning: User: {:?} Process {} ({}) has high IOPS: {}, read: {}, write: {}",
            user_name,
            process.pid(),
            process_cmd.join(" "),
            format_bytes(iops),
            format_bytes(read_bytes),
            format_bytes(write_bytes)
        );
        let msg_content = format!("Warning: User: {:?} Process {} ({}) has high IOPS: {}, read: {}, write: {}\n",
            user_name,
            process.pid(),
            process_cmd.join(" "),
            format_bytes(iops),
            format_bytes(read_bytes),
            format_bytes(write_bytes)
        );
        let _ = notify_msg(&config.notice_config, &res_config.receiver, &msg_content);
    }

    // 监控子进程
    if let Some(tasks) = process.tasks() {
        for task_pid in tasks {
            if let Some(task) = sys.process(*task_pid) {
                monitor_process(&config, &sys, task);
            }
        }
    }
}


