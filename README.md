# DoH: Disributed jObs Hypervisor

## 0x01 Deployment

Install Rust
```bash
# Install rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# or update
rustup update
Install openssl and libssl-dev
sudo apt-get update
sudo apt install openssl 
sudo apt install libssl-dev
sudo apt install pkg-config
```

## 0x02 compile
```bash
git clone https://github.com/ZimaBlue-AI/DoH
cd DoH
cargo build --release
```

## 0x03 configuration

### 3.1 Resource monitoring program configuration, saved as config.json

```json
{
    "disk_monitor": {
        "disk_space_threshold": 107374182400,  #100GB
        "check_interval": 60,  #1 miniute
        "mount_points": ["/mnt/c"],
        "path_space": [
            {
                "path":"/mnt/c/DoH/",
                "space_threshold":[10, 26214400] # lower than 10bytes, or larger than 25MB will give out warning
            }
        ],
        "receiver": [{
                "receive_id": "ou_***",  
                "receive_id_type": "open_id" 
            }]
    },
    "resource_monitor": {
        "check_interval": 10,  #10 seconds
        "iops_threshold": 26214400, # read/write bytes over 25MB
        "memory_threshold": 1073741824,  # RAM over 1GB
        "virtual_memory_threshold": 10737418240, # Virtual memory over 1GB
        "cpu_threshold": 190.0, # CPU　usage over 190%
        "exclude_self_process": true, # don't warrning the self monitor processes
        "receiver": [{
                "receive_id": "186***", # phone
                "receive_id_type": "mobile" 
            }]
    },
    "notice_config": {
        "fs_config": {
            "app_id": "cli_***", # feishu(lark) app_id
            "app_secret": "***", # feishu(lark) app_secret
            "receiver": [{
                "receive_id": "oc_***"
                "receive_id_type": "chat_id" 
            }]
        }
    }
}
```


### 3.2 Node hypervisor configuration

```json
{
    "disk_monitor": {
        "disk_space_threshold": 107374182400,  #100GB
        "check_interval": 60,  #1 miniute
        "mount_points": ["/mnt/c"],
        "path_space": [
            {
                "path":"/mnt/c/DoH/",
                "space_threshold":[10, 26214400] # lower than 10bytes, or larger than 25MB will give out warning
            }
        ],
        "receiver": [{
                "receive_id": "ou_***",  
                "receive_id_type": "open_id" 
            }]
    },
    "resource_monitor": {
        "check_interval": 10,  #10 seconds
        "iops_threshold": 26214400, # read/write bytes over 25MB
        "memory_threshold": 1073741824,  # RAM over 1GB
        "virtual_memory_threshold": 10737418240, # Virtual memory over 1GB
        "cpu_threshold": 190.0, # CPU　usage over 190%
        "exclude_self_process": true, # don't warrning the self monitor processes
        "receiver": [{
                "receive_id": "186***", # phone
                "receive_id_type": "mobile" 
            }]
    },
    "node_monitor": {
        "run_time": 10,
        "check_interval": 60,
        "node_id": "management_node",  # node name
        "exclude_users": ["root"],     # don not daemon root user
        "include_users": ["ai"],       # daemon user list
        "receiver": [{
            "receive_id": "186***",
            "receive_id_type": "mobile" 
        }]
    },
    "notice_config": {
        "fs_config": {
            "app_id": "cli_***", # feishu(lark) app_id
            "app_secret": "***", # feishu(lark) app_secret
            "receiver": []
        }
    }
}
```

### 3.3 Job management program configuration
```
{
    "disk_monitor": {
        "disk_space_threshold": 107374182400,  #100GB
        "check_interval": 60,  #1 miniute
        "mount_points": ["/mnt/c"],
        "path_space": [
            {
                "path":"/mnt/c/DoH/",
                "space_threshold":[10, 26214400] # lower than 10bytes, or larger than 25MB will give out warning
            }
        ],
        "receiver": [{
                "receive_id": "ou_***",  
                "receive_id_type": "open_id" 
            }]
    },
    "resource_monitor": {
        "check_interval": 10,  #10 seconds
        "iops_threshold": 26214400, # read/write bytes over 25MB
        "memory_threshold": 1073741824,  # RAM over 1GB
        "virtual_memory_threshold": 10737418240, # Virtual memory over 1GB
        "cpu_threshold": 190.0, # CPU　usage over 190%
        "exclude_self_process": true, # don't warrning the self monitor processes
        "receiver": [{
                "receive_id": "186***", # phone
                "receive_id_type": "mobile" 
            }]
    },
    "job_monitor": {
        "check_interval": 10,
        "script_path": "/mnt/c/DoH/test/test.sh", # run job shell script
        "receiver": [{
                "receive_id": "ou_***",
                "receive_id_type": "open_id" 
            }]
    },
    "notice_config": {
        "fs_config": {
            "app_id": "cli_***", # feishu(lark) app_id
            "app_secret": "***", # feishu(lark) app_secret
            "receiver": [{
                "receive_id": "oc_***"
                "receive_id_type": "chat_id" 
            }]
        }
    }
}
```

## 0x04 Run
### 4.1 Resource monitoring
```bash
RUST_LOG=INFO ./target/release/doh
```

### 4.2 Node monitoring
```bash
RUST_LOG=INFO ./target/release/node_monitor
```
 
### 4.3 Job monitoring
```bash
RUST_LOG=INFO ./target/release/job_monitor
```

## 0x05 TODO

- [ ] Add support for other IM (WeCom, DingTalk, Slack, Discord, etc.)
- [ ] Increase resource use assessment report
- [ ] ReAct according to constraint policy (Response & Action)
- [ ] Remote control and web interaction
- [ ] Increase artificial intelligence management

## 0x06 License

Licensed under [GNU General Public License v3.0 (GPL-3.0)](https://www.gnu.org/licenses/gpl-3.0.html).

---
Copyright (c) 2024 ZimaBlueAI Tech. Co. Ltd.
