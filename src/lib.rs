use serde::{Serialize,Deserialize};
use std::fs;
use std::net::Ipv4Addr;
use reqwest::{Client, Method, header::{HeaderMap, HeaderName, HeaderValue}}; 

use anyhow::Result;
use reqwest::Error; 
use serde_json;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;
use log::error;
use tokio::time::{sleep, Duration};
use std::collections::HashMap;

#[derive(Deserialize,Clone)]
pub struct Config {
    pub resource_monitor: ResourceMonitorConfig,
    pub disk_monitor: DiskMonitorConfig,
    pub network_monitor: NetworkMonitorConfig,
    pub node_monitor: NodeMonitorConfig,
    pub job_monitor: JobMonitorConfig,
    pub notice_config: NoticeConfig
}

#[derive(Deserialize,Clone)]
pub struct ResourceMonitorConfig {
    pub check_interval: u64,
    pub iops_threshold: u64,
    pub memory_threshold: u64,
    pub virtual_memory_threshold: u64,
    pub cpu_threshold: f32,
    pub exclude_self_process: bool,
    pub receiver: Vec<ReceiverConfig>
}

#[derive(Deserialize,Clone)]
pub struct DiskMonitorConfig {
    pub disk_space_threshold: u64,
    pub check_interval: u64,
    pub mount_points: Vec<String>,
    pub path_space: Vec<PathSpace>,
    pub receiver: Vec<ReceiverConfig>
}
#[derive(Deserialize,Clone)]
pub struct NetworkMonitorConfig {
    pub check_interval: u64,
    pub data_threshold: u64,
    pub exclude_ipv4_address: Vec<String>,
    pub receiver: Vec<ReceiverConfig>
}

#[derive(Deserialize,Clone)]
pub struct PathSpace {
    pub path: String,
    pub space_threshold: (u64, u64)
}


#[derive(Deserialize,Clone)]
pub struct NodeMonitorConfig {
    pub run_time: u64,
    pub check_interval: u64,
    pub node_id: String,
    pub exclude_users: Vec<String>,
    pub include_users: Vec<String>,
    pub receiver: Vec<ReceiverConfig>
}


#[derive(Deserialize, Clone)]
pub struct JobMonitorConfig {
    pub check_interval: u64,
    pub script_path: String,
    pub receiver: Vec<ReceiverConfig>
}

#[derive(Deserialize, Clone, PartialEq)]
pub struct ReceiverConfig {
    pub receive_id: String,
    pub receive_id_type: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct MsgPayload {
    content: String,
    receive_id: String,
    msg_type: String,
    uuid: String
}

#[derive(Deserialize,Clone)]
pub struct NoticeConfig {
    pub fs_config: FsConfig
}

#[derive(Deserialize,Clone)]
pub struct FsConfig {
    pub app_id: String,
    pub app_secret: String,
    pub receiver: Vec<ReceiverConfig>
}

#[derive(Serialize,Clone)]
pub struct AppConfig {
    pub app_id: String,
    pub app_secret: String
}

#[warn(private_interfaces)]
#[derive(Deserialize, Debug,Clone)]
struct AccessTokenResponse {
    tenant_access_token: String,
    expire: u64,
}

#[derive(Deserialize, Debug,Clone)]
struct CommonResponse {
    code: u32,
    msg: String
}

#[allow(dead_code)]
pub fn read_config(config_path: &str) -> Config {
    let config_data = fs::read_to_string(config_path).expect("Unable to read config file");
    serde_json::from_str(&config_data).expect("Unable to parse config file")
}

#[allow(dead_code)]
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 9] = ["B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"];
    let mut size = bytes as f64;
    let mut unit = UNITS[0];
    for &u in &UNITS {
        if size < 1024.0 {
            unit = u;
            break;
        }
        size /= 1024.0;
    }
    format!("{:.2} {}", size, unit)
}

#[allow(dead_code)]
pub fn is_address_in_list(address: &str, list: &[String]) -> bool {
    let addr: Ipv4Addr = address.split(':').next().unwrap().parse().unwrap();
    let addr_str = addr.to_string();
    let addr_parts: Vec<&str> = addr_str.split('.').collect();
    for pattern in list {
        if is_match(&addr_parts, pattern) {
            return true;
        }
    }
    false
}

#[allow(dead_code)]
pub fn is_match(addr_parts: &[&str], pattern: &str) -> bool {
    let pattern_parts: Vec<&str> = pattern.split('.').collect();
    for (addr_part, pattern_part) in addr_parts.iter().zip(pattern_parts.iter()) {
        if pattern_part != &"*" && addr_part != pattern_part {
            return false;
        }
    }
    true
}

#[allow(dead_code)]
pub fn get_dir_size(path: &str) -> u64 {
    let mut total_size = 0;
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries {
            if let Ok(entry) = entry {
                let metadata = entry.metadata().unwrap();
                if metadata.is_dir() {
                    total_size += get_dir_size(entry.path().to_str().unwrap());
                } else {
                    total_size += metadata.len();
                }
            }
        }
    }
    total_size
}

#[allow(dead_code)]
pub async fn construct_send_larkmd_msg(receive_id: &str, receive_id_type: &str, msg_content: &str, 
    img_key: &str, button_content: &str, button_url: &str, header: &str, header_style: &str, tenant_access_token: &str) -> serde_json::Value {
    let extra = construct_template_mdextra(&img_key, &button_content, &button_url);
    let mut header_style = header_style;
    if header_style == "" {
        header_style = "blue";
    }
    let payload = constuct_interactive_msgpayload(&receive_id, &msg_content, &extra, &header, &header_style);
    if payload == "" {
        return serde_json::Value::default();
    }
    let url = format!("https://open.feishu.cn/open-apis/im/v1/messages?receive_id_type={}",receive_id_type);
    let timeout = 5;
    let try_times = 3u8;
    let authorization_header = format!("Bearer {}", tenant_access_token);
    let headers = vec![
        ("Content-Type", "application/json"),
        ("Authorization", &authorization_header),
        // Add more headers here
    ];
    let data_json = match try_connect_requests("POST", &url, headers, &payload, timeout, try_times).await {
        Ok(response) => {
            // 确保响应状态是成功的
            if response.status().is_success() {
                let json_value = response.json::<serde_json::Value>().await.expect("Failed to deserialize");
                let data_json: serde_json::Value = serde_json::from_value(json_value).expect("Failed to deserialize");
                
                data_json
            } else {
                error!("Request failed with status: {}", response.status());
                serde_json::Value::default() // Return an empty serde_json::Value
            }
        }
        Err(e) => {
            error!("Error: {}", e);
            serde_json::Value::default() // Return an empty serde_json::Value
        }
    };
    
    data_json
}

#[allow(dead_code)]
pub async fn send_msg(receive_id: &str, receive_id_type: &str, msg_type: &str, content: &str, tenant_access_token: &str) -> String  {
    let url = format!("https://open.feishu.cn/open-apis/im/v1/messages?receive_id_type={}",receive_id_type);

    //TODO：生成随机唯一的uuid，发送消息成功返回uuid
    let uuid = Uuid::new_v4();

    let msg_payload = MsgPayload {
        content: content.to_string(),
        receive_id: receive_id.to_string(),
        msg_type: msg_type.to_string(),
        uuid: uuid.to_string(),
    };

    let payload = match serde_json::to_string(&msg_payload) {
        Ok(json_str) => json_str,
        Err(e) => {
            error!("Serialization failed: {:?}", e);
            "".to_string()
        }
    };
    if payload == "" {
        return "".to_string();
    }

    let timeout = 5;
    let try_times = 3u8;

    let authorization_header = format!("Bearer {}", tenant_access_token);
    let headers = vec![
        ("Content-Type", "application/json"),
        ("Authorization", &authorization_header),
        // Add more headers here
    ];

    let data_json = match try_connect_requests("POST", &url, headers, &payload, timeout, try_times).await {
        Ok(response) => {
            // 确保响应状态是成功的
            
            if response.status().is_success() {
                let json_value = response.json::<serde_json::Value>().await.expect("Failed to deserialize");
                let data_json: serde_json::Value = serde_json::from_value(json_value).expect("Failed to deserialize");   
                data_json
            } else {
                error!("Request failed with status: {}", response.status());
                serde_json::Value::default()
            }
        }
        Err(e) => {
            error!("Error: {}", e);
            serde_json::Value::default()
        }
    };
    
    
    if data_json.get("code").is_some() && data_json["code"].as_u64() == Some(0) {
        uuid.to_string()
    } else {
        "".to_string()
    }
    // "content": "{\"type\": \"template\", \"data\": { \"template_id\": \"ctp_xxxxxxxxxxxx\", \"template_variable\": {\"article_title\": \"这是文章标题内容\"} } }"
}

#[allow(dead_code)]
fn construct_template_mdextra(img_key: &str, button_content: &str, button_url: &str) -> serde_json::Value {
    if img_key == "" {
        serde_json::json!([{
                "actions": [
                { 

                    "tag": "button",
                    "text": {
                        "content": button_content,
                        "tag": "plain_text"
                    },
                    "type": "primary",
                    "url": button_url
                }],
                "tag": "action"
            }
        ])
    } else {
        serde_json::json!([
            {
                "alt": {
                    "content": "",
                    "tag": "plain_text"
                },
                "img_key": img_key, 
                "tag": "img"
            },
            {
                "actions": [
                { 
                    "tag": "button",
                    "text": {
                        "content": button_content,
                        "tag": "plain_text"
                    },
                    "type": "primary",
                    "url": button_url
                }],
                "tag": "action"
            }
        ])
    }

}

#[allow(dead_code)]
fn constuct_interactive_msgpayload(receive_id: &str, msg_content: &str, extra: &serde_json::Value, header: &str, header_style: &str) -> String {
    let mut larkmd_msg_json = serde_json::json!({
        "config":{
            "wide_screen_mode": true
        }, 
        "elements":[
            { 
                "tag":"div",
                "text":{
                    "tag": "lark_md",
                    "content": msg_content
                }
            }
        ],
        "header": {
            "template": header_style, // blue
            "title": {
                "content": header, //@猫猫果儿小学放学家校对接计划
                "tag": "plain_text"
            }
        }
    });
    let mut elements = larkmd_msg_json["elements"].as_array().unwrap().to_vec();
    if let serde_json::Value::Array(extra_array) = extra {
        elements.extend(extra_array.clone());
    }
    larkmd_msg_json["elements"] = serde_json::Value::Array(elements);
    let content = match serde_json::to_string(&larkmd_msg_json) {
        Ok(json_str) => json_str,
        Err(e) => {
            error!("Serialization failed: {:?}", e);
            "".to_string()
        }
    };
    let payload_json = serde_json::json!({
        "content": content,
        "msg_type": "interactive",
        "receive_id": receive_id
    });
    let payload = match serde_json::to_string(&payload_json) {
        Ok(json_str) => json_str,
        Err(e) => {
            error!("Serialization failed: {:?}", e);
            "".to_string()
        }
    };
    payload
}


async fn try_connect_requests(
    method: &str,
    url: &str,
    headers: Vec<(&str, &str)>,
    payload: &str,
    timeout: u64,
    try_times: u8
) -> Result<reqwest::Response, anyhow::Error> {
    let client = Client::new();
    let mut attempts = 0;

    while attempts < try_times {
        let mut header_map = HeaderMap::new();
        for (name, value) in &headers {
            let header_name = HeaderName::from_bytes(name.as_bytes())?;
            let header_value = HeaderValue::from_bytes(value.as_bytes())?;
            header_map.insert(header_name, header_value);
        }

        let request = client.request(Method::from_bytes(
            method.to_uppercase().as_bytes()).unwrap(), url)
            .headers(header_map)
            .body(payload.to_string())
            .timeout(Duration::from_secs(timeout))
            .send()
            .await;
        match request {
            Ok(response) => return Ok(response),
            Err(e) => {
                error!("Attempt {} failed: {}", attempts + 1, e);
                sleep(Duration::from_secs(1)).await;
                attempts += 1;
            }
        }
    }
    
    Err(anyhow::Error::msg("Max attempts exceeded"))
}

#[allow(dead_code)]
pub async fn apply_token(app_id: String, app_secret: String) -> Result<String, tokio::io::Error> {
    let app_config = AppConfig {
        app_id,
        app_secret
    };

    let token_daemon_actor = Arc::new(TokenActor {
        app_config,
        stored_token: Mutex::new("".to_string()),
        stored_token_expire: Mutex::new(0),
    });

    // 获取token
    let tenant_access_token = token_daemon_actor.get_tenant_access_token().await;
    Ok(tenant_access_token)
}

// 假定 FEISHU_TOKEN_NOT_SUPPORT_CODE 是一个包含不支持的错误代码的集合
#[allow(dead_code)]
const FEISHU_TOKEN_NOT_SUPPORT_CODE: [i64; 2] = [99991663, 99991665];

async fn async_get_tenant_access_token(app_config: &AppConfig) -> Result<AccessTokenResponse, Error> {
    let payload = match serde_json::to_string(&app_config) {
        Ok(json_str) => json_str,
        Err(e) => {
            error!("Serialization failed: {:?}", e);
            "".to_string()
        }
    };

    let timeout = 5;
    let try_times = 3u8;

    let headers = vec![
        ("Content-Type", "application/json"),
        // Add more headers here
    ];

    let url = "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal";

    let result_map: serde_json::Value = match try_connect_requests("POST", url, headers, &payload, timeout, try_times).await {
        Ok(response) => {
            // 确保响应状态是成功的
            if response.status().is_success() {
                response.json::<serde_json::Value>().await.expect("Failed to deserialize")
            } else {
                error!("Request failed with status: {}", response.status());
                serde_json::Value::default()
            }
        }
        Err(e) => {
            error!("Error: {}", e);
            serde_json::Value::default()
        }
    };
    let response = serde_json::from_value(result_map).expect("Failed to deserialize");
    Ok(response)
}


#[allow(dead_code)]
fn token_is_invalid(response: &CommonResponse) -> bool {
    FEISHU_TOKEN_NOT_SUPPORT_CODE.contains(&(response.code as i64))
    || response.msg.contains("Invalid access token") 
    || (response.msg.contains("token") && response.msg.contains("tenant"))
}

pub struct TokenActor {
    pub app_config: AppConfig,
    pub stored_token: Mutex<String>,
    pub stored_token_expire: Mutex<u64>,
}

#[allow(async_fn_in_trait)]
pub trait TokenActorTrait {
    async fn ask(&self, message: &str) -> String;

    async fn get_tenant_access_token(&self) -> String;
    // 定义其他需要的异步方法...
}

impl TokenActorTrait for TokenActor {

    async fn ask(&self, message: &str) -> String {
        if message == "GetToken" {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            let token_expire = self.stored_token_expire.lock().await;
            if *token_expire >= now + 60 {
                self.stored_token.lock().await.clone()
            } else {
                // Token过期，重新获取逻辑（留作实现）
                self.get_tenant_access_token().await // Await the get_tenant_access_token() function call
            }
        } else {
            message.to_string() // 非"GetToken"消息的处理
        }
    }

    async fn get_tenant_access_token(&self) -> String {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let mut token_expire = self.stored_token_expire.lock().await;

        if now > *token_expire {
            let response = async_get_tenant_access_token(&self.app_config).await.expect("Failed to get tenant access token");
            let mut token = self.stored_token.lock().await;
            *token_expire = now + response.expire;
            *token = response.tenant_access_token;
        }
        self.stored_token.lock().await.clone()
    }
}

pub async fn notify_msg(notice_config: &NoticeConfig, receiver_vec: &Vec<ReceiverConfig>, msg_content: &str) -> String {
    if !notice_config.fs_config.app_id.is_empty() {
        let fs_config = &notice_config.fs_config;
        let tenant_access_token = match apply_token(fs_config.app_id.clone(), fs_config.app_secret.clone()).await {
            Ok(token) => token,
            Err(e) => {
                error!("Error: {:?}", e);
                String::from("")
            }
        };
        // println!("tenant_access_token1: {:?}", tenant_access_token1);
        if tenant_access_token == "" {
            return "".to_string();
        }
        let content_json = serde_json::json!({
            "text": msg_content.to_string(),
        });
        let msg_content = match serde_json::to_string(&content_json) {
            Ok(json_str) => json_str,
            Err(e) => {
                error!("Serialization failed: {:?}", e);
                return "".to_string();
            }
        };
        if msg_content == "" {
            return "".to_string();
        }
        let mut send_bool = true;
        let mut all_receivers_vec = receiver_vec.clone();
        for receiver in &notice_config.fs_config.receiver {
            all_receivers_vec.push(receiver.clone());
        }

        let mut seen_receive_ids = HashMap::new();

        for receiver in all_receivers_vec {
            let mut receive_id = receiver.receive_id.clone();
            let mut receive_id_type = receiver.receive_id_type.clone();

            if seen_receive_ids.contains_key(&receive_id) {
                continue;
            }

            if receive_id_type != "open_id" && receive_id_type != "chat_id" {
                if receive_id_type == "email" || receive_id_type == "mobile" {
                    receive_id = batch_get_fs_id(&receive_id, &receive_id_type, &tenant_access_token).await;
                    receive_id_type = "open_id".to_string();
                } else {
                    return "".to_string();
                }
            }

            seen_receive_ids.insert(receive_id.clone(), true);

            let msg_type = "text";
            let uuid = send_msg(&receive_id, &receive_id_type, &msg_type, &msg_content, &tenant_access_token).await;
            if uuid == "" {
                send_bool = false;
            }
        }
        if send_bool{
            return "success".to_string()
        } else {
            return "".to_string()
        }
    } else {
        "".to_string()
    }
}

async fn batch_get_fs_id(account: &str, account_type: &str, tenant_access_token: &str) -> String {
    let url = format!("https://open.feishu.cn/open-apis/contact/v3/users/batch_get_id?user_id_type=open_id");

    let payload_json = serde_json::json!({
        format!("{}s",account_type): [account],
        "include_resigned": false
    });
    
    let authorization_header = format!("Bearer {}", tenant_access_token);
    let headers = vec![
        ("Content-Type", "application/json"),
        ("Authorization", &authorization_header),
        // Add more headers here
    ];
    let payload = match serde_json::to_string(&payload_json) {
        Ok(json_str) => json_str,
        Err(e) => {
            error!("Serialization failed: {:?}", e);
            "".to_string()
        }
    };
    if payload == "" {
        return "".to_string();
    }

    let timeout = 5;
    let try_times = 3u8;

    let data_json = match try_connect_requests("POST", &url, headers, &payload, timeout, try_times).await {
        Ok(response) => {
            if response.status().is_success() {
                let json_value = response.json::<serde_json::Value>().await.expect("Failed to deserialize");
                let data_json: serde_json::Value = serde_json::from_value(json_value).expect("Failed to deserialize");
                data_json
            } else {
                error!("Request failed with status: {}", response.status());
                serde_json::Value::default()
            }
        }
        Err(e) => {
            error!("Error: {}", e);
            serde_json::Value::default()
        }
    };
    
    if data_json.get("code").is_some()  && data_json["code"].as_u64()==Some(0) {
        for user in data_json["data"]["user_list"].as_array().unwrap() {
            if user[account_type].as_str().unwrap() == account {
                return user["user_id"].as_str().unwrap().to_string();
            }
        }
    } 
    "".to_string()  
}