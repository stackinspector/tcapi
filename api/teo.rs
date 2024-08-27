use super::prelude::*;

pub struct EdgeOne;

impl Service for EdgeOne {
    const SERVICE: &'static str = "teo";
    const HOST: &'static str = "teo.tencentcloudapi.com";
    const VERSION: &'static str = "2022-09-01";
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct DownloadL7Logs {
    pub start_time: String, // ISO8601
    pub end_time: String, // ISO8601
    pub zone_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domains: Option<Vec<String>>,
    pub limit: u32,
    pub offset: u32,
}

impl Action for DownloadL7Logs {
    type Res = DownloadL7LogsRes;
    type Service = EdgeOne;
    const STYLE: Style = Style::PostJson;
    const ACTION: &'static str = "DownloadL7Logs";
    const REGION: bool = false;
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct DownloadL7LogsRes {
    pub total_count: u32,
    pub data: Vec<L7OfflineLog>,
    // pub request_id: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct L7OfflineLog {
    pub domain: String,
    pub area: String,
    pub log_packet_name: String,
    pub url: String,
    pub log_time: u64,
    pub log_start_time: String, // ISO8601
    pub log_end_time: String, // ISO8601
    pub size: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ModifyHostsCertificate {
    pub zone_id: String,
    pub hosts: Vec<String>,
    pub server_cert_info: Vec<ServerCertInfo>,
    pub mode: HostsCertificateMode,
    // omited
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ServerCertInfo {
    pub cert_id: String,
    // omited
}

#[allow(non_camel_case_types)]
#[derive(Deserialize_enum_str, Serialize_enum_str)]
pub enum HostsCertificateMode {
    // disable,
    // eofreecert,
    sslcert,
}

impl Action for ModifyHostsCertificate {
    type Res = ModifyHostsCertificateRes;
    type Service = EdgeOne;
    const STYLE: Style = Style::PostJson;
    const ACTION: &'static str = "ModifyHostsCertificate";
    const REGION: bool = false;
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ModifyHostsCertificateRes {
    // pub request_id: String,
}
