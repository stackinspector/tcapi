use super::prelude::*;

pub struct Cert;

impl Service for Cert {
    const SERVICE: &'static str = "ssl";
    const HOST: &'static str = "ssl.tencentcloudapi.com";
    const VERSION: &'static str = "2019-12-05";
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct UploadCertificate {
    pub certificate_public_key: String,
    pub certificate_private_key: String,
    pub alias: String,
    pub allow_download: bool,
    pub repeatable: bool,
    pub certificate_type: CertificateType,
}

#[derive(Deserialize_enum_str, Serialize_enum_str)]
pub enum CertificateType {
    // CA,
    SVR,
}

impl Action for UploadCertificate {
    type Res = UploadCertificateRes;
    type Service = Cert;
    const STYLE: Style = Style::PostJson;
    const ACTION: &'static str = "UploadCertificate";
    const REGION: bool = false;
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct UploadCertificateRes {
    pub certificate_id: String,
    pub repeat_cert_id: String,
    // pub request_id: String,
}
