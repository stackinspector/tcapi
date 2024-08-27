#![no_std]
extern crate alloc;
use alloc::{string::{String, ToString}, format};
use tcapi_model::model::*;

#[derive(serde::Deserialize)]
pub struct Access {
    pub secret_id: String,
    pub secret_key: String,
}

fn timestamp_to_date(timestamp: i64) -> String {
    let datetime = chrono::DateTime::from_timestamp(timestamp, 0).unwrap();
    datetime.format("%Y-%m-%d").to_string()
}

const SHA256_OUT_LEN: usize = 32;

fn sha256<B: AsRef<[u8]>>(data: B) -> [u8; SHA256_OUT_LEN] {
    use sha2::Digest;
    let mut ctx = sha2::Sha256::new();
    ctx.update(data.as_ref());
    ctx.finalize().into()
}

fn hmac_sha256<B1: AsRef<[u8]>, B2: AsRef<[u8]>>(key: B1, data: B2) -> [u8; SHA256_OUT_LEN] {
    use hmac::Mac;
    let mut ctx = hmac::Hmac::<sha2::Sha256>::new_from_slice(key.as_ref()).unwrap();
    ctx.update(data.as_ref());
    ctx.finalize().into_bytes().into()
}

macro_rules! header_value {
    (owned $v:expr) => {
        http::HeaderValue::from_str(&$v).unwrap()
    };
    (static $v:expr) => {
        http::HeaderValue::from_static($v)
    };
}

macro_rules! headers {
    (
        $request:expr;
        known {$($k1:ident => $t1:tt $v1:expr;)*}
        custom {$($k2:expr => $t2:tt $v2:expr;)*}
    ) => {{
        let headers = $request.headers_mut().unwrap();
        $(headers.append(http::header::$k1, header_value!($t1 $v1));)*
        $(headers.append($k2, header_value!($t2 $v2));)*
    }};
}

struct HexBuf<const OUT_LEN: usize> {
    buf: [u8; OUT_LEN],
}

impl<const OUT_LEN: usize> HexBuf<OUT_LEN> {
    fn new() -> HexBuf<OUT_LEN> {
        HexBuf { buf: [0; OUT_LEN] }
    }

    fn hex<B: AsRef<[u8]>>(&mut self, data: B) -> &str {
        hex::encode_to_slice(data, &mut self.buf).unwrap();
        core::str::from_utf8(self.buf.as_slice()).unwrap()
    }
}

pub fn build_request<A: Action>(
    payload: &A,
    timestamp: i64,
    Access {
        secret_id,
        secret_key,
    }: &Access,
    region: Option<&str>,
) -> http::Request<String> {
    let mut hex_buf = HexBuf::<{ SHA256_OUT_LEN * 2 }>::new();
    let mut num_buf = itoa::Buffer::new();
    // TODO guarantees that prev refs are invalidated after next write call

    let service = A::Service::SERVICE;
    let host = A::Service::HOST;
    let version = A::Service::VERSION;
    let action = A::ACTION;
    let payload = serde_json::to_string(payload).unwrap();
    let algorithm = "TC3-HMAC-SHA256";
    let timestamp_string = num_buf.format(timestamp);
    let date = timestamp_to_date(timestamp);

    let http_request_method = match A::STYLE {
        Style::PostJson => "POST",
    };
    let canonical_uri = "/";
    let canonical_querystring = match A::STYLE {
        Style::PostJson => "",
        // get: payload -> urlencode Cow?
    };
    let content_type = match A::STYLE {
        Style::PostJson => "application/json; charset=utf-8",
    };
    // TODO wait for feature(generic_const_exprs)
    let action_lowercase = action.to_ascii_lowercase();
    let canonical_headers = format!("content-type:{content_type}\nhost:{host}\nx-tc-action:{action_lowercase}\n");
    let signed_headers = "content-type;host;x-tc-action";
    let hashed_request_payload = hex_buf.hex(sha256(&payload));
    let canonical_request = [
        http_request_method,
        canonical_uri,
        canonical_querystring,
        canonical_headers.as_str(),
        signed_headers,
        hashed_request_payload,
    ].join("\n");

    let credential_scope = format!("{date}/{service}/tc3_request");
    let hashed_canonical_request = hex_buf.hex(sha256(canonical_request));
    let string_to_sign = [
        algorithm,
        timestamp_string,
        credential_scope.as_str(),
        hashed_canonical_request,
    ].join("\n");

    let secret_date = hmac_sha256(format!("TC3{secret_key}"), date);
    let secret_service = hmac_sha256(secret_date, service);
    let secret_signing = hmac_sha256(secret_service, "tc3_request");
    let signature = hex_buf.hex(hmac_sha256(secret_signing, string_to_sign));

    let authorization = format!("{algorithm} Credential={secret_id}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}");

    let mut request = http::Request::builder()
        .method(match A::STYLE {
            Style::PostJson => http::Method::POST,
        })
        .uri(canonical_uri);

    headers! {
        request;
        known {
            AUTHORIZATION => owned authorization;
            CONTENT_TYPE => static content_type;
            HOST => static host;
        }
        custom {
            "X-TC-Action" => static action;
            "X-TC-Timestamp" => owned timestamp_string;
            "X-TC-Version" => static version;
        }
    }

    if A::REGION {
        let headers = request.headers_mut().unwrap();
        headers.append("X-TC-Region", header_value!(owned region.unwrap()));
    }

    request.body(payload).unwrap()
}
