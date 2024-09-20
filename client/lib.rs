#![no_std]
extern crate alloc;
use alloc::{format, string::String, sync::Arc};
use tcapi_model::model::*;

pub struct KeyStorage {
    buf: String,
}

impl KeyStorage {
    /// SAFETY: buf should zeroize after read
    pub fn from_str_conditional(s: &str) -> KeyStorage {
        let buf = format!("TC3{s}");
        KeyStorage { buf }
    }

    pub fn from_string(mut s: String) -> KeyStorage {
        let _self = KeyStorage::from_str_conditional(s.as_str());
        zeroize::Zeroize::zeroize(&mut s);
        _self
    }

    pub fn as_str(&self) -> &str {
        &self.buf
    }
}

impl Drop for KeyStorage {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.buf);
    }
}

impl<'de> serde::Deserialize<'de> for KeyStorage {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // TODO avoid twice buf creation
        String::deserialize(deserializer).map(KeyStorage::from_string)
    }
}

#[derive(serde::Deserialize)]
pub struct Access {
    pub secret_id: String,
    pub secret_key: KeyStorage,
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

    fn format<B: AsRef<[u8]>>(&mut self, data: B) -> &str {
        hex::encode_to_slice(data, &mut self.buf).unwrap();
        core::str::from_utf8(self.buf.as_slice()).unwrap()
    }
}

struct LastDate {
    date_naive: chrono::NaiveDate,
    formatted: Option<FormatStringBuf>,
}

impl LastDate {
    fn new() -> LastDate {
        LastDate {
            date_naive: chrono::NaiveDate::MIN,
            formatted: None,
        }
    }

    fn format(&mut self, timestamp: i64) -> &str {
        let datetime = chrono::DateTime::from_timestamp(timestamp, 0).unwrap();
        let date_naive = datetime.date_naive();
        if self.date_naive != date_naive {
            self.date_naive = date_naive;
        }
        self.formatted.get_or_insert_with(FormatStringBuf::new).format(format_args!("{}", date_naive.format("%Y-%m-%d")))
    }
}

struct FormatStringBuf {
    buf: String,
}

impl FormatStringBuf {
    fn new() -> FormatStringBuf {
        FormatStringBuf { buf: String::new() }
    }

    // fn with_capacity(capacity: usize) -> FormatStringBuf {
    //     FormatStringBuf { buf: String::with_capacity(capacity) }
    // }

    fn format(&mut self, fmt: core::fmt::Arguments) -> &str {
        core::fmt::Write::write_fmt(&mut self.buf, fmt).unwrap();
        &self.buf
    }
}

pub struct LocalClient {
    access: Arc<Access>,
    hex_buf: HexBuf::<{ SHA256_OUT_LEN * 2 }>,
    num_buf: itoa::Buffer,
    last_date: LastDate,
    canonical_headers_buf: FormatStringBuf,
    credential_scope_buf: FormatStringBuf,
    authorization_buf: FormatStringBuf,
}

impl LocalClient {
    pub fn new(access: Arc<Access>) -> LocalClient {
        LocalClient {
            access,
            // prev refs are invalidated after next write call guaranteed by ownership law
            hex_buf: HexBuf::new(),
            num_buf: itoa::Buffer::new(),
            last_date: LastDate::new(),
            canonical_headers_buf: FormatStringBuf::new(),
            credential_scope_buf: FormatStringBuf::new(),
            authorization_buf: FormatStringBuf::new(),
        }
    }

    pub fn build_request<A: Action>(
        &mut self,
        payload: &A,
        timestamp: i64,
        region: Option<&str>,
    ) -> http::Request<String> {
        let Access { secret_id, secret_key } = self.access.as_ref();

        let service = A::Service::SERVICE;
        let host = A::Service::HOST;
        let version = A::Service::VERSION;
        let action = A::ACTION;
        let payload = serde_json::to_string(payload).unwrap();
        let algorithm = "TC3-HMAC-SHA256";
        let timestamp_string = self.num_buf.format(timestamp);
        let date = self.last_date.format(timestamp);

        let http_request_method = match A::STYLE {
            Style::PostJson => http::Method::POST,
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
        let canonical_headers = self.canonical_headers_buf.format(format_args!("content-type:{content_type}\nhost:{host}\nx-tc-action:{action_lowercase}\n"));
        let signed_headers = "content-type;host;x-tc-action";
        let hashed_request_payload = self.hex_buf.format(sha256(&payload));
        let canonical_request = [
            http_request_method.as_str(),
            canonical_uri,
            canonical_querystring,
            canonical_headers,
            signed_headers,
            hashed_request_payload,
        ].join("\n");

        let credential_scope = self.credential_scope_buf.format(format_args!("{date}/{service}/tc3_request"));
        let hashed_canonical_request = self.hex_buf.format(sha256(canonical_request));
        let string_to_sign = [
            algorithm,
            timestamp_string,
            credential_scope,
            hashed_canonical_request,
        ].join("\n");

        let secret_date = hmac_sha256(secret_key.as_str(), date);
        let secret_service = hmac_sha256(secret_date, service);
        let secret_signing = hmac_sha256(secret_service, "tc3_request");
        let signature = self.hex_buf.format(hmac_sha256(secret_signing, string_to_sign));

        let authorization = self.authorization_buf.format(format_args!("{algorithm} Credential={secret_id}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"));

        let uri = http::Uri::builder()
            .scheme(http::uri::Scheme::HTTPS)
            .authority(host)
            .path_and_query(canonical_uri)
            .build().unwrap();
        let mut request = http::Request::builder().method(http_request_method).uri(uri);

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
}
