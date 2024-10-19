#![deny(unused_results)]

#![no_std]

use tcapi_model::model::*;

use heapless::String as AString;

struct AFString<const LEN: usize> {
    buf: AString<LEN>,
}

impl<const LEN: usize> AFString<LEN> {
    fn new() -> AFString<LEN> {
        AFString { buf: AString::new() }
    }

    fn put_as_mut(&mut self, s: &str) -> &mut str {
        self.buf.clear();
        self.buf.push_str(s).unwrap();
        &mut self.buf
    }

    fn format(&mut self, fmt: core::fmt::Arguments) -> &str {
        self.buf.clear();
        core::fmt::Write::write_fmt(&mut self.buf, fmt).unwrap();
        &self.buf
    }

    fn join_lines<const N: usize>(&mut self, lines: [&str; N]) -> &str {
        self.buf.clear();
        let mut lines = lines.into_iter();
        if let Some(first) = lines.next() {
            self.buf.push_str(first).unwrap();
            for line in lines {
                self.buf.push_str("\n").unwrap();
                self.buf.push_str(line).unwrap();
            }
        }
        &self.buf
    }
}

const SECRET_ID_LEN: usize = 36;
const SECRET_KEY_LEN: usize = 32;
const SECRET_KEY_PREFIX: &str = "TC3";
const SECRET_KEY_PREFIX_LEN: usize = SECRET_KEY_PREFIX.len();
const SECRET_KEY_FULL_LEN: usize = SECRET_KEY_LEN + SECRET_KEY_PREFIX_LEN;

pub struct KeyStorage {
    buf: [u8; SECRET_KEY_FULL_LEN],
}

impl KeyStorage {
    /// SAFETY: buf should zeroize after read
    pub fn from_str_conditional(s: &str) -> KeyStorage {
        let mut buf = [0; SECRET_KEY_FULL_LEN];
        buf[..SECRET_KEY_PREFIX_LEN].copy_from_slice(SECRET_KEY_PREFIX.as_bytes());
        buf[SECRET_KEY_PREFIX_LEN..].copy_from_slice(s.as_bytes());
        KeyStorage { buf }
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf).unwrap()
    }
}

impl Drop for KeyStorage {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.buf);
    }
}

impl<'de> serde::Deserialize<'de> for KeyStorage {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ValueVisitor<'de>(core::marker::PhantomData<&'de ()>);

        impl<'de> serde::de::Visitor<'de> for ValueVisitor<'de> {
            type Value = KeyStorage;

            fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(formatter, "a string no more than {} bytes long", SECRET_KEY_LEN as u64)
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() != SECRET_KEY_LEN {
                    Err(E::invalid_length(v.len(), &self))
                } else {
                    Ok(KeyStorage::from_str_conditional(v))
                }
            }
        }

        deserializer.deserialize_str(ValueVisitor::<'de>(Default::default()))
    }
}

#[derive(serde::Deserialize)]
pub struct Access {
    pub secret_id: AString<SECRET_ID_LEN>,
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
        $(assert_eq!(headers.append(http::header::$k1, header_value!($t1 $v1)), false);)*
        $(assert_eq!(headers.append($k2, header_value!($t2 $v2)), false);)*
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
    formatted: Option<AFString<{ "YYYY-mm-dd".len() }>>,
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
        assert!(matches!(chrono::Datelike::year(&date_naive), 0..9999));
        if self.date_naive != date_naive {
            self.date_naive = date_naive;
        }
        self.formatted.get_or_insert_with(AFString::new).format(format_args!("{}", date_naive.format("%Y-%m-%d")))
    }
}

pub struct LocalClient {
    access: Access,
    hex_buf: HexBuf::<{ SHA256_OUT_LEN * 2 }>,
    num_buf: itoa::Buffer,
    last_date: LastDate,
    action_lowercase_buf: AFString<64>, // vary: ACTION
    canonical_headers_buf: AFString<256>, // vary: STYLE && HOST && SERVICE, ~100+bytes
    credential_scope_buf: AFString<32>, // 26 when YYYY-mm-dd
    authorization_buf: AFString<256>, // 211 when YYYY-mm-dd (&& *1 below)
    canonical_request_buf: AFString<512>, // vary: STYLE && HOST && SERVICE && ACTION, ~200+bytes
    string_to_sign_buf: AFString<128>, // 118 when YYYY-mm-dd && dec timestamp 10 digits
}

impl LocalClient {
    pub fn new(access: Access) -> LocalClient {
        LocalClient {
            access,
            // prev refs are invalidated after next write call guaranteed by ownership law
            hex_buf: HexBuf::new(),
            num_buf: itoa::Buffer::new(),
            last_date: LastDate::new(),
            action_lowercase_buf: AFString::new(),
            canonical_headers_buf: AFString::new(),
            credential_scope_buf: AFString::new(),
            authorization_buf: AFString::new(),
            canonical_request_buf: AFString::new(),
            string_to_sign_buf: AFString::new(),
        }
    }

    pub fn build_request<A: Action, P: AsRef<[u8]>>(
        &mut self,
        serialized_payload: P,
        timestamp: i64,
        region: Option<&str>,
    ) -> http::Request<P> {
        let Access { secret_id, secret_key } = &self.access;

        let service = A::Service::SERVICE;
        let host = A::Service::HOST;
        let version = A::Service::VERSION;
        let action = A::ACTION;
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
        let action_lowercase = self.action_lowercase_buf.put_as_mut(action);
        action_lowercase.make_ascii_lowercase();
        let canonical_headers = self.canonical_headers_buf.format(format_args!("content-type:{content_type}\nhost:{host}\nx-tc-action:{action_lowercase}\n"));
        let signed_headers = "content-type;host;x-tc-action"; // only if Style::PostJson ? *1
        let hashed_request_payload = self.hex_buf.format(sha256(&serialized_payload));
        let canonical_request = self.canonical_request_buf.join_lines([
            http_request_method.as_str(),
            canonical_uri,
            canonical_querystring,
            canonical_headers,
            signed_headers,
            hashed_request_payload,
        ]);

        let credential_scope = self.credential_scope_buf.format(format_args!("{date}/{service}/tc3_request"));
        let hashed_canonical_request = self.hex_buf.format(sha256(canonical_request));
        let string_to_sign = self.string_to_sign_buf.join_lines([
            algorithm,
            timestamp_string,
            credential_scope,
            hashed_canonical_request,
        ]);

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
            assert_eq!(headers.append("X-TC-Region", header_value!(owned region.unwrap())), false);
        }

        request.body(serialized_payload).unwrap()
    }
}
