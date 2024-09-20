pub fn now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let res = SystemTime::now().duration_since(UNIX_EPOCH);
    let dir = res.is_ok();
    let dur = res.unwrap_or_else(|err| err.duration());
    let secs = dur.as_secs();
    // let nanos = dur.subsec_nanos();
    assert!(secs < (i64::MAX as u64));
    let secs = secs as i64;
    let secs = if dir { secs } else { -secs };
    #[allow(clippy::let_and_return)]
    secs
}

pub fn ureq(req: http::Request<String>) -> Box<dyn std::io::Read + Send + Sync + 'static> {
    let (http_parts, body) = req.into_parts();
    ureq::Request::from(http_parts).send_string(&body).unwrap().into_reader()
}

pub use tcapi_model;
pub use tcapi_client;

use tcapi_model::model::*;
use tcapi_client::*;

pub struct LocalUreqClient {
    inner: LocalClient,
}

impl LocalUreqClient {
    pub fn new(access: Access) -> LocalUreqClient {
        LocalUreqClient { inner: LocalClient::new(access) }
    }

    pub fn req<R: Action>(&mut self, payload: R) -> R::Res {
        let serialized_payload = serde_json::to_string(&payload).unwrap();
        let req = self.inner.build_request::<R, String>(serialized_payload, now(), None);
        println!("{:?}", req);
        let res = ureq(req);
        let res: ResponseWrapper<R::Res> = serde_json::from_reader(res).unwrap();
        res.response
    }
}
