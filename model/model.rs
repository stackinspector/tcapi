use serde::{Serialize, Deserialize, de::DeserializeOwned};

pub trait Service {
    const SERVICE: &'static str;
    const HOST: &'static str;
    const VERSION: &'static str;
}

pub enum Style {
    // Get,
    // PostForm,
    PostJson,
}

pub trait Action: Serialize {
    type Res: DeserializeOwned;
    type Service: Service;
    const STYLE: Style;
    const ACTION: &'static str;
    const REGION: bool;
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ResponseWrapper<T> {
    pub response: T,
}
