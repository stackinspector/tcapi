mod prelude {
    pub use alloc::{string::String, vec::Vec};
    pub use serde::{Deserialize, Serialize};
    pub use serde_enum_str::{Deserialize_enum_str, Serialize_enum_str};
    pub use crate::model::{Service, Action, Style};
}

mod teo;
pub use teo::*;
mod cert;
pub use cert::*;
