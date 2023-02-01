use serde::{Deserialize, Serialize};

use crate::adapter::TABLE_NAME;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CasbinRule {
    pub id: Option<i32>,
    pub ptype: Option<String>,
    pub v0: Option<String>,
    pub v1: Option<String>,
    pub v2: Option<String>,
    pub v3: Option<String>,
    pub v4: Option<String>,
    pub v5: Option<String>,
}

rbatis::crud!(CasbinRule {}, TABLE_NAME);
