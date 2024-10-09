use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq, Clone)]
pub struct ErrorResponse {
    pub status: String,
    pub message: String,
    pub order_id: String,
}
