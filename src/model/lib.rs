use chrono::{DateTime, Utc};
use ulid::Ulid;

pub fn get_new_id() -> String {
    Ulid::new().to_string()
}

pub fn get_current_date_time() -> DateTime<Utc> {
    Utc::now()
}
