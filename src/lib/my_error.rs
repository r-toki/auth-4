use actix_web::{HttpResponse as Response, ResponseError};
use derive_new::new;
use serde_json::{json, Map as JsonMap, Value as JsonValue};
use sqlx::Error as SqlxError;
use validator::ValidationErrors;

pub type MyResult<T> = Result<T, MyError>;

#[derive(new, Debug, thiserror::Error)]
pub enum MyError {
    #[error("400 Bad Request: {0}")]
    BadRequest(#[new(default)] JsonValue),
    #[error("401 Unauthorized: {0}")]
    Unauthorized(#[new(default)] JsonValue),
    #[error("403 Forbidden: {0}")]
    Forbidden(#[new(default)] JsonValue),
    #[error("404 Not Found: {0}")]
    NotFound(#[new(default)] JsonValue),
    #[error("409 Conflict: {0}")]
    Conflict(#[new(default)] JsonValue),
    #[error("422 Unprocessable Entity: {0}")]
    UnprocessableEntity(#[new(default)] JsonValue),
    #[error("500 Internal Server Error: {0}")]
    InternalServerError(#[new(default)] JsonValue),
}

impl ResponseError for MyError {
    fn error_response(&self) -> Response {
        let to = |v: &JsonValue| json!({ "error": v });
        match self {
            MyError::BadRequest(v) => Response::BadRequest().json(to(v)),
            MyError::Unauthorized(v) => Response::Unauthorized().json(to(v)),
            MyError::Forbidden(v) => Response::Forbidden().json(to(v)),
            MyError::NotFound(v) => Response::NotFound().json(to(v)),
            MyError::Conflict(v) => Response::Conflict().json(to(v)),
            MyError::UnprocessableEntity(v) => Response::UnprocessableEntity().json(to(v)),
            MyError::InternalServerError(v) => Response::InternalServerError().json(to(v)),
        }
    }
}

impl From<ValidationErrors> for MyError {
    fn from(errors: ValidationErrors) -> Self {
        let mut err_map = JsonMap::new();
        for (field, field_errors) in errors.field_errors().iter() {
            let errors: Vec<JsonValue> = field_errors
                .iter()
                .map(|error| json!(error.message))
                .collect();
            err_map.insert(field.to_string(), json!(errors));
        }
        MyError::UnprocessableEntity(err_map.into())
    }
}

impl From<SqlxError> for MyError {
    fn from(error: SqlxError) -> Self {
        match error {
            _ => MyError::new_internal_server_error(),
        }
    }
}
