use actix_web::{HttpResponse as Response, ResponseError};
use derive_new::new;
use serde_json::{json, Map as JsonMap, Value as JsonValue};
use sqlx::Error as SqlxError;
use validator::ValidationErrors;

pub type MyResult<T> = Result<T, MyError>;

#[derive(new, Debug, thiserror::Error)]
pub enum MyError {
    #[error("Bad Request: {0}")]
    BadRequest(#[new(default)] JsonValue),

    #[error("Unauthorized: {0}")]
    Unauthorized(#[new(default)] JsonValue),

    #[error("Forbidden: {0}")]
    Forbidden(#[new(default)] JsonValue),

    #[error("Not Found: {0}")]
    NotFound(#[new(default)] JsonValue),

    #[error("Conflict: {0}")]
    Conflict(#[new(default)] JsonValue),

    #[error("Unprocessable Entity: {0}")]
    UnprocessableEntity(#[new(default)] JsonValue),

    #[error("Internal Server Error: {0}")]
    InternalServerError(#[new(default)] JsonValue),
}

impl ResponseError for MyError {
    fn error_response(&self) -> Response {
        match self {
            MyError::BadRequest(v) => Response::BadRequest().json(nest_error(v)),
            MyError::Unauthorized(v) => Response::Unauthorized().json(nest_error(v)),
            MyError::Forbidden(v) => Response::Forbidden().json(nest_error(v)),
            MyError::NotFound(v) => Response::NotFound().json(nest_error(v)),
            MyError::Conflict(v) => Response::Conflict().json(nest_error(v)),
            MyError::UnprocessableEntity(v) => Response::UnprocessableEntity().json(nest_error(v)),
            MyError::InternalServerError(v) => Response::InternalServerError().json(nest_error(v)),
        }
    }
}

fn nest_error(v: &JsonValue) -> JsonValue {
    json!({ "error": v })
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
