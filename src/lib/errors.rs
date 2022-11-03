use crate::model::user::Error as UserError;

use actix_web::{HttpResponse, ResponseError};
use jsonwebtoken::errors::Error as JwtError;
use serde_json::{json, Map as JsonMap, Value as JsonValue};
use sqlx::Error as SqlxError;
use validator::ValidationErrors;

pub type MyResult<T> = Result<T, MyError>;

#[derive(Debug, thiserror::Error)]
pub enum MyError {
    // 401
    #[error("Unauthorized: {0}")]
    Unauthorized(JsonValue),

    // 403
    #[error("Forbidden: {0}")]
    Forbidden(JsonValue),

    // 404
    #[error("Not Found: {0}")]
    NotFound(JsonValue),

    // 422
    #[error("Unprocessable Entity: {0}")]
    UnprocessableEntity(JsonValue),

    // 500
    #[error("Internal Server Error")]
    InternalServerError,
}

impl ResponseError for MyError {
    fn error_response(&self) -> HttpResponse {
        match self {
            MyError::Unauthorized(message) => HttpResponse::Unauthorized().json(message),
            MyError::Forbidden(message) => HttpResponse::Forbidden().json(message),
            MyError::NotFound(message) => HttpResponse::NotFound().json(message),
            MyError::UnprocessableEntity(message) => {
                HttpResponse::UnprocessableEntity().json(message)
            }
            MyError::InternalServerError => {
                HttpResponse::InternalServerError().json(json!({"error": "Internal Server Error"}))
            }
        }
    }
}

impl From<JwtError> for MyError {
    fn from(_: JwtError) -> Self {
        MyError::Unauthorized(json!({"error": "An issue was found with the token provided"}))
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

        MyError::UnprocessableEntity(json!({ "error": err_map }))
    }
}

impl From<SqlxError> for MyError {
    fn from(error: SqlxError) -> Self {
        match error {
            SqlxError::RowNotFound => MyError::NotFound(json!({"error": "Entity not found"})),
            _ => MyError::InternalServerError,
        }
    }
}

impl From<UserError> for MyError {
    fn from(error: UserError) -> Self {
        match error {
            UserError::NameAndPasswordUnMatch => {
                MyError::Unauthorized(json!({"error": "Name and password do not match"}))
            }
            UserError::RefreshTokenUnMatch => {
                MyError::Unauthorized(json!({"error": "Refresh token do not match"}))
            }
        }
    }
}
