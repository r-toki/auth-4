use crate::model::user::Error as UserError;

use actix_web::{HttpResponse, ResponseError};
use jsonwebtoken::errors::Error as JwtError;
use serde_json::{json, Map as JsonMap, Value as JsonValue};
use sqlx::Error as SqlxError;
use validator::ValidationErrors;

#[derive(Debug, thiserror::Error)]
pub enum Error {
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

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        match self {
            Error::Unauthorized(message) => HttpResponse::Unauthorized().json(message),
            Error::Forbidden(message) => HttpResponse::Forbidden().json(message),
            Error::NotFound(message) => HttpResponse::NotFound().json(message),
            Error::UnprocessableEntity(message) => {
                HttpResponse::UnprocessableEntity().json(message)
            }
            Error::InternalServerError => {
                HttpResponse::InternalServerError().json(json!({"error": "Internal Server Error"}))
            }
        }
    }
}

impl From<JwtError> for Error {
    fn from(_: JwtError) -> Self {
        Error::Unauthorized(json!({"error": "An issue was found with the token provided"}))
    }
}

impl From<ValidationErrors> for Error {
    fn from(errors: ValidationErrors) -> Self {
        let mut err_map = JsonMap::new();

        for (field, field_errors) in errors.field_errors().iter() {
            let errors: Vec<JsonValue> = field_errors
                .iter()
                .map(|error| json!(error.message))
                .collect();
            err_map.insert(field.to_string(), json!(errors));
        }

        Error::UnprocessableEntity(json!({ "error": err_map }))
    }
}

impl From<SqlxError> for Error {
    fn from(error: SqlxError) -> Self {
        match error {
            SqlxError::RowNotFound => Error::NotFound(json!({"error": "Entity not found"})),
            _ => Error::InternalServerError,
        }
    }
}

impl From<UserError> for Error {
    fn from(error: UserError) -> Self {
        match error {
            UserError::NameAndPasswordUnMatch => {
                Error::Unauthorized(json!({"error": "Name and password do not match"}))
            }
            UserError::RefreshTokenUnMatch => {
                Error::Unauthorized(json!({"error": "Refresh token do not match"}))
            }
        }
    }
}
