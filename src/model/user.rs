use super::lib::{get_current_date_time, get_new_id};
use crate::lib::{
    errors,
    jwt::{generate_tokens, Auth, Tokens},
    password_hashing::{hash, verify},
};

use chrono::{DateTime, Utc};
use derive_new::new;
use lazy_static::lazy_static;
use regex::Regex;
use serde_json::json;
use sqlx::{error, query, query_as, MySqlExecutor};
use validator::Validate;

lazy_static! {
    static ref RE_NAME: Regex = Regex::new(r"[A-Za-z\d#$@!%&*?]{3,15}").unwrap();
    static ref RE_PASSWORD: Regex = Regex::new(r"[A-Za-z\d#$@!%&*?]{8,30}").unwrap();
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("User::Error::NameAndPasswordUnMatch")]
    NameAndPasswordUnMatch,

    #[error("User::Error::RefreshTokenUnMatch")]
    RefreshTokenUnMatch,
}

#[derive(new, Debug, Validate)]
pub struct User {
    pub id: String,
    #[validate(regex(
        path = "RE_NAME",
        message = "must be 3-15 characters in alphabet, numbers or symbols"
    ))]
    pub name: String,
    pub password_hash: String,
    pub refresh_token_hash: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl User {
    pub fn create(name: String, password: String) -> Result<Self, errors::Error> {
        if !RE_PASSWORD.is_match(&password) {
            return Err(errors::Error::UnprocessableEntity(
                json!({"errors": {"password": ["must be 8-30 characters in alphabet, numbers or symbols"]}}),
            ));
        };

        let id = get_new_id();
        let now = get_current_date_time();

        let user = User::new(id, name, hash(&password), None, now, now);
        user.validate()?;

        Ok(user)
    }

    pub fn issue_tokens(&mut self) -> Tokens {
        let tokens = generate_tokens(Auth::new(self.id.clone()));

        self.refresh_token_hash = Some(hash(&tokens.refresh_token));
        self.updated_at = get_current_date_time();

        tokens
    }

    pub fn revoke_tokens(&mut self) {
        self.refresh_token_hash = None;
        self.updated_at = get_current_date_time();
    }

    pub fn verify_password(&self, password: String) -> Result<(), errors::Error> {
        verify(&password, &self.password_hash)
            .map_err(|_| Error::NameAndPasswordUnMatch)
            .map_err(Into::into)
    }

    pub fn verify_refresh_token(&self, refresh_token: String) -> Result<(), errors::Error> {
        let refresh_token_hash = self
            .refresh_token_hash
            .as_ref()
            .ok_or_else(|| Error::RefreshTokenUnMatch)?;

        verify(&refresh_token, refresh_token_hash)
            .map_err(|_| Error::RefreshTokenUnMatch)
            .map_err(Into::into)
    }

    pub async fn find(executor: impl MySqlExecutor<'_>, id: String) -> Result<User, errors::Error> {
        query_as!(
            User,
            r#"
select * from users
where id = ?
            "#,
            id
        )
        .fetch_one(executor)
        .await
        .map_err(Into::into)
    }

    pub async fn find_by_name(
        executor: impl MySqlExecutor<'_>,
        name: String,
    ) -> Result<Option<User>, errors::Error> {
        query_as!(
            User,
            r#"
select * from users
where name = ?
            "#,
            name
        )
        .fetch_optional(executor)
        .await
        .map_err(Into::into)
    }

    pub async fn store(&self, executor: impl MySqlExecutor<'_>) -> Result<(), errors::Error> {
        query!(
            r#"
insert into users (id, name, password_hash, refresh_token_hash, created_at, updated_at)
values (?, ?, ?, ?, ?, ?)
on duplicate key
update
name = values(name),
password_hash = values(password_hash), refresh_token_hash = values(refresh_token_hash),
created_at = values(created_at), updated_at = values(updated_at)
            "#,
            self.id,
            self.name,
            self.password_hash,
            self.refresh_token_hash,
            self.created_at,
            self.updated_at
        )
        .execute(executor)
        .await
        .map(|_| ())
        .map_err(Into::into)
    }

    pub async fn delete(&self, executor: impl MySqlExecutor<'_>) -> Result<(), errors::Error> {
        query!(
            r#"
delete from users
where id = ?
            "#,
            self.id
        )
        .execute(executor)
        .await
        .map(|_| ())
        .map_err(Into::into)
    }

    pub async fn delete_by_id(
        executor: impl MySqlExecutor<'_>,
        id: String,
    ) -> Result<(), error::Error> {
        query!(
            r#"
delete from users
where id = ?
            "#,
            id
        )
        .execute(executor)
        .await
        .map(|_| ())
        .map_err(Into::into)
    }
}