use super::lib::{get_current_date_time, get_new_id};
use crate::lib::{
    jwt::{generate_tokens, Auth, Tokens},
    my_error::{MyError, MyResult},
    password_hashing::{hash, verify},
};

use chrono::{DateTime, Utc};
use derive_new::new;
use lazy_static::lazy_static;
use regex::Regex;
use serde_json::json;
use sqlx::{query, query_as, PgPool};
use validator::Validate;

lazy_static! {
    static ref RE_NAME: Regex = Regex::new(r"[A-Za-z\d#$@!%&*?]{3,15}").unwrap();
    static ref RE_PASSWORD: Regex = Regex::new(r"[A-Za-z\d#$@!%&*?]{8,30}").unwrap();
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
    pub fn create(name: String, password: String) -> MyResult<Self> {
        if !RE_PASSWORD.is_match(&password) {
            return Err(MyError::UnprocessableEntity(
                json!({"password": ["must be 8-30 characters in alphabet, numbers or symbols"]}),
            ));
        };

        let id = get_new_id();
        let now = get_current_date_time();

        let user = User::new(id, name, hash(&password), None, now, now);
        user.validate()?;

        Ok(user)
    }

    pub fn issue_tokens(&mut self) -> Tokens {
        let tokens = generate_tokens(Auth::new(self.id.clone(), self.name.clone()));

        self.refresh_token_hash = Some(hash(&tokens.refresh_token));
        self.updated_at = get_current_date_time();

        tokens
    }

    pub fn revoke_tokens(&mut self) {
        self.refresh_token_hash = None;
        self.updated_at = get_current_date_time();
    }

    pub fn verify_password(&self, password: String) -> MyResult<()> {
        verify(&password, &self.password_hash)
            .map_err(|_| MyError::Unauthorized("Name and password do not match".into()))
            .map_err(Into::into)
    }

    pub fn verify_refresh_token(&self, refresh_token: String) -> MyResult<()> {
        let err = || MyError::Unauthorized("Refresh token do not match".into());
        let refresh_token_hash = self.refresh_token_hash.as_ref().ok_or_else(|| err())?;
        verify(&refresh_token, refresh_token_hash)
            .map_err(|_| err())
            .map_err(Into::into)
    }

    pub async fn find(pool: &PgPool, id: String) -> MyResult<User> {
        query_as!(
            User,
            r#"
select * from users
where id = $1
            "#,
            id
        )
        .fetch_one(pool)
        .await
        .map_err(Into::into)
    }

    pub async fn find_by_name(pool: &PgPool, name: String) -> MyResult<Option<User>> {
        query_as!(
            User,
            r#"
select * from users
where name = $1
            "#,
            name
        )
        .fetch_optional(pool)
        .await
        .map_err(Into::into)
    }

    pub async fn delete_by_id(pool: &PgPool, id: String) -> MyResult<()> {
        query!(
            r#"
delete from users
where id = $1
            "#,
            id
        )
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(Into::into)
    }

    pub async fn store(&self, pool: &PgPool) -> MyResult<()> {
        query!(
            r#"
insert into users (id, name, password_hash, refresh_token_hash, created_at, updated_at)
values ($1, $2, $3, $4, $5, $6)
on conflict (id)
do update
set name = $2, password_hash = $3, refresh_token_hash = $4, created_at = $5, updated_at = $6
            "#,
            self.id,
            self.name,
            self.password_hash,
            self.refresh_token_hash,
            self.created_at,
            self.updated_at
        )
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(Into::into)
    }
}
