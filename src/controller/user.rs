use super::lib::jwt_extractor::AccessTokenDecoded;
use crate::controller::lib::jwt_extractor::{BearerToken, RefreshTokenDecoded};
use crate::lib::my_error::MyError;
use crate::lib::{
    jwt::{Auth, Tokens},
    my_error::MyResult,
};
use crate::model::user::User;

use actix_web::{
    delete, get, patch, post,
    web::{Data, Json, ServiceConfig},
};
use serde::Deserialize;
use sqlx::PgPool;

pub fn init(cfg: &mut ServiceConfig) {
    cfg.service(index);
    cfg.service(create);
    cfg.service(destroy);
    cfg.service(create_session);
    cfg.service(update_session);
    cfg.service(destroy_session);
}

#[get("/user")]
async fn index(token: AccessTokenDecoded) -> Json<Auth> {
    Json(token.into_auth())
}

#[derive(Debug, Deserialize)]
struct Create {
    name: String,
    password: String,
}

#[post("/user")]
async fn create(pool: Data<PgPool>, form: Json<Create>) -> MyResult<Json<Tokens>> {
    let mut user = User::create(form.name.clone(), form.password.clone())?;
    let tokens = user.issue_tokens();
    user.store(&**pool).await?;
    Ok(Json(tokens))
}

#[delete("/user")]
async fn destroy(
    pool: Data<PgPool>,
    access_token_decoded: AccessTokenDecoded,
) -> MyResult<Json<()>> {
    let auth = access_token_decoded.into_auth();
    User::delete_by_id(&**pool, auth.uid).await?;
    Ok(Json(()))
}

#[derive(Debug, Deserialize)]
struct CreateSessions {
    name: String,
    password: String,
}

#[post("/user/session")]
async fn create_session(pool: Data<PgPool>, form: Json<CreateSessions>) -> MyResult<Json<Tokens>> {
    let mut user = User::find_by_name(&**pool, form.name.clone())
        .await?
        .ok_or_else(|| MyError::new_unauthorized())?;
    user.verify_password(form.password.clone())?;
    let tokens = user.issue_tokens();
    user.store(&**pool).await?;
    Ok(Json(tokens))
}

#[patch("/user/session")]
async fn update_session(
    pool: Data<PgPool>,
    token: BearerToken,
    refresh_token_decoded: RefreshTokenDecoded,
) -> MyResult<Json<Tokens>> {
    let auth = refresh_token_decoded.into_auth();
    let mut user = User::find(&**pool, auth.uid).await?;
    user.verify_refresh_token(token.into())?;
    let tokens = user.issue_tokens();
    user.store(&**pool).await?;
    Ok(Json(tokens))
}

#[delete("/user/session")]
async fn destroy_session(
    pool: Data<PgPool>,
    access_token_decoded: AccessTokenDecoded,
) -> MyResult<Json<()>> {
    let auth = access_token_decoded.into_auth();
    let mut user = User::find(&**pool, auth.uid).await?;
    user.revoke_tokens();
    user.store(&**pool).await?;
    Ok(Json(()))
}
