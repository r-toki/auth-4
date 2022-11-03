use super::lib::jwt_extractor::AccessTokenDecoded;
use crate::controller::lib::jwt_extractor::{BearerToken, RefreshTokenDecoded};
use crate::lib::{
    errors,
    jwt::{Auth, Tokens},
};
use crate::model::user::{Error as UserError, User};

use actix_web::{
    delete, get, patch, post,
    web::{Data, Json, ServiceConfig},
};
use serde::Deserialize;
use sqlx::MySqlPool;

pub fn init(cfg: &mut ServiceConfig) {
    cfg.service(index);
    cfg.service(create);
    cfg.service(destroy);
    cfg.service(create_sessions);
    cfg.service(update_sessions);
    cfg.service(destroy_sessions);
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
async fn create(pool: Data<MySqlPool>, form: Json<Create>) -> Result<Json<Tokens>, errors::Error> {
    let mut user = User::create(form.name.clone(), form.password.clone())?;
    let tokens = user.issue_tokens();
    user.store(&**pool).await?;
    Ok(Json(tokens))
}

#[delete("/user")]
async fn destroy(
    pool: Data<MySqlPool>,
    access_token_decoded: AccessTokenDecoded,
) -> Result<Json<()>, errors::Error> {
    let auth = access_token_decoded.into_auth();
    User::delete_by_id(&**pool, auth.uid).await?;
    Ok(Json(()))
}

#[derive(Debug, Deserialize)]
struct CreateSessions {
    name: String,
    password: String,
}

#[post("/user/sessions")]
async fn create_sessions(
    pool: Data<MySqlPool>,
    form: Json<CreateSessions>,
) -> Result<Json<Tokens>, errors::Error> {
    let mut user = User::find_by_name(&**pool, form.name.clone())
        .await?
        .ok_or_else(|| UserError::NameAndPasswordUnMatch)?;
    user.verify_password(form.password.clone())?;
    let tokens = user.issue_tokens();
    user.store(&**pool).await?;
    Ok(Json(tokens))
}

#[patch("/user/sessions")]
async fn update_sessions(
    pool: Data<MySqlPool>,
    token: BearerToken,
    refresh_token_decoded: RefreshTokenDecoded,
) -> Result<Json<Tokens>, errors::Error> {
    let auth = refresh_token_decoded.into_auth();
    let mut user = User::find(&**pool, auth.uid).await?;
    user.verify_refresh_token(token.into())?;
    let tokens = user.issue_tokens();
    user.store(&**pool).await?;
    Ok(Json(tokens))
}

#[delete("/user/sessions")]
async fn destroy_sessions(
    pool: Data<MySqlPool>,
    access_token_decoded: AccessTokenDecoded,
) -> Result<Json<()>, errors::Error> {
    let auth = access_token_decoded.into_auth();
    let mut user = User::find(&**pool, auth.uid).await?;
    user.revoke_tokens();
    user.store(&**pool).await?;
    Ok(Json(()))
}
