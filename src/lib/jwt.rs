use crate::lib::config::CONFIG;

use chrono::{Duration, Utc};
use derive_new::new;
use jsonwebtoken::{
    decode, encode, errors::Error as JwtError, DecodingKey, EncodingKey, Header, Validation,
};
use serde::{Deserialize, Serialize};

const ACCESS_EXP_MINUTES: i64 = 30;
const REFRESH_EXP_WEEKS: i64 = 2;

#[derive(new, Debug, Serialize)]
pub struct Auth {
    pub id: String,
    pub name: String,
}

#[derive(new, Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: i64,
    pub id: String,
    pub name: String,
}

#[derive(new, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Tokens {
    pub access_token: String,
    pub refresh_token: String,
}

pub fn generate_tokens(auth: Auth) -> Tokens {
    let access_exp = (Utc::now() + Duration::minutes(ACCESS_EXP_MINUTES)).timestamp();
    let access_claims = Claims::new(
        auth.id.clone(),
        access_exp,
        auth.id.clone(),
        auth.name.clone(),
    );
    let access_token = encode(
        &Header::default(),
        &access_claims,
        &EncodingKey::from_secret(CONFIG.access_token_secret.as_bytes()),
    )
    .unwrap();

    let refresh_exp = (Utc::now() + Duration::weeks(REFRESH_EXP_WEEKS)).timestamp();
    let refresh_claims = Claims::new(
        auth.id.clone(),
        refresh_exp,
        auth.id.clone(),
        auth.name.clone(),
    );
    let refresh_token = encode(
        &Header::default(),
        &refresh_claims,
        &EncodingKey::from_secret(CONFIG.refresh_token_secret.as_bytes()),
    )
    .unwrap();

    Tokens::new(access_token, refresh_token)
}

pub fn decode_access_token(token: &str) -> Result<Claims, JwtError> {
    decode(
        token,
        &DecodingKey::from_secret(CONFIG.access_token_secret.as_bytes()),
        &Validation::default(),
    )
    .map(|v| v.claims)
}

pub fn decode_refresh_token(token: &str) -> Result<Claims, JwtError> {
    decode(
        token,
        &DecodingKey::from_secret(CONFIG.refresh_token_secret.as_bytes()),
        &Validation::default(),
    )
    .map(|v| v.claims)
}
