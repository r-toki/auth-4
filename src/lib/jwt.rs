use crate::lib::config::CONFIG;

use chrono::{Duration, Utc};
use derive_new::new;
use jsonwebtoken::{
    decode, encode, errors::Error as JwtError, DecodingKey, EncodingKey, Header, Validation,
};
use serde::{Deserialize, Serialize};

#[derive(new, Debug)]
pub struct Auth {
    pub user_id: String,
}

#[derive(new, Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: i64,
    pub user_id: String,
}

#[derive(new, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Tokens {
    pub access_token: String,
    pub refresh_token: String,
}

pub fn generate_tokens(auth: Auth) -> Tokens {
    let access_exp = (Utc::now() + Duration::minutes(30)).timestamp();
    let access_claims = Claims::new(auth.user_id.clone(), access_exp, auth.user_id.clone());
    let access_token = encode(
        &Header::default(),
        &access_claims,
        &EncodingKey::from_secret(CONFIG.access_token_secret.as_bytes()),
    )
    .unwrap();

    let refresh_exp = (Utc::now() + Duration::weeks(2)).timestamp();
    let refresh_claims = Claims::new(auth.user_id.clone(), refresh_exp, auth.user_id.clone());
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
