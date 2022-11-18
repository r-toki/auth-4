use lazy_static::lazy_static;
use serde::Deserialize;

lazy_static! {
    pub static ref CONFIG: Config = Config::new();
}

#[derive(Deserialize)]
pub struct Config {
    pub host: String,
    pub port: String,
    pub database_url: String,
    pub access_token_secret: String,
    pub refresh_token_secret: String,
    pub frontend_origins: Vec<String>,
}

impl Config {
    fn new() -> Self {
        let host = std::env::var("HOST").unwrap_or("127.0.0.1".into());
        let port = std::env::var("PORT").unwrap_or("9099".into());
        let database_url = std::env::var("DATABASE_URL").unwrap();
        let access_token_secret = std::env::var("ACCESS_TOKEN_SECRET").unwrap_or("secret".into());
        let refresh_token_secret = std::env::var("REFRESH_TOKEN_SECRET").unwrap_or("secret".into());
        let frontend_origins: Vec<String> = std::env::vars()
            .into_iter()
            .filter(|v| v.0.starts_with("FRONTEND_ORIGIN_"))
            .map(|v| v.1)
            .collect();

        Self {
            host,
            port,
            database_url,
            access_token_secret,
            refresh_token_secret,
            frontend_origins,
        }
    }
}
