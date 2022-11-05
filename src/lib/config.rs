use lazy_static::lazy_static;
use serde::Deserialize;

lazy_static! {
    pub static ref CONFIG: Config = Config::new().unwrap();
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
    fn new() -> Result<Self, config::ConfigError> {
        let frontend_origins: Vec<String> = std::env::vars()
            .into_iter()
            .filter(|v| v.0.starts_with("FRONTEND_ORIGIN_"))
            .map(|v| v.1)
            .collect();

        let environment = config::Environment::default().try_parsing(true);
        let config = config::Config::builder()
            .set_default("host", "127.0.0.1")?
            .set_default("port", "9099")?
            .set_default("access_token_secret", "secret")?
            .set_default("refresh_token_secret", "secret")?
            .set_default("frontend_origins", frontend_origins)?
            .add_source(environment)
            .build()?;
        config.try_deserialize()
    }
}
