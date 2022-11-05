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
    pub domain: String,
}

impl Config {
    fn new() -> Result<Self, config::ConfigError> {
        let environment = config::Environment::default().try_parsing(true);
        let config = config::Config::builder()
            .set_default("host", "127.0.0.1")?
            .set_default("port", "9099")?
            .set_default("access_token_secret", "secret")?
            .set_default("refresh_token_secret", "secret")?
            .set_default("domain", "127.0.0.1:5173")?
            .add_source(environment)
            .build()?;
        config.try_deserialize()
    }
}
