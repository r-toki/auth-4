mod controller;
mod lib;
mod model;

use crate::lib::{config::CONFIG, cors::cors};

use actix_web::{get, middleware::Logger, web, App, HttpServer, Responder};
use sqlx::PgPool;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    if cfg!(debug_assertions) {
        dotenv::dotenv().ok();
    }

    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    let pool = PgPool::connect(&CONFIG.database_url).await.unwrap();

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .wrap(cors())
            .wrap(Logger::default())
            .configure(controller::init)
            .service(index)
    })
    .bind(format!("{}:{}", CONFIG.host, CONFIG.port))?
    .run()
    .await
}

#[get("/")]
async fn index() -> impl Responder {
    format!("HELLO FROM AUTH!")
}
