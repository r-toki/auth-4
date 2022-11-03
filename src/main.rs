mod lib;
mod model;

use crate::lib::{config::CONFIG, cors::cors};

use actix_web::{get, middleware::Logger, web, App, HttpServer, Responder};
use dotenv::dotenv;
use sqlx::MySqlPool;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    let pool = MySqlPool::connect(&CONFIG.database_url).await.unwrap();

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .wrap(Logger::default())
            .wrap(cors())
            // .configure(controller::init)
            .service(index)
    })
    .bind(format!("{}:{}", CONFIG.host, CONFIG.port))?
    .run()
    .await
}

#[get("/")]
async fn index() -> impl Responder {
    format!("HELLO WORLD!")
}
