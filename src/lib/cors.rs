use crate::lib::config::CONFIG;

use actix_cors::Cors;
use actix_web::http;

pub fn cors() -> Cors {
    Cors::default()
        .allowed_origin_fn(|origin, _req_head| {
            println!("origin: {:?}", &origin.to_str().unwrap().to_string());
            println!("frontend_origins: {:?}", CONFIG.frontend_origins);
            println!(
                "allowed: {:?}",
                CONFIG
                    .frontend_origins
                    .contains(&origin.to_str().unwrap().into())
            );
            CONFIG
                .frontend_origins
                .contains(&origin.to_str().unwrap().into())
        })
        .allowed_methods(vec!["GET", "POST", "PATCH", "DELETE"])
        .allowed_headers(vec![
            http::header::AUTHORIZATION,
            http::header::ACCEPT,
            http::header::CONTENT_TYPE,
        ])
        .max_age(3_600)
}
