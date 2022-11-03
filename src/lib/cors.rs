use crate::lib::config::CONFIG;

use actix_cors::Cors;
use actix_web::http;

pub fn cors() -> Cors {
    Cors::default()
        .allowed_origin_fn(|origin, _req_head| {
            CONFIG.allowed_domain_suffix.as_bytes() == b"127.0.0.1"
                || origin
                    .as_bytes()
                    .ends_with(CONFIG.allowed_domain_suffix.as_bytes())
        })
        .allowed_methods(vec!["GET", "POST", "PATCH", "DELETE"])
        .allowed_headers(vec![
            http::header::AUTHORIZATION,
            http::header::ACCEPT,
            http::header::CONTENT_TYPE,
        ])
        .max_age(3_600)
}
