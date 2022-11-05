use actix_cors::Cors;
use actix_web::http;
use lazy_static::lazy_static;

lazy_static! {
    static ref FRONTEND_ORIGINS: Vec<String> = std::env::vars()
        .into_iter()
        .filter(|v| v.0.starts_with("FRONTEND_ORIGIN_"))
        .map(|v| v.1)
        .collect();
}

pub fn cors() -> Cors {
    Cors::default()
        .allowed_origin_fn(|origin, _req_head| {
            FRONTEND_ORIGINS.contains(&origin.to_str().unwrap().into())
        })
        .allowed_methods(vec!["GET", "POST", "PATCH", "DELETE"])
        .allowed_headers(vec![
            http::header::AUTHORIZATION,
            http::header::ACCEPT,
            http::header::CONTENT_TYPE,
        ])
        .max_age(3_600)
}
