mod lib;
mod user;

use actix_web::web::ServiceConfig;

pub fn init(cfg: &mut ServiceConfig) {
    user::init(cfg);
}
