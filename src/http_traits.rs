use crate::cookie_functions::empty_unix_epoch_cookie;
use actix_web::body::MessageBody;
use actix_web::{cookie::Cookie, http, HttpResponse};

pub trait CustomHttpResponse {
    /// A shortcut for returning a HttpResponse like
    ///
    /// ```
    /// use actix_web::{cookie::Cookie, http, HttpResponse};
    /// fn cumbersome_example(cookie: Cookie) -> HttpResponse{
    ///   return HttpResponse::Ok()
    ///   .content_type("application/text")
    ///   .append_header(("Access-Control-Allow-Origin", "*"))
    ///   .append_header((http::header::SET_COOKIE, cookie.to_string()))
    ///   .body("OK: this is fine!");
    /// }
    /// ```
    fn ok_text_response_with_cookie<B>(body: B, cookie: Cookie) -> actix_web::HttpResponse
    where
        B: MessageBody + 'static;
    /// A shortcut for returning a HttpResponse like
    ///
    /// ```
    /// use actix_web::HttpResponse;
    /// fn cumbersome_example() -> HttpResponse{
    ///   return HttpResponse::Ok()
    ///   .content_type("application/text")
    ///   .append_header(("Access-Control-Allow-Origin", "*"))
    ///   .body("OK: this is fine!");
    /// }
    /// ```
    fn ok_text_response_with_empty_unix_epoch_cookie<B>(body: B) -> actix_web::HttpResponse
    where
        B: MessageBody + 'static;
    /// A shortcut for returning a HttpResponse like
    ///
    /// ```
    /// use actix_web::{cookie::Cookie, cookie::time::OffsetDateTime, http, HttpResponse};
    /// use lmtyas::cookie_functions::{COOKIE_NAME, COOKIE_PATH, empty_unix_epoch_cookie};
    /// fn cumbersome_example() -> HttpResponse{
    ///     #[cfg(feature = "ldap-auth")]
    ///     let same_site = actix_web::cookie::SameSite::Strict;
    ///     #[cfg(feature = "oidc-auth-ldap")]
    ///     let same_site = actix_web::cookie::SameSite::Lax;
    ///     let empty_unix_epoch_cookie = Cookie::build(COOKIE_NAME, "".to_string())
    ///         .secure(true)
    ///         .http_only(true)
    ///         .path(COOKIE_PATH)
    ///         .expires(OffsetDateTime::UNIX_EPOCH)
    ///         .same_site(same_site)
    ///         .finish();
    ///         HttpResponse::Ok()
    ///         .content_type("application/text")
    ///         .append_header(("Access-Control-Allow-Origin", "*"))
    ///         .append_header((
    ///         http::header::SET_COOKIE,
    ///         empty_unix_epoch_cookie.to_string(),
    ///         ))
    ///         .body("OK: this is fine!")
    /// }
    /// ```
    fn ok_text_response<B>(body: B) -> actix_web::HttpResponse
    where
        B: MessageBody + 'static;
    /// A shortcut for returning a HttpResponse like
    ///
    /// ```
    /// use actix_web::HttpResponse;
    /// fn cumbersome_example() -> HttpResponse{
    ///   return HttpResponse::Ok()
    ///   .content_type("application/json")
    ///   .append_header(("Access-Control-Allow-Origin", "*"))
    ///   .body("{\"this\": \"that\"}");
    /// }
    /// ```
    fn ok_json_response<B>(body: B) -> actix_web::HttpResponse
    where
        B: MessageBody + 'static;
    /// A shortcut for returning a HttpResponse like
    ///
    /// ```
    /// use actix_web::HttpResponse;
    /// fn cumbersome_example() -> HttpResponse{
    ///   return HttpResponse::BadRequest()
    ///   .content_type("application/text")
    ///   .append_header(("Access-Control-Allow-Origin", "*"))
    ///   .body("ERROR: this is bad!");
    /// }
    /// ```
    fn err_text_response<B>(body: B) -> actix_web::HttpResponse
    where
        B: MessageBody + 'static;
}

impl CustomHttpResponse for HttpResponse {
    fn ok_text_response<B>(body: B) -> actix_web::HttpResponse
    where
        B: MessageBody + 'static,
    {
        return HttpResponse::Ok()
            .content_type("application/text; charset=UTF-8")
            .append_header(("X-Content-Type-Options", "nosniff"))
            .append_header(("Access-Control-Allow-Origin", "*"))
            .body(body);
    }

    fn ok_text_response_with_cookie<B>(body: B, cookie: Cookie) -> actix_web::HttpResponse
    where
        B: MessageBody + 'static,
    {
        return HttpResponse::Ok()
            .content_type("application/text; charset=UTF-8")
            .append_header(("X-Content-Type-Options", "nosniff"))
            .append_header(("Access-Control-Allow-Origin", "*"))
            .append_header((http::header::SET_COOKIE, cookie.to_string()))
            .body(body);
    }

    fn ok_text_response_with_empty_unix_epoch_cookie<B>(body: B) -> actix_web::HttpResponse
    where
        B: MessageBody + 'static,
    {
        return HttpResponse::Ok()
            .content_type("application/text; charset=UTF-8")
            .append_header(("X-Content-Type-Options", "nosniff"))
            .append_header(("Access-Control-Allow-Origin", "*"))
            .append_header((
                http::header::SET_COOKIE,
                empty_unix_epoch_cookie().to_string(),
            ))
            .body(body);
    }

    fn ok_json_response<B>(body: B) -> actix_web::HttpResponse
    where
        B: MessageBody + 'static,
    {
        return HttpResponse::Ok()
            .content_type("application/json; charset=UTF-8")
            .append_header(("X-Content-Type-Options", "nosniff"))
            .append_header(("Access-Control-Allow-Origin", "*"))
            .body(body);
    }

    fn err_text_response<B>(body: B) -> actix_web::HttpResponse
    where
        B: MessageBody + 'static,
    {
        return HttpResponse::BadRequest()
            .content_type("application/text; charset=UTF-8")
            .append_header(("X-Content-Type-Options", "nosniff"))
            .append_header(("Access-Control-Allow-Origin", "*"))
            .body(body);
    }
}
