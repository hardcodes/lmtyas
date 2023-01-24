use actix_web::body::MessageBody;
use actix_web::{cookie::Cookie, http, HttpResponse};

pub trait CustomHttpResponse {
    /// A shortcut for returning a HttpResponse like
    ///
    /// ```ignore
    /// return HttpResponse::Ok()
    /// .content_type("application/text")
    /// .header("Access-Control-Allow-Origin", "*")
    /// .body("OK: this is fine!");
    /// ```
    ///
    /// # Arguments
    ///
    /// - `body': a `actix_web::body::MessageBody` with the text content to return
    ///
    /// # Returns
    ///
    /// - `actix_web::HttpResponse`
    fn ok_text_response_with_cookie<B>(body: B, cookie: Cookie) -> actix_web::HttpResponse
    where
        B: MessageBody + 'static;
    /// A shortcut for returning a HttpResponse like
    ///
    /// ```ignore
    /// return HttpResponse::Ok()
    /// .content_type("application/text")
    /// .append_header("Access-Control-Allow-Origin", "*")
    /// .append_header((http::header::SET_COOKIE, cookie.to_string()))
    /// .body("OK: this is fine!");
    /// ```
    ///
    /// # Arguments
    ///
    /// - `body':   a `actix_web::body::MessageBody` with the text content to return
    /// - `cookie`: cookie to set in the response
    ///
    /// # Returns
    ///
    /// - `actix_web::HttpResponse`
    fn ok_text_response<B>(body: B) -> actix_web::HttpResponse
    where
        B: MessageBody + 'static;
    /// A shortcut for returning a HttpResponse like
    ///
    /// ```ignore
    /// return HttpResponse::Ok()
    /// .content_type("application/json")
    /// .append_header("Access-Control-Allow-Origin", "*")
    /// .body({"this": "that"});
    /// ```
    ///
    /// # Arguments
    ///
    /// - `body': a `actix_web::body::MessageBody` with the JSON content to return
    ///
    /// # Returns
    ///
    /// - `actix_web::HttpResponse`
    fn ok_json_response<B>(body: B) -> actix_web::HttpResponse
    where
        B: MessageBody + 'static;
    /// A shortcut for returning a HttpResponse like
    ///
    /// ```ignore
    /// return HttpResponse::BadRequest()
    /// .content_type("application/text")
    /// .append_header("Access-Control-Allow-Origin", "*")
    /// .body("ERROR: this is bad!");
    /// ```
    ///
    /// # Arguments
    ///
    /// - `body': a `actix_web::body::MessageBody` with the text content to return
    ///
    /// # Returns
    ///
    /// - `actix_web::HttpResponse`
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
