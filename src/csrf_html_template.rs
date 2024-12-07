use actix_web::HttpResponse;
use log::warn;
use std::fs::read_to_string;
use std::path::Path;

/// List of template files. For just two files
/// it makes sense to use hardcoded values.
const TEMPLATE_FILES: [&str; 2] = ["reveal.html", "tell.html"];
/// Basedirectory for the template files
const TEMPLATE_BASEDIR: &str = "web-content/authenticated/";
/// CSRF token pattern that will be replaced in template files
const CSRF_TOKEN_PATTERN: &str = r"{CSRF_TOKEN}";

pub struct CsrfHtmlTemplate {}

impl CsrfHtmlTemplate {
    /// Loads template file and injects the given CSRF token and returns it
    /// as HttpResult.
    pub fn inject_csrf_token(filename: &str, csrf_token_payload: &str) -> HttpResponse {
        if !is_template_file(filename) {
            return HttpResponse::NotFound().finish();
        }
        let file_content = match read_to_string(Path::new(TEMPLATE_BASEDIR).join(filename)) {
            Err(e) => {
                warn!("Cannot load csrf template file: {}", e);
                return HttpResponse::NotFound().finish();
            }
            Ok(f) => f,
        };
        let file_content_with_csrf_token =
            file_content.replace(CSRF_TOKEN_PATTERN, csrf_token_payload);
        HttpResponse::Ok()
            .content_type("text/html; charset=UTF-8")
            .append_header(("X-Content-Type-Options", "nosniff"))
            .append_header(("Access-Control-Allow-Origin", "*"))
            .body(file_content_with_csrf_token)
    }
}

/// Check if the given filename is one of the template files.
fn is_template_file(filename: &str) -> bool {
    match TEMPLATE_FILES.into_iter().find(|&f| f == filename) {
        None => false,
        Some(_) => true,
    }
}
