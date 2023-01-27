/// The implementation of this trait should return the value of a cookie
/// if it has the given name
pub trait HeaderValueExctractor {
    fn get_value_for_cookie_with_name(&self, cookie_name: &str) -> Option<String>;
}

/// Implementation of the HeaderValueExctractor trait.
///
/// # Arguments
///
/// * `cookie_name`:  a slice of a string containing the name of the wanted cookie
///
/// # Returns
///
/// * `Some<String>`: the String representation of the cookie value
/// * `None`:         if the cookie has not the name `cookie_name` or can not be converted
///
/// ```ignore
/// "cookie": "<cookie_name>=eb9a5628-8fa1-11ea-8001-81d9d263515d"
/// "cookie": "<cookie_name>=base64gibberish"
/// "cookie": "<cookie_name>=5e599155-8f9f-11ea-8009-81d9d263515d; other_cookie=base64gibberish
/// ```
impl HeaderValueExctractor for actix_web::http::header::HeaderValue {
    fn get_value_for_cookie_with_name(&self, cookie_name: &str) -> Option<String> {
        if let Ok(header_value_str) = self.to_str() {
            let cookies = &header_value_str.split(';').collect::<Vec<_>>();
            for &cookie in cookies.iter() {
                match &cookie.split_once('='){
                    None => {},
                    Some((key,value)) => {
                        if cookie_name.eq_ignore_ascii_case(key) {
                            return Some(value.to_string());
                        }
                    }
                };
            }
        }
        None
    }
}
