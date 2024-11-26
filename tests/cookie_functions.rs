use actix_web::http::StatusCode;
use lmtyas::cookie_functions::{
    build_new_cookie_response, build_new_encrypted_authentication_cookie, get_plain_cookie_string,
    COOKIE_PATH,
};
use lmtyas::rsa_functions::RsaKeys;

#[cfg(not(feature = "oidc-auth-ldap"))]
const INVALID_RSA_COOKIE: &str =
    r"lmtyas=invalid_rsa_cookie; HttpOnly; SameSite=Strict; Secure; Path=/; Domain=/; Max-Age=90";
#[cfg(feature = "oidc-auth-ldap")]
const INVALID_RSA_COOKIE: &str =
    r"lmtyas=invalid_rsa_cookie; HttpOnly; SameSite=Lax; Secure; Path=/; Domain=/; Max-Age=90";

#[test]
fn cookie_functions() {
    const COOKIE_VALUE: &str = "my cookie";

    let rsa_keys = RsaKeys::generate_random_rsa_keys().unwrap();

    let valid_rsa_cookie =
        build_new_encrypted_authentication_cookie(COOKIE_VALUE, 90, COOKIE_PATH, &rsa_keys);
    let rsa_cookie_as_str = valid_rsa_cookie.to_string();

    let splitted_rsa_cookie_value: Vec<&str> = rsa_cookie_as_str.split(';').collect();

    let cookie = splitted_rsa_cookie_value
        .first()
        .unwrap()
        .replace("lmtyas=", "");

    let plain_cookie = get_plain_cookie_string(&cookie, &rsa_keys);
    assert_eq!(
        plain_cookie, COOKIE_VALUE,
        "cannot decrypt rsa encrypted cookie!"
    );

    let cookie_response = build_new_cookie_response(&valid_rsa_cookie, COOKIE_PATH.to_string());
    assert_eq!(cookie_response.status(), StatusCode::OK);

    let invalid_plaintext_cookie = get_plain_cookie_string(INVALID_RSA_COOKIE, &rsa_keys);
    assert_eq!(
        invalid_plaintext_cookie, "invalid_rsa_cookie_value",
        "should not be able to get plain cookie from this!"
    );
}
