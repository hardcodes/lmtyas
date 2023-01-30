use actix_web::http::StatusCode;
use lmtyas::cookie_functions::{
    build_new_authentication_cookie, build_new_base64_authentication_cookie,
    build_new_cookie_response, build_new_encrypted_authentication_cookie, get_plain_cookie_string,
    COOKIE_PATH,
};
use lmtyas::rsa_functions::RsaKeys;
use secstr::SecStr;
use std::path::Path;

const WORKSPACE_DIR: &str = env!("CARGO_MANIFEST_DIR");

#[test]
fn test_cookie_functions() {
    const RSA_PASSPHRASE: &str = "12345678901234";
    const COOKIE: &str = "my cookie";

    let mut rsa_keys = RsaKeys::new();
    let invalid_rsa_cookie =
        build_new_encrypted_authentication_cookie(&COOKIE, 90, &COOKIE_PATH, &rsa_keys);
    assert_eq!(
        invalid_rsa_cookie.to_string(),
        r#"lmtyas=invalid_rsa_cookie; HttpOnly; SameSite=Strict; Secure; Path=/; Domain=/; Max-Age=90"#,
        "should not be able to build rsa encrypted cookie without loaded keys!"
    );

    let invalid_plain_base64_cookie = get_plain_cookie_string(COOKIE, &rsa_keys);
    assert_eq!(
        invalid_plain_base64_cookie, "invalid_base64_cookie",
        "should not be able to get plaint cookie from this!"
    );

    let base64_cookie = build_new_authentication_cookie(&COOKIE, 90, &COOKIE_PATH, &rsa_keys);
    assert_eq!(
        base64_cookie.to_string(),
        r#"lmtyas=bXkgY29va2ll; HttpOnly; SameSite=Strict; Secure; Path=/; Domain=/; Max-Age=90"#,
        "cannot build base64 encoded cookie!"
    );

    let secure_rsa_passphrase = SecStr::from(RSA_PASSPHRASE);
    if let Err(e) = rsa_keys.read_from_files(
        Path::new(WORKSPACE_DIR).join("ignore/lmtyas_rsa_private.key"),
        Path::new(WORKSPACE_DIR).join("ignore/lmtyas_rsa_public.key"),
        &secure_rsa_passphrase,
    ) {
        panic!("cannot load rsa keys! {}", &e);
    };

    let invalid_plain_rsa_cookie = get_plain_cookie_string(COOKIE, &rsa_keys);
    assert_eq!(
        invalid_plain_rsa_cookie, "invalid_rsa_cookie_value",
        "should not be able to get plaint cookie from this!"
    );

    let valid_rsa_cookie =
        build_new_encrypted_authentication_cookie(&COOKIE, 90, &COOKIE_PATH, &rsa_keys);
    let rsa_cookie_as_str = valid_rsa_cookie.to_string();
    let splitted_rsa_cookie_value: Vec<&str> = rsa_cookie_as_str.split(';').collect();
    let splitted_cookie_value: Vec<&str> = splitted_rsa_cookie_value
        .first()
        .unwrap()
        .split('=')
        .collect();
    let cookie = splitted_cookie_value[1];
    let plain_cookie = get_plain_cookie_string(&cookie, &rsa_keys);
    assert_eq!(plain_cookie, COOKIE, "cannot decrypt rsa encrypted cookie!");

    let valid_rsa_cookie = build_new_authentication_cookie(&COOKIE, 90, &COOKIE_PATH, &rsa_keys);
    let rsa_cookie_as_str = valid_rsa_cookie.to_string();
    let splitted_rsa_cookie_value: Vec<&str> = rsa_cookie_as_str.split(';').collect();
    let splitted_cookie_value: Vec<&str> = splitted_rsa_cookie_value
        .first()
        .unwrap()
        .split('=')
        .collect();
    let cookie = splitted_cookie_value[1];
    let plain_cookie = get_plain_cookie_string(&cookie, &rsa_keys);
    assert_eq!(plain_cookie, COOKIE, "cannot decrypt rsa encrypted cookie!");

    let base64_cookie = build_new_base64_authentication_cookie(&COOKIE, 90, &COOKIE_PATH);
    assert_eq!(
        base64_cookie.to_string(),
        r#"lmtyas=bXkgY29va2ll; HttpOnly; SameSite=Strict; Secure; Path=/; Domain=/; Max-Age=90"#,
        "cannot build base64 encoded cookie!"
    );

    let base64_cookie = build_new_base64_authentication_cookie(&COOKIE, 90, &COOKIE_PATH);
    let cookie_response = build_new_cookie_response(&base64_cookie, COOKIE_PATH.to_string());
    assert_eq!(cookie_response.status(), StatusCode::OK);
}
