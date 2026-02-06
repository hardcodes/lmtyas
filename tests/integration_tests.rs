mod authenticated_user_test;
mod common;
use actix_files::Files;
use actix_http::StatusCode;
use actix_web::body::MessageBody;
use actix_web::{guard, http::header, middleware, test, web, App, HttpResponse};
use common::SETUP_SINGLETON;
use hacaoi::hybrid_crypto::HybridCryptoFunctions;
#[cfg(feature = "hacaoi-openssl")]
type HybridCrypto = hacaoi::openssl::hybrid_crypto::HybridCrypto;
#[cfg(feature = "hacaoi-rust-crypto")]
type HybridCrypto = hacaoi::rust_crypto::hybrid_crypto::HybridCrypto;
use hacaoi::base64_trait::{Base64StringConversions, Base64VecU8Conversions};
use hacaoi::rsa::RsaKeysFunctions;
#[cfg(feature = "ldap-auth")]
use lmtyas::authentication_ldap::LdapCommonConfiguration;
#[cfg(feature = "ldap-auth")]
pub use lmtyas::authentication_ldap::LdapLogin;
use lmtyas::authentication_middleware::CheckAuthentication;
#[cfg(feature = "oidc-auth-ldap")]
use lmtyas::authentication_oidc::OidcConfiguration;
#[cfg(feature = "oidc-auth-ldap")]
use lmtyas::authentication_oidc::OidcUserDetails;
use lmtyas::authentication_url;
use lmtyas::configuration::ApplicationConfiguration;
use lmtyas::cookie_functions::build_new_encrypted_authentication_cookie;
use lmtyas::handler_functions::*;
#[cfg(any(feature = "ldap-auth", feature = "oidc-auth-ldap"))]
use lmtyas::ldap_common::LdapSearchResult;
use lmtyas::log_functions::extract_request_path;
use lmtyas::login_user_trait::Login;
#[cfg(feature = "mail-noauth-notls")]
pub use lmtyas::mail_noauth_notls::SendEMail;
#[cfg(feature = "oidc-auth-ldap")]
use lmtyas::oidc_ldap::OidcUserLdapUserDetails;
use lmtyas::MAX_BEARER_TOKEN_LEN;
use lmtyas::MAX_FORM_BYTES_LEN;
use rand::distr::Alphanumeric;
use rand::{rng, Rng};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

#[cfg(feature = "ldap-auth")]
type AuthConfiguration = LdapCommonConfiguration;
#[cfg(feature = "oidc-auth-ldap")]
type AuthConfiguration = OidcConfiguration;

const WORKSPACE_DIR: &str = env!("CARGO_MANIFEST_DIR");
const COOKIE_PATH: &str = "/";

const RSA_PRIVATE_KEY_FILE: &str = "resources/tests/rsa/lmtyas_rsa_private.pkcs8.key";
const LMTYAS_CONFIG_FILE: &str = "resources/config/lmtyas-config.json";

/// testing the functions that need external services in one go.
#[actix_web::test]
async fn with_setup() {
    let secrets_directory = Path::new(common::WORKSPACE_DIR).join("ignore/secrets");
    if !secrets_directory.exists() {
        panic!(
            "directory does not exist: {}",
            secrets_directory.to_string_lossy()
        );
    }
    remove_stored_secrets(&secrets_directory);

    let mut setup_singleton_lock = SETUP_SINGLETON.lock().await;
    // set up external helper services, like e.g. ldap and dummy mail server
    common::setup(&mut setup_singleton_lock);
    assert!(
        setup_singleton_lock.setup_done,
        "setup is not done, cannot run tests!"
    );

    // load configuration file with the ldap server connection details
    let application_configuration = ApplicationConfiguration::read_from_file(
        Path::new(common::WORKSPACE_DIR).join(LMTYAS_CONFIG_FILE),
    )
    .await
    .unwrap();

    ///////////////////////////////////////////////////////////////////////////
    // Test with configuration.
    // Call test functions that need a loaded configuration file
    // When feature "oidc-auth-ldap" is enabled, the configuration
    // file cannot be loaded without the oidc helper service running.
    ///////////////////////////////////////////////////////////////////////////
    crate::authenticated_user_test::test_authenticated_user(&application_configuration).await;

    #[cfg(feature = "mail-noauth-notls")]
    {
        // test sending mail after the server is has been started
        let send_mail_ok = application_configuration
            .configuration_file
            .email_configuration
            .send_mail(
                "alice@acme.local",
                "bob@acme.local",
                "mail_subject",
                "mail_body",
            );
        assert!(
            send_mail_ok.is_ok(),
            "server should be running, why can I not send mails?"
        );

        // test sending mail after the server is has been started
        let send_mail_fail2 = application_configuration
            .configuration_file
            .email_configuration
            .send_mail(
                "alice@acme.local",
                "wrong mail address",
                "mail_subject",
                "mail_body",
            );
        assert!(
            send_mail_fail2.is_err(),
            "should not be able to send mails with wrong address"
        );

        // test sending mail after the server is has been started
        let send_mail_fail3 = application_configuration
            .configuration_file
            .email_configuration
            .send_mail(
                "alice@acme.local",
                "<bob@acme.local",
                "mail_subject",
                "mail_body",
            );
        assert!(
            send_mail_fail3.is_err(),
            "should not be able to send mails with wrong address"
        );
    } // end of mail testing

    #[cfg(feature = "ldap-common")]
    {
        // looking up existing user by uid in ldap
        let user_found_by_uid = application_configuration
            .configuration_file
            .ldap_common_configuration
            .ldap_search_by_uid(
                "bob",
                Some(
                    &application_configuration
                        .configuration_file
                        .ldap_common_configuration
                        .user_filter,
                ),
            )
            .await;
        let user_found_by_uid_result =
            serde_json::from_str(&user_found_by_uid.unwrap().replace(['[', ']'], ""))
                as Result<LdapSearchResult, _>;
        assert_eq!(
            user_found_by_uid_result.unwrap().user_name,
            "bob",
            "expected finding user bob in ldap server by uid"
        );

        // looking up non existing user by uid in ldap
        let user_not_found_by_uid = application_configuration
            .configuration_file
            .ldap_common_configuration
            .ldap_search_by_uid(
                "b0b",
                Some(
                    &application_configuration
                        .configuration_file
                        .ldap_common_configuration
                        .user_filter,
                ),
            )
            .await;
        let user_not_found_by_uid_result =
            serde_json::from_str(&user_not_found_by_uid.unwrap().replace(['[', ']'], ""))
                as Result<LdapSearchResult, _>;
        assert!(
            user_not_found_by_uid_result.is_err(),
            "expected not to find user b0b in ldap server by uid"
        );

        // looking up existing user by mail in ldap
        let user_found_by_mail = application_configuration
            .configuration_file
            .ldap_common_configuration
            .ldap_search_by_mail(
                "bob@acme.local",
                Some(
                    &application_configuration
                        .configuration_file
                        .ldap_common_configuration
                        .mail_filter,
                ),
            )
            .await;
        let user_found_by_mail_result =
            serde_json::from_str(&user_found_by_mail.unwrap().replace(['[', ']'], ""))
                as Result<LdapSearchResult, _>;
        assert_eq!(
            user_found_by_mail_result.unwrap().user_name,
            "bob",
            "expected finding user bob in ldap server by mail"
        );

        // looking up non existing user by mail in ldap
        let user_not_found_by_mail = application_configuration
            .configuration_file
            .ldap_common_configuration
            .ldap_search_by_mail(
                "b0b@acme.local",
                Some(
                    &application_configuration
                        .configuration_file
                        .ldap_common_configuration
                        .user_filter,
                ),
            )
            .await;
        let user_not_found_by_mail_result =
            serde_json::from_str(&user_not_found_by_mail.unwrap().replace(['[', ']'], ""))
                as Result<LdapSearchResult, _>;
        assert!(
            user_not_found_by_mail_result.is_err(),
            "expected not to find user b0b in ldap server by mail"
        );
    } // end of common ldap testing

    #[cfg(feature = "ldap-auth")]
    {
        // ldap login with correct password
        let ldap_login_success = application_configuration
            .configuration_file
            .ldap_common_configuration
            .ldap_login("bob", "passw0rd")
            .await;
        assert!(
            matches!(ldap_login_success, Ok(_)),
            "user bob could not login with correct password"
        );

        // ldap login with wrong user name and password
        let ldap_login_fail = application_configuration
            .configuration_file
            .ldap_common_configuration
            .ldap_login("mary", "peterpaul")
            .await;
        assert!(
            matches!(ldap_login_fail, Err(_)),
            "user bob should not be able to login with wrong password"
        );
    } // end of ldap auth testing

    #[cfg(feature = "oidc-auth-ldap")]
    {
        let oidc_user = OidcUserLdapUserDetails::get_oidc_user_details_from_email(
            "bob@acme.local",
            &application_configuration,
        )
        .await;
        assert!(
            oidc_user.is_ok(),
            "oidc user details for bob@acme.local should be found!"
        );
        let oidc_user = OidcUserLdapUserDetails::get_oidc_user_details_from_email(
            "bobo@acme.local",
            &application_configuration,
        )
        .await;
        assert!(
            oidc_user.is_err(),
            "oidc user details for bobo@acme.local should not be found!"
        );
    } // end of oidc ldap testing

    ///////////////////////////////////////////////////////////////////////////
    // At this point functions were only tested with a loaded configuration.
    // Now we start the service itself.
    ///////////////////////////////////////////////////////////////////////////
    // values for the csp-header
    let content_security_policy = concat!(
        "form-action 'self';",
        "frame-ancestors 'none';",
        "connect-src 'self';",
        "default-src 'self';",
        "script-src 'self';",
        "style-src 'self';",
    );

    let test_service = test::init_service(lmtyas::app!(
        application_configuration.clone(),
        content_security_policy,
        MAX_FORM_BYTES_LEN
    ))
    .await;

    ///////////////////////////////////////////////////////////////////////////
    // Testing routes that don't need authentication
    ///////////////////////////////////////////////////////////////////////////

    let request = test::TestRequest::get()
        .uri("/monitoring/still_alive")
        .to_request();
    let result = test::call_and_read_body(&test_service, request).await;
    assert_eq!(
        result,
        "System alive but not ready!".as_bytes(),
        "service should not boogie!"
    );

    let request = test::TestRequest::get()
        .uri("/system/is_server_ready")
        .to_request();
    let result = test::call_and_read_body(&test_service, request).await;
    assert_eq!(
        result,
        "{\"isReady\": false}".as_bytes(),
        "/system/is_server_ready should fail!"
    );

    let request = test::TestRequest::get()
        .uri("/system/get/login-hint")
        .to_request();
    let result = test::call_and_read_body(&test_service, request).await;
    assert_eq!(
        result,
        "A.C.M.E. LDAP account".as_bytes(),
        "wrong response from /system/get/login-hint!"
    );

    let request = test::TestRequest::get()
        .uri("/system/get/mail-hint")
        .to_request();
    let result = test::call_and_read_body(&test_service, request).await;
    assert_eq!(
        result,
        "{\"MailHint\": \"hint:firstname.lastname@acme.local\"}".as_bytes(),
        "wrong response from /system/get/mail-hint!"
    );

    let request = test::TestRequest::get()
        .uri("/system/get/imprint-link")
        .to_request();
    let result = test::call_and_read_body(&test_service, request).await;
    assert_eq!(
        result,
        "{\"href\":\"https://www.acme.local/imprint\",\"target\":\"_blank\"}".as_bytes(),
        "wrong response from /system/get/imprint-link!"
    );

    let request = test::TestRequest::get()
        .uri("/system/get/privacy-link")
        .to_request();
    let result = test::call_and_read_body(&test_service, request).await;
    assert_eq!(
        result,
        "{\"href\":\"https://www.acme.local/privacy\",\"target\":\"_blank\"}".as_bytes(),
        "wrong response from /system/get/privacy-link!"
    );

    let request = test::TestRequest::get()
        .uri("/gfx/favicon.png")
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::OK,
        "/gfx/favicon.png should be 200!"
    );

    let request = test::TestRequest::get()
        .uri("/gfx/company-logo.png")
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::OK,
        "/gfx/company-logo.png should be 200!"
    );

    let request = test::TestRequest::get().uri("/css/colors.css").to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::OK,
        "/css/colors.css should be 200!"
    );

    let request = test::TestRequest::get().uri("/css/lmtyas.css").to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::OK,
        "/css/lmtyas.css should be 200!"
    );

    let request = test::TestRequest::get()
        .uri("/custom/imprint.html")
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::NOT_FOUND,
        "/custom/imprint.html should be 302!"
    );

    let request = test::TestRequest::get()
        .uri("/custom/privacy.html")
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::NOT_FOUND,
        "/custom/privacy.html should be 302!"
    );

    let index_file = Path::new(common::WORKSPACE_DIR).join("web-content/static/index.html");
    if !index_file.exists() {
        panic!("file does not exist: {}", index_file.to_string_lossy());
    }
    let index_file_content = std::fs::read_to_string(index_file).unwrap();
    let request = test::TestRequest::get().uri("/index.html").to_request();
    let result = test::call_service(&test_service, request).await;

    assert_eq!(
        result.status(),
        StatusCode::OK,
        "/index.html should be 200!"
    );
    let body = test::read_body(result).await;
    assert_eq!(
        body.try_into_bytes().unwrap(),
        index_file_content.as_bytes(),
        "should return body of index.html!"
    );

    let request = test::TestRequest::get().uri("/").to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(result.status(), StatusCode::SEE_OTHER, "/ should be 303!");
    assert_eq!(
        result.response().headers().get(header::LOCATION),
        Some(&header::HeaderValue::from_static("/index.html")),
        "Location header should point to index.html!"
    );

    let request = test::TestRequest::get().uri("/random.html").to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::NOT_FOUND,
        "/random.html should be 404!"
    );

    let request = test::TestRequest::get().uri("/random.html").to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::NOT_FOUND,
        "/random.html should be 404!"
    );

    let request = test::TestRequest::get().uri("/../Cargo.toml").to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::NOT_FOUND,
        "//../Cargo.toml should be 404!"
    );

    ///////////////////////////////////////////////////////////////////////////
    // Testing routes that need authentication and should redirect
    ///////////////////////////////////////////////////////////////////////////

    let request = test::TestRequest::post()
        .uri("/authenticated/sysop/set_password_for_rsa_rivate_key")
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::FOUND,
        "/authenticated/sysop/set_password_for_rsa_rivate_key should redirect!"
    );

    let request = test::TestRequest::get()
        .uri("/authenticated/sysop/sysop.html")
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::FOUND,
        "/authenticated/sysop/sysop.html should redirect!"
    );

    let request = test::TestRequest::get()
        .uri("/authenticated/sysop/js/sysop.js")
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::FOUND,
        "/authenticated/sysop/js/sysop.js should redirect!"
    );

    let request = test::TestRequest::post()
        .uri("/authenticated/secret/tell")
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::FOUND,
        "/authenticated/secret/tell should redirect!"
    );

    let request = test::TestRequest::get()
        .uri("/authenticated/secret/reveal/abcd")
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::FOUND,
        "/authenticated/secret/reveal/abcd should redirect!"
    );

    let request = test::TestRequest::get()
        .uri("/authenticated/user/get/details/from")
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::FOUND,
        "/authenticated/user/get/details/from should redirect!"
    );

    let request = test::TestRequest::get()
        .uri("/authenticated/receiver/get/validated_email/abdc")
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::FOUND,
        "/authenticated/receiver/get/validated_email/ should redirect!"
    );

    let request = test::TestRequest::get()
        .uri("/authenticated/keep_session_alive")
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::FOUND,
        "/authenticated/keep_session_alive should redirect!"
    );

    let request = test::TestRequest::post().uri("/api/v1/secret").to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "/api/v1/secret should be unavailable!"
    );

    let request = test::TestRequest::get().uri("/html/tell.html").to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::FOUND,
        "/html/tell.html should redirect!"
    );

    let request = test::TestRequest::get()
        .uri("/html/reveal.html")
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::FOUND,
        "/html/reveal.html should redirect!"
    );

    ///////////////////////////////////////////////////////////////////////////
    // Testing access token route
    ///////////////////////////////////////////////////////////////////////////

    {
        if application_configuration
            .hybrid_crypto_for_secrets
            .lock()
            .await
            .is_some()
        {
            panic!("rsa private key should not have been loaded at this point!");
        }
    }

    let access_token_path = Path::new(WORKSPACE_DIR)
        .join("resources/tests/access_token_payload/test-token-payload.json");
    let access_token_file = File::open(access_token_path).unwrap();
    let reader = BufReader::new(access_token_file);
    let access_token: lmtyas::access_token::AccessTokenPayload =
        serde_json::from_reader(reader).unwrap();

    let bearer_token_ok = serde_json::to_string(&access_token.clone())
        .unwrap()
        .to_base64_encoded();
    const SECRET_PLAINTEXT: &str = r#"PASS!"§$%&/()=?ß\´`+*~'#-_.:,;<>|WORD"#;
    const CONTEXT: &str = "TESTING LMTYAS";
    const IP_ADDRESS: &str = "127.0.0.1:9876";
    const IP_ADDRESS_BAD: &str = "1.2.3.4:9876";
    let base64_secret = SECRET_PLAINTEXT.to_base64_encoded();
    let secret = lmtyas::secret_functions::Secret {
        from_email: "".to_string(),
        from_display_name: "".to_string(),
        to_email: "alice@acme.local".to_string(),
        to_display_name: "".to_string(),
        context: CONTEXT.to_string(),
        secret: base64_secret,
        csrf_token: None,
    };
    let json_secret = serde_json::to_string(&secret).unwrap();
    let request = test::TestRequest::post()
        .uri("/api/v1/secret")
        .append_header(("Authorization", format!("Bearer {}", &bearer_token_ok)))
        .set_payload(json_secret.clone())
        .peer_addr(IP_ADDRESS.parse().unwrap())
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "/api/v1/secret should be unavailable!"
    );

    const RSA_PASSPHRASE: &str = "12345678901234";
    let hybrid_crypto = match HybridCrypto::from_file(
        Path::new(WORKSPACE_DIR).join(RSA_PRIVATE_KEY_FILE),
        RSA_PASSPHRASE,
    ) {
        Err(e) => {
            panic!("cannot load rsa keys! {}", &e);
        }
        Ok(hybrid_crypto) => hybrid_crypto,
    };

    let mut rwlockguard = application_configuration
        .hybrid_crypto_for_secrets
        .lock()
        .await;
    *rwlockguard = Some(hybrid_crypto);
    drop(rwlockguard);

    let request = test::TestRequest::post()
        .uri("/api/v1/secret")
        .append_header(("Authorization", format!("Bearer {}", &bearer_token_ok)))
        .set_payload(json_secret.clone())
        .peer_addr(IP_ADDRESS.parse().unwrap())
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::OK,
        "/api/v1/secret should work now!"
    );
    let body = test::read_body(result).await;
    assert_eq!(body.try_into_bytes().unwrap(), "OK".as_bytes());
    // try with no Authorization Bearer token header at all
    let request = test::TestRequest::post()
        .uri("/api/v1/secret")
        .set_payload(json_secret.clone())
        .peer_addr(IP_ADDRESS.parse().unwrap())
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::FORBIDDEN,
        "/api/v1/secret should not work (no Authorization Bearer token header)!"
    );
    let body = test::read_body(result).await;
    assert_eq!(
        body.try_into_bytes().unwrap(),
        "No access token found!".as_bytes(),
        "/api/v1/secret should not work (no Authorization Bearer token header)!"
    );
    // try with empty Authorization Bearer token header
    let request = test::TestRequest::post()
        .uri("/api/v1/secret")
        .append_header(("Authorization", ""))
        .set_payload(json_secret.clone())
        .peer_addr(IP_ADDRESS.parse().unwrap())
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::UNAUTHORIZED,
        "/api/v1/secret should not work (empty Authorization Bearer token header)!"
    );
    let body = test::read_body(result).await;
    assert_eq!(
        body.try_into_bytes().unwrap(),
        "No access token found!".as_bytes(),
        "/api/v1/secret should not work (empty Authorization Bearer token header)!"
    );
    // try with phantasy Authorization Bearer token header
    let request = test::TestRequest::post()
        .uri("/api/v1/secret")
        .append_header(("Authorization", "blablabla"))
        .set_payload(json_secret.clone())
        .peer_addr(IP_ADDRESS.parse().unwrap())
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::UNAUTHORIZED,
        "/api/v1/secret should not work (phantasy Authorization Bearer token header)!"
    );
    let body = test::read_body(result).await;
    assert_eq!(
        body.try_into_bytes().unwrap(),
        "No access token found!".as_bytes(),
        "/api/v1/secret should not work (phantasy Authorization Bearer token header)!"
    );

    // not base64 encoded but enough for size checking
    let oversized_bearer_token: String = rng()
        .sample_iter(&Alphanumeric)
        .take(MAX_BEARER_TOKEN_LEN + 1)
        .map(char::from)
        .collect();
    let request = test::TestRequest::post()
        .uri("/api/v1/secret")
        .append_header((
            "Authorization",
            format!("Bearer {}", &oversized_bearer_token),
        ))
        .set_payload(json_secret.clone())
        .peer_addr(IP_ADDRESS.parse().unwrap())
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::UNAUTHORIZED,
        "/api/v1/secret should not work (bearer token size)!"
    );
    let body = test::read_body(result).await;
    assert_eq!(
        body.try_into_bytes().unwrap(),
        "Access token too big!".as_bytes(),
        "/api/v1/secret should not work (bearer token size)!"
    );

    let request = test::TestRequest::post()
        .uri("/api/v1/secret")
        .append_header(("Authorization", format!("Bearer {}", &bearer_token_ok)))
        .set_payload(json_secret.clone())
        .peer_addr(IP_ADDRESS_BAD.parse().unwrap())
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::FORBIDDEN,
        "/api/v1/secret should not work (bad ip)!"
    );

    let mut bearer_token_bad = access_token.clone();
    bearer_token_bad.aud = "yada".to_string();
    let bearer_token_bad = serde_json::to_string(&bearer_token_bad).unwrap();
    let request = test::TestRequest::post()
        .uri("/api/v1/secret")
        .append_header(("Authorization", format!("Bearer {}", &bearer_token_bad)))
        .set_payload(json_secret.clone())
        .peer_addr(IP_ADDRESS.parse().unwrap())
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::UNAUTHORIZED,
        "/api/v1/secret should not work (bad aud)!"
    );

    let mut bearer_token_bad = access_token.clone();
    bearer_token_bad.iss = "yada".to_string();
    let bearer_token_bad_b64 = serde_json::to_string(&bearer_token_bad).unwrap();
    let request = test::TestRequest::post()
        .uri("/api/v1/secret")
        .append_header(("Authorization", format!("Bearer {}", &bearer_token_bad_b64)))
        .set_payload(json_secret.clone())
        .peer_addr(IP_ADDRESS.parse().unwrap())
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::UNAUTHORIZED,
        "/api/v1/secret should not work (bad iss)!"
    );

    let mut bearer_token_bad = access_token.clone();
    bearer_token_bad.jti = "yada".to_string();
    let bearer_token_bad = serde_json::to_string(&bearer_token_bad).unwrap();
    let request = test::TestRequest::post()
        .uri("/api/v1/secret")
        .append_header(("Authorization", format!("Bearer {}", &bearer_token_bad)))
        .set_payload(json_secret.clone())
        .peer_addr(IP_ADDRESS.parse().unwrap())
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::UNAUTHORIZED,
        "/api/v1/secret should not work (bad jti)!"
    );

    // decodes to b800066c-028d-411f-b269-88b041774690 (non existent file on server side)
    const BAD_JTI: &str = "uTDqmTHf2rACPA7ty+wtxLYBJLcVmruDdwfXsmKfoawYrm0j55fD1SX9KTzw2XBquf0wrhjExAI0P5AERtMx4jIAcazbWzY7XvMD6QfRfjonx9km7TDa8d1WrjcpDR2lqZxCkoPUE09UfuynaCc8gCfnoPJQEa9TI3oRzFvtmzvoVFlBucjJxVBwcvlY0aYhwLtxRxX2KDKT3cbkxfASR7FXLVY8SlCfD5UomiIvXF6Z7L+nQnZNNSML0/SlIREzfgRaqoHeBN94mwRyaNP8of0CtzA55zOvNgyV7pXZbGbPvBT4QiN/eHfwIsI9hObZx0SRPWIU97ipSgINBlSB9BE3JBiQFGkY8OonugVhbQ12nNlNNgW14IiLZ3pWpi1YfJr0pvKJL3YznAdN6eOesFd8WnMBlxgtASAuXqhg2qZqfLnNM36jC4wzbq7UXU5i3Vk9PF9QItt2QhZTfS4jdRWLdJxbvMkhszRBLObIR0vRugZY5N8Nh7kSndTZcGgVtkjemrqxSFjRr/4WCAjT5Qry8/4DCs1RRzy8b4MKvF9SNbGM+aFfxOSO+si7rhywwzNRWwMVW0oTCEeBTwNfe2paC16/CwBxMHH3g5/FnHSP5Awl6taPiihCDB6G9g/3B/Py6md4++QtSIs4E+2j6k41QlRezTBPzWBe/IlpWD8=";
    let mut bearer_token_bad = access_token.clone();
    bearer_token_bad.jti = BAD_JTI.to_string();
    let bearer_token_bad = serde_json::to_string(&bearer_token_bad).unwrap();
    let request = test::TestRequest::post()
        .uri("/api/v1/secret")
        .append_header(("Authorization", format!("Bearer {}", &bearer_token_bad)))
        .set_payload(json_secret.clone())
        .peer_addr(IP_ADDRESS.parse().unwrap())
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::UNAUTHORIZED,
        "/api/v1/secret should not work (bad jti)!"
    );

    // decodes to "Not enrypted""
    const BAD_JTI2: &str = "Tm90IGVuY3J5cHRlZA==";
    let mut bearer_token_bad = access_token.clone();
    bearer_token_bad.jti = BAD_JTI2.to_string();
    let bearer_token_bad_b64 = serde_json::to_string(&bearer_token_bad).unwrap();
    let request = test::TestRequest::post()
        .uri("/api/v1/secret")
        .append_header(("Authorization", format!("Bearer {}", &bearer_token_bad_b64)))
        .set_payload(json_secret.clone())
        .peer_addr(IP_ADDRESS.parse().unwrap())
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::UNAUTHORIZED,
        "/api/v1/secret should not work (bad jti)!"
    );

    let mut bearer_token_bad = access_token.clone();
    bearer_token_bad.nbf = 1672527600; // Jan 01 2023
    let bearer_token_bad = serde_json::to_string(&bearer_token_bad).unwrap();
    let request = test::TestRequest::post()
        .uri("/api/v1/secret")
        .append_header(("Authorization", format!("Bearer {}", &bearer_token_bad)))
        .set_payload(json_secret.clone())
        .peer_addr(IP_ADDRESS.parse().unwrap())
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::UNAUTHORIZED,
        "/api/v1/secret should not work (bad nbf)!"
    );

    let mut bearer_token_bad = access_token.clone();
    bearer_token_bad.exp = 4070818800; // Dec 31 2098
    let bearer_token_bad = serde_json::to_string(&bearer_token_bad).unwrap();
    let request = test::TestRequest::post()
        .uri("/api/v1/secret")
        .append_header(("Authorization", format!("Bearer {}", &bearer_token_bad)))
        .set_payload(json_secret.clone())
        .peer_addr(IP_ADDRESS.parse().unwrap())
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::UNAUTHORIZED,
        "/api/v1/secret should not work (bad exp)!"
    );

    let base64_secret = SECRET_PLAINTEXT.to_base64_encoded();
    let secret = lmtyas::secret_functions::Secret {
        from_email: "".to_string(),
        from_display_name: "".to_string(),
        to_email: "jane@acme.local".to_string(),
        to_display_name: "".to_string(),
        context: CONTEXT.to_string(),
        secret: base64_secret,
        csrf_token: None,
    };
    let json_secret = serde_json::to_string(&secret).unwrap();
    let request = test::TestRequest::post()
        .uri("/api/v1/secret")
        .append_header(("Authorization", format!("Bearer {}", &bearer_token_ok)))
        .set_payload(json_secret)
        .peer_addr(IP_ADDRESS.parse().unwrap())
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::BAD_REQUEST,
        "/api/v1/secret should not work (bad email)!"
    );

    ///////////////////////////////////////////////////////////////////////////
    // Testing setting of RSA password
    ///////////////////////////////////////////////////////////////////////////

    // Log in walter
    let cookie_data_walter = match application_configuration
        .shared_authenticated_users
        .write()
        .unwrap()
        .new_cookie_data_for("walter", "Walter", "Linz", "walter@acme.local", "127.0.0.1")
    {
        Some(c) => c,
        None => {
            panic!("cookie_data for Walter expected!");
        }
    };

    if let Some(authenticated_walter) = application_configuration
        .shared_authenticated_users
        .read()
        .unwrap()
        .authenticated_users_hashmap
        .get(&cookie_data_walter.uuid)
    {
        let valid_walter_cookie_value = format!(
            "{};{}",
            cookie_data_walter.uuid.to_string(),
            &authenticated_walter.cookie_update_lifetime_counter
        );

        let valid_rsa_cookie = build_new_encrypted_authentication_cookie(
            &valid_walter_cookie_value,
            90,
            COOKIE_PATH,
            &application_configuration.rsa_keys_for_cookies,
        );
        let request = test::TestRequest::get()
            .uri("/authenticated/sysop/sysop.html")
            .append_header(("Cookie", valid_rsa_cookie.to_string()))
            .peer_addr(IP_ADDRESS.parse().unwrap())
            .to_request();
        let result = test::call_service(&test_service, request).await;
        assert_eq!(
            result.status(),
            StatusCode::OK,
            "/authenticated/sysop/sysop.html should work with cookie!"
        );
        let body = test::read_body(result).await;
        assert!(
            std::str::from_utf8(&body.try_into_bytes().unwrap())
                .unwrap()
                .contains(&authenticated_walter.csrf_token),
            "sysop.html should contain crsf token!"
        );

        let request = test::TestRequest::get()
            .uri("/authenticated/sysop/js/sysop.js")
            .append_header(("Cookie", valid_rsa_cookie.to_string()))
            .peer_addr(IP_ADDRESS.parse().unwrap())
            .to_request();
        let result = test::call_service(&test_service, request).await;
        assert_eq!(
            result.status(),
            StatusCode::OK,
            "/authenticated/sysop/js/sysop.js should work with cookie!"
        );
        // "wrong passw0rd" + right csrf token
        let wrong_b64_password_csrf =
            format!("d3JvbmcgcGFzc3cwcmQ=;{}", &authenticated_walter.csrf_token);
        let request = test::TestRequest::post()
            .uri("/authenticated/sysop/set_password_for_rsa_rivate_key")
            .append_header(("Cookie", valid_rsa_cookie.to_string()))
            .peer_addr(IP_ADDRESS.parse().unwrap())
            .set_payload(wrong_b64_password_csrf)
            .to_request();
        let result = test::call_service(&test_service, request).await;
        assert_eq!(
            result.status(),
            StatusCode::BAD_REQUEST,
            "/authenticated/sysop/set_password_for_rsa_rivate_key should not work!"
        );
        // right password "12345678901234" (MTIzNDU2Nzg5MDEyMzQ=)
        let ok_b64_password_csrf =
            format!("MTIzNDU2Nzg5MDEyMzQ=;{}", &authenticated_walter.csrf_token);
        let bad_b64_password_csrf_1 =
            format!("MTIzNDU2Nzg5MDEyMzQ={}", &authenticated_walter.csrf_token);
        let bad_b64_password_csrf_2 =
            format!("MTIzNDU2Nzg5MDEyMzQ=;{}x", &authenticated_walter.csrf_token);
        // missing ; separator
        let request = test::TestRequest::post()
            .uri("/authenticated/sysop/set_password_for_rsa_rivate_key")
            .append_header(("Cookie", valid_rsa_cookie.to_string()))
            .peer_addr(IP_ADDRESS.parse().unwrap())
            .set_payload(bad_b64_password_csrf_1)
            .to_request();
        let result = test::call_service(&test_service, request).await;
        assert_eq!(
            result.status(),
            StatusCode::BAD_REQUEST,
            "/authenticated/sysop/set_password_for_rsa_rivate_key should not work!"
        );
        // wrong csrf token
        let request = test::TestRequest::post()
            .uri("/authenticated/sysop/set_password_for_rsa_rivate_key")
            .append_header(("Cookie", valid_rsa_cookie.to_string()))
            .peer_addr(IP_ADDRESS.parse().unwrap())
            .set_payload(bad_b64_password_csrf_2)
            .to_request();
        let result = test::call_service(&test_service, request).await;
        assert_eq!(
            result.status(),
            StatusCode::BAD_REQUEST,
            "/authenticated/sysop/set_password_for_rsa_rivate_key should not work!"
        );
        // right password and csrf token
        let request = test::TestRequest::post()
            .uri("/authenticated/sysop/set_password_for_rsa_rivate_key")
            .append_header(("Cookie", valid_rsa_cookie.to_string()))
            .peer_addr(IP_ADDRESS.parse().unwrap())
            .set_payload(ok_b64_password_csrf)
            .to_request();
        let result = test::call_service(&test_service, request).await;
        assert_eq!(
            result.status(),
            StatusCode::OK,
            "/authenticated/sysop/set_password_for_rsa_rivate_key should work!"
        );
        {
            if application_configuration
                .hybrid_crypto_for_secrets
                .lock()
                .await
                .is_none()
            {
                panic!("rsa private key should have been loaded at this point!");
            }
        }
        // keys are loaded, base64 encoded cookie is not enough:
        let request = test::TestRequest::get()
            .uri("/authenticated/user/get/details/from")
            .append_header((header::SET_COOKIE, valid_rsa_cookie.to_string()))
            .peer_addr(IP_ADDRESS.parse().unwrap())
            .to_request();
        let result = test::call_service(&test_service, request).await;
        assert_eq!(
            result.status(),
            StatusCode::FOUND,
            "/authenticated/user/get/details/from should redirect!"
        );
    }
    ///////////////////////////////////////////////////////////////////////////
    // Log in Bob
    ///////////////////////////////////////////////////////////////////////////
    let cookie_data_bob = match application_configuration
        .shared_authenticated_users
        .write()
        .unwrap()
        .new_cookie_data_for("bob", "Bob", "Sanders", "bob@acme.local", "127.0.0.1")
    {
        Some(c) => c,
        None => {
            panic!("cookie_data for Bob expected!");
        }
    };

    let valid_cookie_value = format!(
        "{};{}",
        cookie_data_bob.uuid.to_string(),
        &cookie_data_bob.cookie_update_lifetime_counter
    );
    let valid_rsa_cookie = build_new_encrypted_authentication_cookie(
        &valid_cookie_value,
        90,
        COOKIE_PATH,
        &application_configuration.rsa_keys_for_cookies,
    );
    // try again with encrypted cookie
    let request = test::TestRequest::get()
        .uri("/authenticated/user/get/details/from")
        .append_header(("Cookie", valid_rsa_cookie.to_string()))
        .peer_addr(IP_ADDRESS.parse().unwrap())
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::OK,
        "/authenticated/user/get/details/from should work now!"
    );
    let body = test::read_body(result).await;
    assert_eq!(
        body.try_into_bytes().unwrap(),
        "{\"DisplayName\":\"Bob Sanders\",\"Email\":\"bob@acme.local\"}".as_bytes(),
        "/authenticated/user/get/details/from should provide data!"
    );

    ///////////////////////////////////////////////////////////////////////////
    // Get receiver email (as Bob)
    ///////////////////////////////////////////////////////////////////////////

    // wrong address format
    let request = test::TestRequest::get()
        .uri("/authenticated/receiver/get/validated_email/alice@acme.world.local")
        .append_header(("Cookie", valid_rsa_cookie.to_string()))
        .peer_addr(IP_ADDRESS.parse().unwrap())
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::OK,
        "/authenticated/receiver/get/validated_email/alice@acme.world.local should work!"
    );
    let body = test::read_body(result).await;
    assert_eq!(
        body.try_into_bytes().unwrap(),
        lmtyas::UNKNOWN_RECEIVER_EMAIL.as_bytes(),
        "/authenticated/receiver/get/validated_email/alice@acme.world.local should provide unknown email!"
    );

    // unkown email
    let request = test::TestRequest::get()
        .uri("/authenticated/receiver/get/validated_email/jane@acme.local")
        .append_header(("Cookie", valid_rsa_cookie.to_string()))
        .peer_addr(IP_ADDRESS.parse().unwrap())
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::OK,
        "/authenticated/receiver/get/validated_email/jane@acme.local should work!"
    );
    let body = test::read_body(result).await;
    assert_eq!(
        body.try_into_bytes().unwrap(),
        lmtyas::UNKNOWN_RECEIVER_EMAIL.as_bytes(),
        "/authenticated/receiver/get/validated_email/jane@acme.local should provide unknown email!"
    );

    // well kown email
    let request = test::TestRequest::get()
        .uri("/authenticated/receiver/get/validated_email/alice@acme.local")
        .append_header(("Cookie", valid_rsa_cookie.to_string()))
        .peer_addr(IP_ADDRESS.parse().unwrap())
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::OK,
        "/authenticated/receiver/get/validated_email/alice@acme.local should work!"
    );
    let body = test::read_body(result).await;
    assert_eq!(
        body.try_into_bytes().unwrap(),
        "alice@acme.local".as_bytes(),
        "/authenticated/receiver/get/validated_email/alice@acme.local should provide same email address!"
    );

    ///////////////////////////////////////////////////////////////////////////
    // Keep session alive
    ///////////////////////////////////////////////////////////////////////////

    let request = test::TestRequest::get()
        .uri("/authenticated/keep_session_alive")
        .append_header(("Cookie", valid_rsa_cookie.to_string()))
        .peer_addr(IP_ADDRESS.parse().unwrap())
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::OK,
        "/authenticated/keep_session_alive should work!"
    );
    let body = test::read_body(result).await;
    assert_eq!(
        body.try_into_bytes().unwrap(),
        "OK".as_bytes(),
        "/authenticated/keep_session_alive should return OK!"
    );

    // setup fake cookie
    let encrypted_cookie_value = {
        let mut hybrid_crypto_rwlock = application_configuration
            .hybrid_crypto_for_secrets
            .lock()
            .await;
        // Take the `Option<HybridCrypto>`, so that we can work with it. As long as the write lock exists,
        // nobody else will notice. This code path must not panic (we shouln't anyway inside a thread)!
        // Really ugly hack, there must be a better way!
        let hybrid_crypto_option = hybrid_crypto_rwlock.take();
        // Safe, we checked before.
        let hybrid_crypto = hybrid_crypto_option.unwrap();
        // de1bf8ab-a9f3-4af6-9183-56f6d7b17ec7 is a random value generated with uuidgen
        let encrypted_cookie_value = hybrid_crypto
            .encrypt_str_pkcs1v15_padding_to_b64("de1bf8ab-a9f3-4af6-9183-56f6d7b17ec7;0")
            .unwrap();
        // Put back the `Option<HybridCrypto>`
        *hybrid_crypto_rwlock = Some(hybrid_crypto);
        encrypted_cookie_value
    };
    let fake_cookie = format!(
        "{}={}",
        &lmtyas::cookie_functions::COOKIE_NAME,
        &encrypted_cookie_value
    );
    let request = test::TestRequest::get()
        .uri("/authenticated/keep_session_alive")
        .append_header(("Cookie", fake_cookie))
        .peer_addr(IP_ADDRESS.parse().unwrap())
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::FOUND,
        "/authenticated/keep_session_alive should not work with a fake cookie!"
    );

    // Create a random secret that is 8000 chars long (max. length in form)
    let random_secret: String = rng()
        .sample_iter(&Alphanumeric)
        .take(8000)
        .map(char::from)
        .collect();

    ///////////////////////////////////////////////////////////////////////////
    // Tell secret
    ///////////////////////////////////////////////////////////////////////////
    // build a random context that we can search for later on.
    let random_context: String = rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    // get updated cookie
    if let Some(authenticated_bob) = application_configuration
        .shared_authenticated_users
        .read()
        .unwrap()
        .authenticated_users_hashmap
        .get(&cookie_data_bob.uuid)
    {
        let valid_cookie_value = format!(
            "{};{}",
            cookie_data_bob.uuid.to_string(),
            &authenticated_bob.cookie_update_lifetime_counter
        );
        let valid_updated_rsa_cookie = build_new_encrypted_authentication_cookie(
            &valid_cookie_value,
            90,
            COOKIE_PATH,
            &application_configuration.rsa_keys_for_cookies,
        );

        // Check if tell.html form contains the CSRF token generated for user bob
        let request = test::TestRequest::get()
            .uri("/html/tell.html")
            .append_header(("Cookie", valid_updated_rsa_cookie.to_string()))
            .peer_addr(IP_ADDRESS.parse().unwrap())
            .to_request();
        let result = test::call_service(&test_service, request).await;
        assert_eq!(
            result.status(),
            StatusCode::OK,
            "GET /html/tell.html should work!"
        );
        let body = test::read_body(result).await;
        assert!(
            std::str::from_utf8(&body.try_into_bytes().unwrap())
                .unwrap()
                .contains(&authenticated_bob.csrf_token),
            "tell.html should contain crsf token!"
        );

        // build and send secret
        let base64_secret = random_secret.to_base64_encoded();
        let secret = lmtyas::secret_functions::Secret {
            from_email: "bob@acme.local".to_string(),
            from_display_name: "Bob Sanders".to_string(),
            to_email: "alice@acme.local".to_string(),
            to_display_name: "Alice Henderson".to_string(),
            context: random_context.clone(),
            secret: base64_secret.clone(),
            csrf_token: Some(authenticated_bob.csrf_token.clone()),
        };
        let json_secret = serde_json::to_string(&secret).unwrap();
        let request = test::TestRequest::post()
            .uri("/authenticated/secret/tell")
            .append_header(("Cookie", valid_updated_rsa_cookie.to_string()))
            .peer_addr(IP_ADDRESS.parse().unwrap())
            .set_payload(json_secret)
            .to_request();
        let result = test::call_service(&test_service, request).await;
        assert_eq!(
            result.status(),
            StatusCode::OK,
            "authenticated/secret/tell should work!"
        );
        let body = test::read_body(result).await;
        assert_eq!(
            body.try_into_bytes().unwrap(),
            "OK".as_bytes(),
            "authenticated/secret/tell should return OK!"
        );
        // no CSRF token
        let secret = lmtyas::secret_functions::Secret {
            from_email: "bob@acme.local".to_string(),
            from_display_name: "Bob Sanders".to_string(),
            to_email: "alice@acme.local".to_string(),
            to_display_name: "Alice Henderson".to_string(),
            context: random_context.clone(),
            secret: base64_secret.clone(),
            csrf_token: None,
        };
        let json_secret = serde_json::to_string(&secret).unwrap();
        let request = test::TestRequest::post()
            .uri("/authenticated/secret/tell")
            .append_header(("Cookie", valid_updated_rsa_cookie.to_string()))
            .peer_addr(IP_ADDRESS.parse().unwrap())
            .set_payload(json_secret)
            .to_request();
        let result = test::call_service(&test_service, request).await;
        assert_eq!(
            result.status(),
            StatusCode::BAD_REQUEST,
            "authenticated/secret/tell should not work!"
        );
        // wrong CSRF token
        let mut wrong_csrf_token = authenticated_bob.csrf_token.clone();
        wrong_csrf_token.push('x');
        let secret = lmtyas::secret_functions::Secret {
            from_email: "bob@acme.local".to_string(),
            from_display_name: "Bob Sanders".to_string(),
            to_email: "alice@acme.local".to_string(),
            to_display_name: "Alice Henderson".to_string(),
            context: random_context.clone(),
            secret: base64_secret.clone(),
            csrf_token: Some(wrong_csrf_token),
        };
        let json_secret = serde_json::to_string(&secret).unwrap();
        let request = test::TestRequest::post()
            .uri("/authenticated/secret/tell")
            .append_header(("Cookie", valid_updated_rsa_cookie.to_string()))
            .peer_addr(IP_ADDRESS.parse().unwrap())
            .set_payload(json_secret)
            .to_request();
        let result = test::call_service(&test_service, request).await;
        assert_eq!(
            result.status(),
            StatusCode::BAD_REQUEST,
            "authenticated/secret/tell should not work!"
        );
        // wrong receiver email format
        let secret = lmtyas::secret_functions::Secret {
            from_email: "bob@acme.local".to_string(),
            from_display_name: "Bob Sanders".to_string(),
            to_email: "alice@acme.world.local".to_string(),
            to_display_name: "Alice Henderson".to_string(),
            context: random_context.clone(),
            secret: base64_secret.clone(),
            csrf_token: Some(authenticated_bob.csrf_token.clone()),
        };
        let json_secret = serde_json::to_string(&secret).unwrap();
        let request = test::TestRequest::post()
            .uri("/authenticated/secret/tell")
            .append_header(("Cookie", valid_updated_rsa_cookie.to_string()))
            .peer_addr(IP_ADDRESS.parse().unwrap())
            .set_payload(json_secret)
            .to_request();
        let result = test::call_service(&test_service, request).await;
        assert_eq!(
            result.status(),
            StatusCode::BAD_REQUEST,
            "authenticated/secret/tell should not work!"
        );

        // nonexistent receiver email
        let secret = lmtyas::secret_functions::Secret {
            from_email: "bob@acme.local".to_string(),
            from_display_name: "Bob Sanders".to_string(),
            to_email: "jane@acme.local".to_string(),
            to_display_name: "Jane Doe".to_string(),
            context: random_context.clone(),
            secret: base64_secret.clone(),
            csrf_token: Some(authenticated_bob.csrf_token.clone()),
        };
        let json_secret = serde_json::to_string(&secret).unwrap();
        let request = test::TestRequest::post()
            .uri("/authenticated/secret/tell")
            .append_header(("Cookie", valid_updated_rsa_cookie.to_string()))
            .peer_addr(IP_ADDRESS.parse().unwrap())
            .set_payload(json_secret)
            .to_request();
        let result = test::call_service(&test_service, request).await;
        assert_eq!(
            result.status(),
            StatusCode::BAD_REQUEST,
            "authenticated/secret/tell should not work!"
        );
    }

    ///////////////////////////////////////////////////////////////////////////
    // Validate sent mail
    ///////////////////////////////////////////////////////////////////////////

    let mail_query_url = format!(
        "http://127.0.0.1:8025/api/v2/search?kind=containing&query={}&limit=1",
        &random_context.clone()
    );
    let mailhog_answer_body = reqwest::get(mail_query_url)
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    // remove quoted printable in the URL part
    let mailhog_answer_body = mailhog_answer_body.replace(r"=\r\n", "");
    let mailhog_answer_body = mailhog_answer_body.replace(r"=3D", "=");
    let json_root: serde_json::Value = serde_json::from_str(&mailhog_answer_body).unwrap();
    let reply_to: Option<&str> = json_root
        .get("items")
        .and_then(|value| value.get(0))
        .and_then(|value| value.get("Content"))
        .and_then(|value| value.get("Headers"))
        .and_then(|value| value.get("Reply-To"))
        .and_then(|value| value.get(0))
        .and_then(|value| value.as_str());
    assert_eq!(
        reply_to.unwrap(),
        "bob@acme.local",
        "Reply-To should be bob@acme.local!"
    );
    let to: Option<&str> = json_root
        .get("items")
        .and_then(|value| value.get(0))
        .and_then(|value| value.get("Content"))
        .and_then(|value| value.get("Headers"))
        .and_then(|value| value.get("To"))
        .and_then(|value| value.get(0))
        .and_then(|value| value.as_str());
    assert_eq!(
        to.unwrap(),
        "alice@acme.local",
        "To should be alice@acme.local!"
    );
    let from: Option<&str> = json_root
        .get("items")
        .and_then(|value| value.get(0))
        .and_then(|value| value.get("Content"))
        .and_then(|value| value.get("Headers"))
        .and_then(|value| value.get("From"))
        .and_then(|value| value.get(0))
        .and_then(|value| value.as_str());
    assert_eq!(
        from.unwrap(),
        "IT-department <do-not-reply@lmtyas.acme.home.arpa>",
        "From should be IT-department <do-not-reply@lmtyas.acme.home.arpa>!"
    );
    let wanted_subject = format!("Your new password for {}", &random_context);
    let subject: Option<&str> = json_root
        .get("items")
        .and_then(|value| value.get(0))
        .and_then(|value| value.get("Content"))
        .and_then(|value| value.get("Headers"))
        .and_then(|value| value.get("Subject"))
        .and_then(|value| value.get(0))
        .and_then(|value| value.as_str());
    assert_eq!(subject.unwrap(), wanted_subject, "Subject does not match!");
    let body: Option<&str> = json_root
        .get("items")
        .and_then(|value| value.get(0))
        .and_then(|value| value.get("Content"))
        .and_then(|value| value.get("Body"))
        .and_then(|value| value.as_str());
    let body = body.unwrap().to_string();
    let url_regex =
        regex::Regex::new(r"\bhttps://127.0.0.1:8844/html/reveal.html\?secret_id=(?<url>.+)\b")
            .unwrap();
    assert!(url_regex.is_match(&body), "URl should be in mail body!");
    let captures = url_regex.captures(&body).unwrap();
    let secret_url = captures.name("url").map_or("UNKOWN", |m| m.as_str());
    assert_ne!(secret_url, "UNKNOWN", "secret url should not be UNKNOWN!");
    println!("secret_url = {}", &secret_url);

    ///////////////////////////////////////////////////////////////////////////
    // Reveal secret
    ///////////////////////////////////////////////////////////////////////////

    // Log in Alice
    let uuid_option = application_configuration
        .shared_authenticated_users
        .write()
        .unwrap()
        .new_cookie_data_for(
            "alice",
            "Alice",
            "Henderson",
            "alice@acme.local",
            "127.0.0.1",
        );
    if uuid_option.is_none() {
        panic!("uuid for Alice expected!");
    }

    let valid_rsa_cookie = build_new_encrypted_authentication_cookie(
        &uuid_option.unwrap().to_string(),
        90,
        COOKIE_PATH,
        &application_configuration.rsa_keys_for_cookies,
    );
    // get secret
    let request = test::TestRequest::get()
        .uri(&format!("/authenticated/secret/reveal/{}", &secret_url))
        .append_header(("Cookie", valid_rsa_cookie.to_string()))
        .peer_addr(IP_ADDRESS.parse().unwrap())
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::OK,
        "/authenticated/secret/reveal/ should work!"
    );
    let body_with_secret = test::read_body(result).await;
    let secret_json = String::from_utf8(body_with_secret.to_vec()).unwrap();
    let secret: lmtyas::secret_functions::Secret = serde_json::from_str(&secret_json).unwrap();
    assert_eq!(
        secret.from_email, "bob@acme.local",
        "FromEmail should be bob@acme.local"
    );
    assert_eq!(
        secret.from_display_name, "Bob Sanders",
        "FromDisplayName should be Bob Sanders"
    );
    assert_eq!(
        secret.to_email, "alice@acme.local",
        "ToEmail should be alice@acme.local"
    );
    assert_eq!(
        secret.to_display_name, "Alice Henderson",
        "ToDisplayName should be Alice Henderson"
    );
    assert_eq!(secret.context, random_context, "Context does not match!");
    let plain_u8 = Vec::from_base64_encoded(&secret.secret).unwrap();
    let decoded_plaintext = String::from_utf8(plain_u8).unwrap();
    assert_eq!(decoded_plaintext, random_secret, "secret does not match!");

    // get secret 2nd time
    let request = test::TestRequest::get()
        .uri(&format!("/authenticated/secret/reveal/{}", &secret_url))
        .append_header(("Cookie", valid_rsa_cookie.to_string()))
        .peer_addr(IP_ADDRESS.parse().unwrap())
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::BAD_REQUEST,
        "/authenticated/secret/reveal/ should not work!"
    );
    let body = test::read_body(result).await;
    assert_eq!(
        body.try_into_bytes().unwrap(),
        "ERROR: Secret cannot be read! Already revealed?".as_bytes(),
        "/authenticated/secret/reveal/ should return ERROR: Secret cannot be read! Already revealed?!"
    );
    let request = test::TestRequest::get()
        .uri("/authenticated/secret/reveal/aW52YWxpZCBVUkw=")
        .append_header(("Cookie", valid_rsa_cookie.to_string()))
        .peer_addr(IP_ADDRESS.parse().unwrap())
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::BAD_REQUEST,
        "/authenticated/secret/reveal/ should not work!"
    );

    ///////////////////////////////////////////////////////////////////////////
    // Log in
    ///////////////////////////////////////////////////////////////////////////

    // TODO

    ///////////////////////////////////////////////////////////////////////////
    // Cleanup.
    ///////////////////////////////////////////////////////////////////////////

    remove_stored_secrets(&secrets_directory);
    common::teardown(&mut setup_singleton_lock);
}

fn remove_stored_secrets<P: AsRef<Path>>(secrets_directory: P) {
    // remove stored secrets
    for entry in std::fs::read_dir(secrets_directory).unwrap() {
        match entry {
            Err(_) => {}
            Ok(entry) => {
                let path = entry.path();
                if path.is_file() {
                    std::fs::remove_file(path).unwrap();
                }
            }
        }
    }
}
