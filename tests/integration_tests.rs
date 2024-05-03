mod authenticated_user_test;
mod common;
use actix_files::Files;
use actix_http::StatusCode;
use actix_web::{guard, middleware, test, web, App, HttpResponse};
use common::SETUP_SINGLETON;
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
use lmtyas::base64_trait::Base64StringConversions;
use lmtyas::configuration::ApplicationConfiguration;
use lmtyas::handler_functions::*;
#[cfg(any(feature = "ldap-auth", feature = "oidc-auth-ldap"))]
use lmtyas::ldap_common::LdapSearchResult;
use lmtyas::log_functions::extract_request_path;
use lmtyas::login_user_trait::Login;
#[cfg(feature = "mail-noauth-notls")]
pub use lmtyas::mail_noauth_notls::SendEMail;
#[cfg(feature = "oidc-auth-ldap")]
use lmtyas::oidc_ldap::OidcUserLdapUserDetails;
use lmtyas::MAX_FORM_BYTES_LEN;
use secstr::SecStr;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

#[cfg(feature = "ldap-auth")]
type AuthConfiguration = LdapCommonConfiguration;
#[cfg(feature = "oidc-auth-ldap")]
type AuthConfiguration = OidcConfiguration;

const WORKSPACE_DIR: &str = env!("CARGO_MANIFEST_DIR");

/// testing the functions that need external services in one go.
#[actix_web::test]
async fn with_setup() {
    let mut setup_singleton_lock = SETUP_SINGLETON.lock().await;
    // set up external helper services, like e.g. ldap and dummy mail server
    common::setup(&mut setup_singleton_lock);
    assert!(
        setup_singleton_lock.setup_done,
        "setup is not done, cannot run tests!"
    );

    // load configuration file with the ldap server connection details
    let application_configuration = ApplicationConfiguration::read_from_file(
        Path::new(common::WORKSPACE_DIR).join("resources/config/lmtyas-config.json"),
    )
    .await;

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
            matches!(send_mail_ok, Ok(_)),
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
            matches!(send_mail_fail2, Err(_)),
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
            matches!(send_mail_fail3, Err(_)),
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
            matches!(user_not_found_by_uid_result, Err(_)),
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
            matches!(user_not_found_by_mail_result, Err(_)),
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
        "System not ready!".as_bytes(),
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
        "{\"href\":\"https://www.acme.local\",\"target\":\"_blank\"}".as_bytes(),
        "wrong response from /system/get/imprint-link!"
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

    let request = test::TestRequest::get().uri("/index.html").to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::OK,
        "/index.html should be 200!"
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
        .uri("/authenticated/sysop/set_password_for_rsa_rivate_key/MTIzNDU2Nzg5MDEyMzQ=")
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::FOUND,
        "/authenticated/sysop/set_password_for_rsa_rivate_key/ should redirect!"
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
        .uri("/authenticated/js/sysop.js")
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::FOUND,
        "/authenticated/js/sysop.js should redirect!"
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
        let rsa_keys_read_lock = application_configuration.rsa_keys.read().unwrap();
        if rsa_keys_read_lock.rsa_private_key.is_some() {
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
    const PLAINTEXT: &str = r#"PASS!"§$%&/()=?ß\´`+*~'#-_.:,;<>|WORD"#;
    const CONTEXT: &str = "TESTING LMTYAS";
    const IP_ADDRESS: &str = "127.0.0.1:9876";
    const IP_ADDRESS_BAD: &str = "1.2.3.4:9876";
    let base64_secret = PLAINTEXT.to_base64_encoded();
    let secret = lmtyas::secret_functions::Secret {
        from_email: "".to_string(),
        from_display_name: "".to_string(),
        to_email: "alice@acme.local".to_string(),
        to_display_name: "".to_string(),
        context: CONTEXT.to_string(),
        secret: base64_secret,
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
    let secure_rsa_passphrase = SecStr::from(RSA_PASSPHRASE);
    {
        let mut rsa_keys_write_lock = application_configuration.rsa_keys.write().unwrap();
        if let Err(e) = rsa_keys_write_lock.read_from_files(
            Path::new(WORKSPACE_DIR).join("resources/tests/rsa/lmtyas_rsa_private.key"),
            Path::new(WORKSPACE_DIR).join("resources/tests/rsa/lmtyas_rsa_public.key"),
            &secure_rsa_passphrase,
        ) {
            panic!("cannot load rsa keys! {}", &e);
        };
    }

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

    // decodes to b800066c-028d-411f-b269-88b041774690 (non existent file on server side)
    const BAD_JTI: &str = "uTDqmTHf2rACPA7ty+wtxLYBJLcVmruDdwfXsmKfoawYrm0j55fD1SX9KTzw2XBquf0wrhjExAI0P5AERtMx4jIAcazbWzY7XvMD6QfRfjonx9km7TDa8d1WrjcpDR2lqZxCkoPUE09UfuynaCc8gCfnoPJQEa9TI3oRzFvtmzvoVFlBucjJxVBwcvlY0aYhwLtxRxX2KDKT3cbkxfASR7FXLVY8SlCfD5UomiIvXF6Z7L+nQnZNNSML0/SlIREzfgRaqoHeBN94mwRyaNP8of0CtzA55zOvNgyV7pXZbGbPvBT4QiN/eHfwIsI9hObZx0SRPWIU97ipSgINBlSB9BE3JBiQFGkY8OonugVhbQ12nNlNNgW14IiLZ3pWpi1YfJr0pvKJL3YznAdN6eOesFd8WnMBlxgtASAuXqhg2qZqfLnNM36jC4wzbq7UXU5i3Vk9PF9QItt2QhZTfS4jdRWLdJxbvMkhszRBLObIR0vRugZY5N8Nh7kSndTZcGgVtkjemrqxSFjRr/4WCAjT5Qry8/4DCs1RRzy8b4MKvF9SNbGM+aFfxOSO+si7rhywwzNRWwMVW0oTCEeBTwNfe2paC16/CwBxMHH3g5/FnHSP5Awl6taPiihCDB6G9g/3B/Py6md4++QtSIs4E+2j6k41QlRezTBPzWBe/IlpWD8=";
    let mut bearer_token_bad = access_token.clone();
    bearer_token_bad.jti = BAD_JTI.to_string();
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
        "/api/v1/secret should not work (bad nbf)!"
    );

    let mut bearer_token_bad = access_token.clone();
    bearer_token_bad.exp = 4070818800; // Dec 31 2098
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
        "/api/v1/secret should not work (bad exp)!"
    );

    ///////////////////////////////////////////////////////////////////////////
    // Testing setting of RSA password
    ///////////////////////////////////////////////////////////////////////////

    // keys have been set in previous steps
    {
        let rsa_keys_read_lock = application_configuration.rsa_keys.read().unwrap();
        if rsa_keys_read_lock.rsa_private_key.is_none() {
            panic!("rsa private key should have been loaded at this point!");
        }
    }
    {
        // We replace `RsaKeys` with a new (empty) version
        let mut rsa_keys_write_lock = application_configuration.rsa_keys.write().unwrap();
        let _old_keys = std::mem::take(&mut *rsa_keys_write_lock);
    }
    {
        let rsa_keys_read_lock = application_configuration.rsa_keys.read().unwrap();
        if rsa_keys_read_lock.rsa_private_key.is_some() {
            panic!("rsa private key should not have been loaded at this point!");
        }
    }
    // Log in walter
    let uuid_option = application_configuration
        .shared_authenticated_users
        .write()
        .unwrap()
        .new_cookie_uuid_for("walter", "Walter", "Linz", "walter@acme.local", "127.0.0.1");
    if uuid_option.is_none() {
        panic!("uuid for Walter expected!");
    }

    let cookie = format!(
        "{}={}",
        &lmtyas::cookie_functions::COOKIE_NAME,
        &uuid_option.unwrap().to_string().to_base64_encoded()
    );
    // "wrong passw0rd"
    let request = test::TestRequest::post()
        .uri("/authenticated/sysop/set_password_for_rsa_rivate_key/d3JvbmcgcGFzc3cwcmQ=")
        .append_header(("Cookie", cookie.clone()))
        .peer_addr(IP_ADDRESS.parse().unwrap())
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::BAD_REQUEST,
        "/authenticated/sysop/set_password_for_rsa_rivate_key/ should not work!"
    );
    // "12345678901234"
    let request = test::TestRequest::post()
        .uri("/authenticated/sysop/set_password_for_rsa_rivate_key/MTIzNDU2Nzg5MDEyMzQ=")
        .append_header(("Cookie", cookie.clone()))
        .peer_addr(IP_ADDRESS.parse().unwrap())
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::OK,
        "/authenticated/sysop/set_password_for_rsa_rivate_key/ should work!"
    );
    {
        let rsa_keys_read_lock = application_configuration.rsa_keys.read().unwrap();
        if rsa_keys_read_lock.rsa_private_key.is_none() {
            panic!("rsa private key should have been loaded at this point!");
        }
    }
    // keys are loaded, base64 encoded cookie is not enough:
    let request = test::TestRequest::get()
        .uri("/authenticated/user/get/details/from")
        .append_header(("Cookie", cookie))
        .peer_addr(IP_ADDRESS.parse().unwrap())
        .to_request();
    let result = test::call_service(&test_service, request).await;
    assert_eq!(
        result.status(),
        StatusCode::FOUND,
        "/authenticated/user/get/details/from should redirect!"
    );

    // TODO: authentication routes

    ///////////////////////////////////////////////////////////////////////////
    // Cleanup.
    ///////////////////////////////////////////////////////////////////////////
    common::teardown(&mut setup_singleton_lock);
}
