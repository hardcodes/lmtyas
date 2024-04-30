mod authenticated_user_test;
mod common;
use actix_files::Files;
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
use std::path::Path;

#[cfg(feature = "ldap-auth")]
type AuthConfiguration = LdapCommonConfiguration;
#[cfg(feature = "oidc-auth-ldap")]
type AuthConfiguration = OidcConfiguration;

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
    // Application is running.
    ///////////////////////////////////////////////////////////////////////////

    let request = test::TestRequest::get().uri("/monitoring/still_alive").to_request();
    let result = test::call_and_read_body(&test_service, request).await;
    assert_eq!(result, "System not ready!".as_bytes(), "service should not boogie!");

    let request = test::TestRequest::get().uri("/system/is_server_ready").to_request();
    let result = test::call_and_read_body(&test_service, request).await;
    assert_eq!(result, "{\"isReady\": false}".as_bytes(), "/system/is_server_ready should fail!");

    ///////////////////////////////////////////////////////////////////////////
    // Cleanup.
    ///////////////////////////////////////////////////////////////////////////
    common::teardown(&mut setup_singleton_lock);
}
