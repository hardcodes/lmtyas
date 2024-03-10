mod common;
use common::SETUP_SINGLETON;
#[cfg(feature = "ldap-auth")]
pub use lmtyas::authentication_ldap::LdapLogin;
#[cfg(feature = "oidc-auth-ldap")]
use lmtyas::authentication_oidc::OidcUserDetails;
use lmtyas::configuration::ApplicationConfiguration;
#[cfg(any(feature = "ldap-auth", feature = "oidc-auth-ldap"))]
use lmtyas::ldap_common::LdapSearchResult;
#[cfg(feature = "mail-noauth-notls")]
pub use lmtyas::mail_noauth_notls::SendEMail;
#[cfg(feature = "oidc-auth-ldap")]
use lmtyas::oidc_ldap::OidcUserLdapUserDetails;

use std::path::Path;

/// testing the functions that need external services in one go.
#[actix_rt::test]
async fn with_setup() {
    // load configuration file with the ldap server connection details
    let application_configuration = ApplicationConfiguration::read_from_file(
        Path::new(common::WORKSPACE_DIR).join("resources/config/lmtyas-config.json"),
    )
    .await;

    // test sending mail before the server is has been started
    let send_mail_fail = application_configuration
        .configuration_file
        .email_configuration
        .send_mail(
            "alice@acme.local",
            "bob@acme.local",
            "mail_subject",
            "mail_body",
        );
    assert!(
        matches!(send_mail_fail, Err(_)),
        "should not be able to send mails without server running"
    );

    let mut setup_singleton_lock = SETUP_SINGLETON.lock().await;
    // set up ldap and dummy mail server
    common::setup(&mut setup_singleton_lock);
    assert!(
        setup_singleton_lock.setup_done,
        "setup is not done, cannot run tests!"
    );

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
    }

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
    }

    common::teardown(&mut setup_singleton_lock);
}
