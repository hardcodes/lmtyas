mod common;
use lmtyas::authentication_ldap::LdapSearchResult;
use lmtyas::configuration::ApplicationConfiguration;
use std::path::Path;

/// testing the ldap functions in one go,
/// so that the ldap server must only be started once.
#[actix_rt::test]
async fn test_with_setup() {
    // set up ldap and dummy mail server
    common::setup();
    // load configuration file with the ldap server connection details
    let application_configuration = ApplicationConfiguration::read_from_file(
        Path::new(common::WORKSPACE_DIR).join("conf.dev/lmtyas-config.json"),
    );

    // looking up existing user by uid in ldap
    let user_found_by_uid = application_configuration
        .configuration_file
        .ldap_configuration
        .ldap_search_by_uid(
            "bob",
            Some(
                &application_configuration
                    .configuration_file
                    .ldap_configuration
                    .ldap_user_filter,
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

    // lookin up non existing user by uid in ldap
    let user_not_found_by_uid = application_configuration
        .configuration_file
        .ldap_configuration
        .ldap_search_by_uid(
            "b0b",
            Some(
                &application_configuration
                    .configuration_file
                    .ldap_configuration
                    .ldap_user_filter,
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
        .ldap_configuration
        .ldap_search_by_mail(
            "bob@acme.local",
            Some(
                &application_configuration
                    .configuration_file
                    .ldap_configuration
                    .ldap_mail_filter,
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

    // lookin up non existing user by mail in ldap
    let user_not_found_by_mail = application_configuration
        .configuration_file
        .ldap_configuration
        .ldap_search_by_mail(
            "b0b@acme.local",
            Some(
                &application_configuration
                    .configuration_file
                    .ldap_configuration
                    .ldap_user_filter,
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

    // ldap login with correct password
    let ldap_login_success = application_configuration
        .configuration_file
        .ldap_configuration
        .ldap_login("bob", "passw0rd")
        .await;
    assert!(
        matches!(ldap_login_success, Ok(_)),
        "user bob could not login with correct password"
    );

    // ldap login with wrong password
    let ldap_login_fail = application_configuration
        .configuration_file
        .ldap_configuration
        .ldap_login("bob", "password")
        .await;
    assert!(
        matches!(ldap_login_fail, Err(_)),
        "user bob should not be able to login with wrong password"
    );

    common::teardown();
}
