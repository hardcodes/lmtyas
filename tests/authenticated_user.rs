use lmtyas::authenticated_user::{
    cleanup_authenticated_users_hashmap, AccessScope, MAX_AUTH_USERS,
};
use lmtyas::configuration::ApplicationConfiguration;
use std::path::Path;

const WORKSPACE_DIR: &str = env!("CARGO_MANIFEST_DIR");

#[test]
fn test_authenticated_user() {
    let application_configuration = ApplicationConfiguration::read_from_file(
        Path::new(WORKSPACE_DIR).join("conf.dev/lmtyas-config.json"),
    );
    for user_count in 1..MAX_AUTH_USERS + 1 {
        let uuid_option: Option<uuid::Uuid>;
        {
            uuid_option = application_configuration
                .shared_authenticated_users
                .write()
                .unwrap()
                .new_cookie_uuid_for(
                    &format!("_name_name_{}", user_count),
                    &format!("first_name_{}", user_count),
                    &format!("last_name_{}", user_count),
                    &format!("username{}@acme.local", user_count),
                    "127.0.0.1",
                );
        }
        if let Some(uuid) = uuid_option {
            assert!(
                user_count <= MAX_AUTH_USERS,
                "should still be able to add user {}, max: {}",
                user_count,
                MAX_AUTH_USERS
            );

            if let Some(stored_user) = application_configuration
                .shared_authenticated_users
                .read()
                .unwrap()
                .authenticated_users_hashmap
                .get(&uuid)
            {
                assert_eq!(
                    stored_user.access_scope,
                    AccessScope::User,
                    "expected access_scope User!"
                );
            } else {
                panic!("user should be in hashmap");
            }
        } else {
            assert_eq!(
                user_count,
                MAX_AUTH_USERS + 1,
                "should not be able to add more than {} users",
                MAX_AUTH_USERS
            );
        }
    }

    // wait 2 seconds, so that user entries are old enough for cleanup
    std::thread::sleep(std::time::Duration::from_secs(2));
    cleanup_authenticated_users_hashmap(&application_configuration.shared_authenticated_users, 1);

    assert_eq!(
        application_configuration
            .shared_authenticated_users
            .read()
            .unwrap()
            .authenticated_users_hashmap
            .keys()
            .len(),
        0,
        "expected zero users in hashmap"
    );

    let uuid_option: Option<uuid::Uuid>;
    {
        uuid_option = application_configuration
            .shared_authenticated_users
            .write()
            .unwrap()
            .new_cookie_uuid_for("walter", "Walter", "Linz", "walter@acme.local", "127.0.0.1");
    }
    if let Some(uuid) = uuid_option {
        if let Some(stored_user) = application_configuration
            .shared_authenticated_users
            .read()
            .unwrap()
            .authenticated_users_hashmap
            .get(&uuid)
        {
            assert_eq!(
                stored_user.access_scope,
                AccessScope::Administrator,
                "expected access_scope Administrator!"
            );
        } else {
            panic!("user should be in hashmap");
        }
    } else {
        panic!("should be able to add admin Walter");
    }
}
