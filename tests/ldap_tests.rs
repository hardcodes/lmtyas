mod common;

#[test]
fn test_ldap_server() {
    let helper_apps: Option<common::ExternalHelperApps> = common::setup();
    // TODO load config
    // Path::new(WORKSPACE_DIR).join("conf.dev/lmtyas-config.json"),
    std::thread::sleep(std::time::Duration::from_secs(5));
    assert_eq!(1, 1);
    common::teardown(helper_apps);
}