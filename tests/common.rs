use lazy_static::lazy_static;
use std::path::Path;
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};

pub const WORKSPACE_DIR: &str = env!("CARGO_MANIFEST_DIR");

lazy_static! {
    static ref SETUP_SINGLETON: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
}

pub struct ExternalHelperApps {
    glauth: Option<Child>,
    mail_server: Option<Child>,
}

/// common setup routine for all tests
pub fn setup() -> Option<ExternalHelperApps> {
    let mut helper_apps = ExternalHelperApps { glauth: None, mail_server: None };
    //make sure that setup is only done once
    let mut setup_lock = SETUP_SINGLETON.lock().unwrap();
    if *setup_lock != false {
        return None;
    }
    // starting with test setup
    //
    // 1. start ldap server
    //
    //    `glauth -c conf.dev/ldap.conf`
    let glauth = Command::new("glauth")
        .args([
            "-c",
            Path::new(WORKSPACE_DIR)
                .join("conf.dev/ldap.conf")
                .to_str()
                .unwrap(),
        ])
        .spawn()
        .expect("cannot start glauth ldap server");
    helper_apps.glauth = Some(glauth);
    // 2. start dummy mail server
    //
    //    `python3 -m smtpd -n -c DebuggingServer 127.0.0.1:2525`
    let mail_server = Command::new("python3")
        .args([
            "-m",
            "smtpd",
            "-n",
            "-c",
            "DebuggingServer",
            "127.0.0.1:2525"
        ])
        .spawn()
        .expect("cannot start dummy mail server");
    helper_apps.mail_server = Some(mail_server);
    // done with setup
    *setup_lock = true;
    Some(helper_apps)
}

/// common teardown routine for all tests
pub fn teardown(helper_apps: Option<ExternalHelperApps>) {
    if let Some(h) = helper_apps {
        h.glauth.unwrap().kill().expect("glauth was not running");
        h.mail_server.unwrap().kill().expect("dummy mail server was not running");
    }
}
