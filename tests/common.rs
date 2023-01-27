use lazy_static::lazy_static;
use std::path::Path;
use std::process::{Child, Command};
use std::sync::Arc;
use tokio::sync::{Mutex, MutexGuard};

pub const WORKSPACE_DIR: &str = env!("CARGO_MANIFEST_DIR");

lazy_static! {
    pub static ref SETUP_SINGLETON: Arc<Mutex<ExternalHelperApplications>> =
        Arc::new(Mutex::new(ExternalHelperApplications {
            setup_done: false,
            ..Default::default()
        }));
}

#[derive(Default)]
pub struct ExternalHelperApplications {
    pub setup_done: bool,
    glauth: Option<Child>,
    mail_server: Option<Child>,
}

/// common setup routine for all tests
pub fn setup(setup_lock: &mut MutexGuard<ExternalHelperApplications>) {
    // this should never happen, since caller must hold a lock.
    if setup_lock.setup_done {
        return;
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
    setup_lock.glauth = Some(glauth);
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
            "127.0.0.1:2525",
        ])
        .spawn()
        .expect("cannot start dummy mail server");
    setup_lock.mail_server = Some(mail_server);
    // give services some time to start up
    std::thread::sleep(std::time::Duration::from_secs(2));
    // done with setup
    setup_lock.setup_done = true;
}

/// common teardown routine for all tests
pub fn teardown(teardown_lock: &mut MutexGuard<ExternalHelperApplications>) {
    teardown_lock
        .glauth
        .as_mut()
        .unwrap()
        .kill()
        .expect("glauth was not running");
    teardown_lock
        .mail_server
        .as_mut()
        .unwrap()
        .kill()
        .expect("dummy mail server was not running");
    teardown_lock.setup_done = false;
}
