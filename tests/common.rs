use lazy_static::lazy_static;
use lmtyas::CONTAINER_COMMAND;
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
    #[cfg(feature = "ldap-common")]
    glauth: Option<Child>,
    #[cfg(feature = "mail-noauth-notls")]
    mail_server: Option<Child>,
    #[cfg(feature = "oidc-auth-ldap")]
    oidc_server: Option<Child>,
}

/// common setup routine for all tests
pub fn setup(setup_lock: &mut MutexGuard<ExternalHelperApplications>) {
    // this should never happen, since caller must hold a lock.
    if setup_lock.setup_done {
        return;
    }
    #[cfg(feature = "ldap-common")]
    {
        // 1. start ldap server
        //
        // docker run \
        //     -d \
        //     --rm \
        //     --name lmtyas-glauth \
        //     -p 3893:3893 \
        //     -v ./resources/tests/ldap/ldap.conf:/app/config/config.cfg \
        //     docker.io/glauth/glauth:latest
        let glauth = Command::new(CONTAINER_COMMAND)
            .args([
                "run",
                "-d",
                "--rm",
                "--name",
                "lmtyas-glauth",
                "-p",
                "3893:3893",
                "-v",
                "./resources/tests/ldap/ldap.conf:/app/config/config.cfg",
                "docker.io/glauth/glauth:latest",
            ])
            .spawn()
            .expect("cannot start glauth ldap server");
        setup_lock.glauth = Some(glauth);
    }

    #[cfg(feature = "mail-noauth-notls")]
    {
        // 2. start dummy mail server
        //
        // docker run \
        // -d \
        // --rm \
        // --name lmtyas-mailhog \
        // -p 2525:1025 \
        // -p 8025:8025 \
        // docker.io/mailhog/mailhog:latest
        let mail_server = Command::new(CONTAINER_COMMAND)
            .args([
                "run",
                "-d",
                "--rm",
                "--name",
                "lmtyas-mailhog",
                "-p",
                "2525:1025",
                "-p",
                "8025:8025",
                "docker.io/mailhog/mailhog:latest",
            ])
            .spawn()
            .expect("cannot start dummy mail server");
        setup_lock.mail_server = Some(mail_server);
    }

    #[cfg(feature = "oidc-auth-ldap")]
    {
        // 3. start dummy oidc server
        //
        // docker run \
        //     -d \
        //     --rm \
        //     --name lmtyas-oidc \
        //     --env PORT=9090 \
        //     --env CLIENT_ID=id \
        //     --env CLIENT_SECRET=secret \
        //     --env CLIENT_REDIRECT_URI=https://127.0.0.1:8844/authentication/callback \
        //     --env CLIENT_LOGOUT_REDIRECT_URI=http://localhost:8080/.magnolia/admincentral \
        //     -p 9090:9090 \
        //     magnolia/mock-oidc-user-server:latest
        let oidc_server = Command::new(CONTAINER_COMMAND)
            .args([
                "run",
                "-d",
                "--rm",
                "--name",
                "lmtyas-oidc",
                "--env",
                "PORT=9090",
                "--env",
                "CLIENT_ID=id",
                "--env",
                "CLIENT_SECRET=secret",
                "--env",
                "CLIENT_REDIRECT_URI=https://127.0.0.1:8844/authentication/callback",
                "--env",
                "CLIENT_LOGOUT_REDIRECT_URI=http://localhost:8080/.magnolia/admincentral",
                "-p",
                "9090:9090",
                "docker.io/magnolia/mock-oidc-user-server:latest",
            ])
            .spawn()
            .expect("cannot start dummy oidc server");
        setup_lock.oidc_server = Some(oidc_server);
    }

    // give services some time to start up
    std::thread::sleep(std::time::Duration::from_secs(2));
    // done with setup
    setup_lock.setup_done = true;
}

/// common teardown routine for all tests
pub fn teardown(teardown_lock: &mut MutexGuard<ExternalHelperApplications>) {
    #[cfg(feature = "ldap-common")]
    let _stopped_ldap_server = Command::new(CONTAINER_COMMAND)
        .args(["stop", "lmtyas-glauth"])
        .spawn()
        .expect("cannot stop dummy ldap server");
    #[cfg(feature = "mail-noauth-notls")]
    let _stopped_mail_server = Command::new(CONTAINER_COMMAND)
        .args(["stop", "lmtyas-mailhog"])
        .spawn()
        .expect("cannot stop dummy mail server");
    #[cfg(feature = "oidc-auth-ldap")]
    let _stopped_oidc_server = Command::new(CONTAINER_COMMAND)
        .args(["stop", "lmtyas-oidc"])
        .spawn()
        .expect("cannot stop dummy oidc server");
    teardown_lock.setup_done = false;
    std::thread::sleep(std::time::Duration::from_secs(2));
}
