use crate::authenticated_user::cleanup_authenticated_users_hashmap;
use crate::authentication_middleware::cleanup_authentication_state_hashmap;
#[cfg(feature = "oidc-auth-ldap")]
use crate::authentication_oidc::cleanup_oidc_authentication_data_hashmap;
use crate::configuration::ApplicationConfiguration;
use crate::TIMER_VEC_CAPACITY;
use log::info;
use timer::{Guard, Timer};

const TIMER_INTERVAL_SECONDS: i64 = 5;
pub struct TimerGuard(Vec<(Guard, Timer)>);

impl TimerGuard {
    /// Return the number of stored timers.
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        0 == self.0.len()
    }
}

/// Timer that calls a cleanup routine every TIMER_INTERVAL_SECONDS
/// and removes used or aged authentication requests
fn build_cleanup_authentication_state_hashmap_timer(
    application_configuration: &ApplicationConfiguration,
) -> (Guard, Timer) {
    let auth_duration = application_configuration
        .configuration_file
        .max_authrequest_age_seconds;
    let cleanup_authentication_state_hashmap_timer = Timer::new();
    let authentication_state_hashmap = application_configuration.shared_request_data.clone();
    (
        cleanup_authentication_state_hashmap_timer.schedule_repeating(
            chrono::Duration::try_seconds(TIMER_INTERVAL_SECONDS).unwrap(),
            move || {
                cleanup_authentication_state_hashmap(&authentication_state_hashmap, auth_duration)
            },
        ),
        cleanup_authentication_state_hashmap_timer,
    )
}

/// Timer that calls a cleanup routine every TIMER_INTERVAL_SECONDS
/// and removes expired user sessions
fn build_cleanup_authenticated_users_hashmap_timer(
    application_configuration: &ApplicationConfiguration,
) -> (Guard, Timer) {
    let cookie_duration = application_configuration
        .configuration_file
        .max_cookie_age_seconds;
    let cleanup_authenticated_users_hashmap_timer = Timer::new();
    let authenticated_users_hashmap = application_configuration.shared_authenticated_users.clone();
    (
        cleanup_authenticated_users_hashmap_timer.schedule_repeating(
            chrono::Duration::try_seconds(TIMER_INTERVAL_SECONDS).unwrap(),
            move || {
                cleanup_authenticated_users_hashmap(&authenticated_users_hashmap, cookie_duration)
            },
        ),
        cleanup_authenticated_users_hashmap_timer,
    )
}

/// Timer that calls a cleanup routine every TIMER_INTERVAL_SECONDS
/// and removes used or aged oidc authentication requests
#[cfg(feature = "oidc-auth-ldap")]
fn build_cleanup_oidc_authentication_state_hashmap_timer(
    application_configuration: &ApplicationConfiguration,
) -> (Guard, Timer) {
    let auth_duration = application_configuration
        .configuration_file
        .max_authrequest_age_seconds;
    let cleanup_oidc_authentication_state_hashmap_timer = Timer::new();
    let shared_oidc_verification_data = application_configuration
        .shared_oidc_verification_data
        .clone();
    (
        cleanup_oidc_authentication_state_hashmap_timer.schedule_repeating(
            chrono::Duration::try_seconds(TIMER_INTERVAL_SECONDS).unwrap(),
            move || {
                cleanup_oidc_authentication_data_hashmap(
                    &shared_oidc_verification_data,
                    auth_duration,
                )
            },
        ),
        cleanup_oidc_authentication_state_hashmap_timer,
    )
}

/// Build a vector of timer guards and timers to
/// hold on the references until the program ends.
pub fn build_cleaup_timers(application_configuration: &ApplicationConfiguration) -> TimerGuard {
    let mut timer_guards: Vec<(Guard, Timer)> = Vec::with_capacity(TIMER_VEC_CAPACITY);
    timer_guards.push(build_cleanup_authentication_state_hashmap_timer(
        application_configuration,
    ));
    timer_guards.push(build_cleanup_authenticated_users_hashmap_timer(
        application_configuration,
    ));
    #[cfg(feature = "oidc-auth-ldap")]
    timer_guards.push(build_cleanup_oidc_authentication_state_hashmap_timer(
        application_configuration,
    ));
    info!("started {} cleanup timers", TIMER_VEC_CAPACITY);
    TimerGuard(timer_guards)
}
