use crate::authenticated_user::cleanup_authenticated_users_hashmap;
use crate::authentication_middleware::cleanup_authentication_state_hashmap;
#[cfg(feature = "oidc-auth-ldap")]
use crate::authentication_oidc::cleanup_oidc_authentication_data_hashmap;
use crate::configuration::ApplicationConfiguration;
use timer::{Guard, Timer};

pub struct TimerGuard(Vec<(Guard, Timer)>);

/// Timer that calls a cleanup routine every 15 seconds
/// and removes used or aged authentication requests
fn build_cleanup_authentication_state_hashmap_timer(
    application_configuration: &ApplicationConfiguration,
) -> (Guard, Timer) {
    let auth_duration = application_configuration
        .configuration_file
        .max_authrequest_age_seconds;
    let cleanup_authentication_state_hashmap_timer = Timer::new();
    let authentication_state_hashmap = application_configuration.shared_request_data.clone();
    (cleanup_authentication_state_hashmap_timer
        .schedule_repeating(chrono::Duration::seconds(15), move || {
            cleanup_authentication_state_hashmap(&authentication_state_hashmap, auth_duration)
        }), cleanup_authentication_state_hashmap_timer)
}

/// Timer that calls a cleanup routine every 15 seconds
/// and removes expired user sessions
fn build_cleanup_authenticated_users_hashmap_timer(
    application_configuration: &ApplicationConfiguration,
) -> (Guard, Timer) {
    let cookie_duration = application_configuration
        .configuration_file
        .max_cookie_age_seconds;
    let cleanup_authenticated_users_hashmap_timer = Timer::new();
    let authenticated_users_hashmap = application_configuration.shared_authenticated_users.clone();
    (cleanup_authenticated_users_hashmap_timer
        .schedule_repeating(chrono::Duration::seconds(15), move || {
            cleanup_authenticated_users_hashmap(&authenticated_users_hashmap, cookie_duration)
        }), cleanup_authenticated_users_hashmap_timer)
}

/// Timer that calls a cleanup routine every 15 seconds
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
    (cleanup_oidc_authentication_state_hashmap_timer.schedule_repeating(
        chrono::Duration::seconds(15),
        move || {
            cleanup_oidc_authentication_data_hashmap(&shared_oidc_verification_data, auth_duration)
        },
    ), cleanup_oidc_authentication_state_hashmap_timer)
}

/// Build a vector of timer guards and timers to keep
/// the references until the program ends.
pub fn build_cleaup_timers(application_configuration: &ApplicationConfiguration) -> TimerGuard {
    let mut timer_guards: Vec<(Guard, Timer)> = Vec::new();
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
    TimerGuard(timer_guards)
}
