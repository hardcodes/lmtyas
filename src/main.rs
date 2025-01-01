use lmtyas::cert_renewal::{tcp_server_loop, uds_server, UdsConfiguration};
use lmtyas::cleanup_timer::build_cleanup_timers;
use lmtyas::cli_parser::{parse_cli_parameters, ARG_CONFIG_FILE};
use lmtyas::configuration::ApplicationConfiguration;
use log::info;
use log::warn;
use std::io::Write;
use std::path::Path;

#[cfg(unix)]
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // crate env_logger is configured via the RUST_LOG environment variable
    #[cfg(debug_assertions)]
    std::env::set_var("RUST_LOG", "debug, actix_web=trace");
    #[cfg(not(debug_assertions))]
    std::env::set_var("RUST_LOG", "info, actix_web=info");
    env_logger::builder()
        .format(|buf, record| writeln!(buf, "{}: {}", record.level(), record.args()))
        .init();

    // parse cli parameters and load the configuration
    let clap_arg_matches = parse_cli_parameters();
    let config_file: String = clap_arg_matches
        .get_one::<String>(ARG_CONFIG_FILE)
        .unwrap()
        .to_string();
    let application_configuration =
        match ApplicationConfiguration::read_from_file(Path::new(&config_file)).await {
            Err(e) => {
                warn!("Cannot load application configuration: {}", &e);
                std::process::exit(1);
            }
            Ok(a) => a,
        };

    // build cleanup timers and store references to keep them running
    let timer_guards = build_cleanup_timers(&application_configuration);
    info!("started {} cleanup timers", timer_guards.len());

    match rustls::crypto::aws_lc_rs::default_provider().install_default() {
        Ok(r) => r,
        Err(_) => {
            warn!("Cannot install rusttls crypto provider.");
            std::process::exit(1);
        }
    };

    let uds_configuration =
        UdsConfiguration::new(application_configuration.tls_cert_status.clone());

    //////////////////////////////////////////////////////////
    // Here we can loop and reload certs if the server stops.
    //////////////////////////////////////////////////////////
    let tcp_server_loop_task = actix_web::rt::spawn(tcp_server_loop(
        application_configuration.clone(),
        uds_configuration.clone(),
    ));

    // Wrapper for the Unix Domain Socket server to get same result type as `tcp_server_loop_task`.
    let uds_server_task =
        actix_web::rt::spawn(uds_server(application_configuration, uds_configuration));

    // Start both servers and wait from them to stop.
    let _res = futures::future::try_join(tcp_server_loop_task, uds_server_task).await?;
    Ok(())
}
