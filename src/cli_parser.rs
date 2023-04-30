use crate::PROGRAM_AUTHORS;
use crate::PROGRAM_DESCRIPTION;
use crate::PROGRAM_NAME;
use crate::PROGRAM_VERSION;

pub const ARG_CONFIG_FILE: &str = "configfile";

/// Parse the command line parameters with help of clap.
pub fn parse_cli_parameters() -> clap::ArgMatches {
    clap::Command::new(PROGRAM_NAME)
        .version(PROGRAM_VERSION)
        .author(PROGRAM_AUTHORS)
        .about(PROGRAM_DESCRIPTION)
        .arg(
            clap::Arg::new(ARG_CONFIG_FILE)
                .short('c')
                .long("config-file")
                .value_name("json configuration file")
                .help("json file with the configuration of the webservice")
                .num_args(1)
                .required(true),
        )
        .after_help(r##"See README.md for details."##)
        .get_matches()
}
