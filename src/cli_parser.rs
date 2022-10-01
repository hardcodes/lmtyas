use crate::PROGRAM_AUTHORS;
use crate::PROGRAM_DESCRIPTION;
use crate::PROGRAM_NAME;
use crate::PROGRAM_VERSION;

/// Parse the command line parameters with help of clap.
pub fn parse_cli_parameters() -> clap::ArgMatches {
    let arg_matches = clap::App::new(PROGRAM_NAME)
        .version(PROGRAM_VERSION)
        .author(PROGRAM_AUTHORS)
        .about(PROGRAM_DESCRIPTION)
        .arg(
            clap::Arg::with_name("configfile")
                .short('c')
                .long("--config-file")
                .value_name("json configuration file")
                .help("json file with the configuration of the webservice")
                .takes_value(true)
                .required(true),
        )
        .after_help(
            r##"Here is an example of a working configuration file:

{
    "web_bind_address": "127.0.0.1:8844",
    "ssl_private_key_file": "ignore/lmtyas-selfsigned.key",
    "ssl_certificate_chain_file": "ignore/lmtyas-selfsigned-cert.pem",
    "rsa_private_key_file": "ignore/lmtyas_rsa_private.key",
    "rsa_public_key_file": "ignore/lmtyas_rsa_public.key",
    "secret_directory": "ignore/secrets",
    "email_configuration" : {
        "mail_server_address": "127.0.0.1",
        "mail_server_port": 2525,
        "mail_from": "IT-department <do-not-reply@acme.local>",
        "mail_subject": "Your new password for {Context}",
        "mail_template_file": "conf.dev/mailtemplate.txt"
    },
    "admin_accounts": ["walter"],
    "max_authrequest_age_seconds": 300,
    "max_cookie_age_seconds": 90,
    "fqdn": "127.0.0.1:8844",
    "ldap_configuration": {
        "ldap_url": "ldap://127.0.0.1:3893",
        "ldap_base_ou": "ou=superheros,dc=acme,dc=local",
        "ldap_bind_passwd": "ldapsecr3t",
        "ldap_bind_dn": "cn=ldap-tec-user,ou=svcaccts,dc=acme,dc=local",
        "ldap_user_filter": "(uid={0})",
        "ldap_mail_filter": "(mail={0})",
        "ldap_bind_user_dn": "cn={0},ou=superheros,dc=acme,dc=local",
        "valid_user_regex": "^[\\w\\d\\-]{3,8}"
    },
    "login_hint": "A.C.M.E. LDAP account",
    "mail_hint": "firstname.lastname@acme.local",
    "imprint": {
        "href": "https://www.acme.local",
        "target": "_blank"
    }
}"##,
        )
        .get_matches();
    arg_matches
}
