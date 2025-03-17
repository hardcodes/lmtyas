use crate::configuration::ApplicationConfiguration;
use crate::get_userdata_trait::GetUserData;
pub use crate::ldap_common::{LdapCommonConfiguration, LdapSearchResult};
use actix_web::web;
use async_trait::async_trait;
use log::warn;

pub struct GetUserDataLdapBackend;

/// This trait is used to force one implementation of a get_display_name()
/// function. The implementation may change depending on the authentication
/// method used.
#[async_trait]
impl GetUserData for GetUserDataLdapBackend {
    /// This function is called when a secret is transmitted
    /// to get the display name of the receiver. At this
    /// point we only know of the email address
    async fn get_receiver_display_name(
        mail: &str,
        application_configuration: &web::Data<ApplicationConfiguration>,
    ) -> Result<String, String> {
        let ldap_search_result = match &application_configuration
            .configuration_file
            .ldap_common_configuration
            .ldap_search_by_mail(
                mail,
                Some(
                    &application_configuration
                        .configuration_file
                        .ldap_common_configuration
                        .mail_filter,
                ),
            )
            .await
        {
            Err(e) => {
                let error_message =
                    format!("error while looking up user by mail {}: {}", &mail, &e);
                warn!("{}", &error_message);
                return Err(error_message);
            }
            Ok(ldap_search_result) => ldap_search_result.clone(),
        };
        // dirty hack to build a json string from the ldap query result,
        // so it can be serialized.
        let ldap_result = match serde_json::from_str(&ldap_search_result.replace(['[', ']'], ""))
            as Result<LdapSearchResult, _>
        {
            Err(e) => {
                let error_message = format!(
                    "cannot serde_json::from_str({}): {}",
                    &ldap_search_result, &e
                );
                return Err(error_message);
            }
            Ok(r) => r,
        };
        let display_name = format!("{} {}", &ldap_result.first_name, &ldap_result.last_name);
        Ok(display_name)
    }

    /// This function is called before a secret is transmitted
    /// when the email address of the receiver is entered.
    /// An invalid email address will prevent sending the form.
    async fn validate_email_address(
        mail: &str,
        application_configuration: &web::Data<ApplicationConfiguration>,
    ) -> Result<String, String> {
        let ldap_search_result = match &application_configuration
            .configuration_file
            .ldap_common_configuration
            .ldap_search_by_mail(
                mail,
                Some(
                    &application_configuration
                        .configuration_file
                        .ldap_common_configuration
                        .mail_filter,
                ),
            )
            .await
        {
            Err(e) => {
                let error_message =
                    format!("error while looking up user by mail {}: {}", &mail, &e);
                warn!("{}", &error_message);
                return Err(error_message);
            }
            Ok(ldap_search_result) => ldap_search_result.clone(),
        };
        // dirty hack to build a json string from the ldap query result,
        // so it can be serialized.
        let ldap_result = match serde_json::from_str(&ldap_search_result.replace(['[', ']'], ""))
            as Result<LdapSearchResult, _>
        {
            Err(e) => {
                let error_message = format!(
                    "cannot serde_json::from_str({}): {}",
                    &ldap_search_result, &e
                );
                return Err(error_message);
            }
            Ok(r) => r,
        };
        Ok(ldap_result.mail)
    }
}
