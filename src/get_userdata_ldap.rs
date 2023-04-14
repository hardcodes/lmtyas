use crate::configuration::ApplicationConfiguration;
use crate::get_userdata_trait::GetUserData;
pub use crate::ldap_common::{LdapCommonConfiguration, LdapSearchResult};
use actix_web::web;
use async_trait::async_trait;
use log::warn;

pub struct GetUserDataLdapBackend;

#[async_trait]
impl GetUserData for GetUserDataLdapBackend {
    async fn get_receiver_display_name(
        mail: &str,
        application_configuration: &web::Data<ApplicationConfiguration>,
    ) -> Result<String, String> {
        // 2. check if user exists
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
                    "can not serde_json::from_str({}): {}",
                    &ldap_search_result, &e
                );
                return Err(error_message);
            }
            Ok(r) => r,
        };
        let display_name = format!("{} {}", &ldap_result.first_name, &ldap_result.last_name);
        Ok(display_name)
    }
}
