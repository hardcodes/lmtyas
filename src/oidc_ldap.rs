use crate::authentication_oidc::{OidcUser, OidcUserDetails};
use crate::configuration::ApplicationConfiguration;
use async_trait::async_trait;
use std::error::Error;

/// Empty struct for trait implementation.
pub struct OidcUserLdapUserDetails;

#[async_trait(?Send)]
impl OidcUserDetails for OidcUserLdapUserDetails {
    async fn get_oidc_user_details_from_email(
        mail: &str,
        application_configuration: &ApplicationConfiguration,
    ) -> Result<OidcUser, Box<dyn std::error::Error>> {
        let ldap_search_result = match application_configuration
            .configuration_file
            .ldap_common_configuration
            .ldap_search_by_mail(mail, None)
            .await
        {
            Ok(l) => l,
            Err(e) => {
                let error_message = format!("cannot deserialize ldap result: {}", e);
                let boxed_error = Box::<dyn Error + Send + Sync>::from(error_message);
                return Err(boxed_error);
            }
        };
        // dirty hack to build a json string from the ldap query result,
        // so it can be serialized.
        let ldap_result: OidcUser = match serde_json::from_str(&ldap_search_result.replace(['[', ']'], ""))
        {
            Ok(r) => r,
            Err(e) => {
                return Err(e.into());
            }
        };
        Ok(OidcUser {
            user_name: ldap_result.user_name,
            first_name: ldap_result.first_name,
            last_name: ldap_result.last_name,
            mail: ldap_result.mail,
        })
    }
}
