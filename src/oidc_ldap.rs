use crate::authentication_oidc::{OidcUser, OidcUserDetails};
use crate::configuration::ApplicationConfiguration;
use async_trait::async_trait;

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
                return Err(format!("cannot deserialize ldap result: {}", e).into());
            }
        };
        // dirty hack to build a json string from the ldap query result,
        // so it can be serialized.
        let ldap_result: OidcUser =
            serde_json::from_str(&ldap_search_result.replace(['[', ']'], ""))?;
        Ok(OidcUser {
            user_name: ldap_result.user_name,
            first_name: ldap_result.first_name,
            last_name: ldap_result.last_name,
            mail: ldap_result.mail,
        })
    }
}
