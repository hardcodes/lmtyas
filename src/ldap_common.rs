extern crate env_logger;
pub use crate::login_user_trait::Login;
use crate::unsecure_string::SecureStringToUnsecureString;
use ldap3::{ldap_escape, LdapConnAsync, Scope, SearchEntry};
use log::debug;
use secstr::SecStr;
use serde::Deserialize;
use std::error::Error;
use zeroize::Zeroize;
#[cfg(feature = "ldap-auth")]
use crate::authentication_ldap::LdapAuthConfiguration;


/// Holds the configuration to access an LDAP server
/// to query user details
#[derive(Clone, Deserialize, Debug)]
pub struct LdapCommonConfiguration {
    pub url: String,
    pub base_ou: String,
    pub bind_passwd: SecStr,
    pub bind_dn: String,
    pub user_filter: String,
    pub mail_filter: String,
    #[cfg(feature = "ldap-auth")]
    pub authentication: LdapAuthConfiguration,
}

impl LdapCommonConfiguration {
    /// Performs a generic ldap search
    ///
    /// # Arguments
    ///
    /// * `filter`:         filter expression to use for the search-
    /// * `attributes`:     a vector of attributes that should be delivered as search result.
    ///
    /// # Returns
    ///
    /// - `Result<String, Box<dyn Error>>` - either the search result as json formatted string or an error
    async fn ldap_search<S: AsRef<str> + std::marker::Sync + std::marker::Send>(
        &self,
        filter: &str,
        attributes: Vec<S>,
    ) -> Result<String, Box<dyn Error>> {
        let (conn, mut ldap) = LdapConnAsync::new(&self.url).await?;
        ldap3::drive!(conn);
        debug!("Connected to {}", &&self.url);
        // the password is stored in a secure string,
        // so that a 3rd party can not scan the memory
        // to gather the precious data.
        // Nevertheless the LDAP library wants the password
        // in plaintext. It is converted here and lives only
        // for the short time of a query.
        let bind_pw = &mut self.bind_passwd.to_unsecure_string();
        ldap.simple_bind(&self.bind_dn, bind_pw)
            .await?
            .success()?;
        bind_pw.zeroize();
        debug!("ldap.simple_bind() -> OK");
        let (rs, _res) = ldap
            .search(&self.base_ou, Scope::Subtree, filter, attributes)
            .await?
            .success()?;
        let mut result = String::new();
        for entry in rs {
            let search_entry = SearchEntry::construct(entry);
            // build a string containing the whole result not unlike json.
            // Not 100% happy with this solution but for now it seems the
            // most generic approach.
            String::push_str(&mut result, &format!("{:?}", search_entry.attrs));
        }
        ldap.unbind().await?;
        debug!("result = {}", &result);
        debug!("ldap.unbind() -> OK");
        Ok(result)
    }

    /// Search uid in Ldap for basic user information attributes, such as
    /// cn, givenName, sn, mail
    ///
    /// # Arguments
    ///
    /// - `user_name`:      uid of the user that should be looked up.
    /// - `Option<filter>`: optional filter expression to use for the search. If `None` is
    ///                     given, `ldap_user_filter` will be used.
    ///
    /// # Returns
    ///
    /// - `Result<String, Box<dyn Error>>` - either the search result as json formatted string or an error
    pub async fn ldap_search_by_uid(
        &self,
        user_name: &str,
        filter: Option<&str>,
    ) -> Result<String, Box<dyn Error>> {
        let ldap_filter = match filter {
            Some(f) => f,
            None => &self.user_filter,
        };
        let filterstring = &ldap_filter.replace("{0}", &ldap_escape(user_name));
        self.ldap_search(filterstring, vec!["uid", "givenName", "sn", "mail"])
            .await
    }

    /// Search uid in Ldap for basic user information attributes, such as
    /// uid, cn, givenName, sn
    ///
    /// # Arguments
    ///
    /// - `mail     `:      mail of the user that should be looked up.
    /// - `Option<filter>`: optional filter expression to use for the search. If `None` is
    ///                     given, `ldap_user_filter` will be used.
    ///
    /// # Returns
    ///
    /// - `Result<String, Box<dyn Error>>` - either the search result as json formatted string or an error
    pub async fn ldap_search_by_mail(
        &self,
        mail: &str,
        filter: Option<&str>,
    ) -> Result<String, Box<dyn Error>> {
        let ldap_filter = match filter {
            Some(f) => f,
            None => &self.mail_filter,
        };
        let filterstring = &ldap_filter.replace("{0}", &ldap_escape(mail));
        self.ldap_search(filterstring, vec!["uid", "givenName", "sn", "mail"])
            .await
    }
}

/// Used to deserialze the ldap search result
#[derive(Deserialize, Debug)]
pub struct LdapSearchResult {
    #[serde(rename = "uid")]
    pub user_name: String,
    #[serde(rename = "givenName")]
    pub first_name: String,
    #[serde(rename = "sn")]
    pub last_name: String,
    #[serde(rename = "mail")]
    pub mail: String,
}
