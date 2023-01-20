//#[macro_use]
extern crate env_logger;
use crate::authentication_middleware::AuthenticationRedirect;
use crate::authentication_middleware::PeerIpAddress;
use crate::authentication_middleware::UNKNOWN_PEER_IP;
use crate::configuration::ApplicationConfiguration;
use crate::cookie_functions::build_new_authentication_cookie;
use crate::get_userdata_trait::GetUserData;
use crate::http_traits::CustomHttpResponse;
pub use crate::login_user_trait::Login;
use crate::unsecure_string::SecureStringToUnsecureString;
use actix_web::{http, http::StatusCode, web, web::Bytes, HttpRequest, HttpResponse};
use async_trait::async_trait;
use ldap3::{ldap_escape, LdapConnAsync, Scope, SearchEntry};
use log::{debug, info, warn};
use regex::Regex;
use secstr::SecStr;
use serde::Deserialize;
use std::error::Error;
use uuid::Uuid;
use zeroize::Zeroize;

// maximum bytes that can be transferred as login data
const MAX_BYTES: usize = 384;
// maximum length of a password
const MAX_PASSWORD_LENGTH: usize = 128;

/// Holds the configuration to access an LDAP server
/// for user authentication
#[derive(Clone, Deserialize, Debug)]
pub struct LdapAuthConfiguration {
    pub ldap_url: String,
    pub ldap_base_ou: String,
    pub ldap_bind_passwd: SecStr,
    pub ldap_bind_dn: String,
    pub ldap_user_filter: String,
    pub ldap_mail_filter: String,
    pub ldap_bind_user_dn: String,
    pub valid_user_regex: String,
    #[serde(skip_deserializing)]
    user_regex: Option<Regex>,
}

impl LdapAuthConfiguration {
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
        let (conn, mut ldap) = LdapConnAsync::new(&self.ldap_url).await?;
        ldap3::drive!(conn);
        debug!("Connected to {}", &&self.ldap_url);
        // the password is stored in a secure string,
        // so that a 3rd party can not scan the memory
        // to gather the precious data.
        // Nevertheless the LDAP library wants the password
        // in plaintext. It is converted here and lives only
        // for the short time of a query.
        let bind_pw = &mut self.ldap_bind_passwd.to_unsecure_string();
        ldap.simple_bind(&self.ldap_bind_dn, bind_pw)
            .await?
            .success()?;
        bind_pw.zeroize();
        debug!("ldap.simple_bind() -> OK");
        let (rs, _res) = ldap
            .search(&self.ldap_base_ou, Scope::Subtree, filter, attributes)
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
            None => &self.ldap_user_filter,
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
            None => &self.ldap_mail_filter,
        };
        let filterstring = &ldap_filter.replace("{0}", &ldap_escape(mail));
        self.ldap_search(filterstring, vec!["uid", "givenName", "sn", "mail"])
            .await
    }

    /// Bind to the ldap server with the given user and password,
    /// AKA login
    ///
    /// # Arguments
    ///
    /// - `user_name`:      uid of the user that should be looked up.
    /// - `password`:       password used to bind
    ///
    /// # Returns
    ///
    /// - `Result<(), Box<dyn Error>>` - either Ok() or an error
    async fn ldap_login(&self, user_name: &str, password: &str) -> Result<(), Box<dyn Error>> {
        let (conn, mut ldap) = LdapConnAsync::new(&self.ldap_url).await?;
        ldap3::drive!(conn);
        debug!("Connected to {}", &&self.ldap_url);
        ldap.simple_bind(
            &self
                .ldap_bind_user_dn
                .replace("{0}", &ldap_escape(user_name)),
            password,
        )
        .await?
        .success()?;
        debug!("ldap.simple_bind() -> OK");
        Ok(ldap.unbind().await?)
    }
}

/// Data that gets POSTed when
/// a user logs in
#[derive(Deserialize, Debug)]
pub struct LoginData {
    #[serde(rename = "LoginName")]
    pub login_name: String,
    #[serde(rename = "LoginPassword")]
    pub login_password: String,
    #[serde(rename = "RequestId")]
    pub request_id: String,
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

#[async_trait(?Send)]
impl Login for LdapAuthConfiguration {
    async fn login_user(
        bytes: Bytes,
        request: HttpRequest,
        application_configuration: web::Data<ApplicationConfiguration>,
    ) -> HttpResponse {
        debug!("bytes = {:?}", &bytes);
        debug!("request = {:?}", &request);
        let peer_ip = Peer::get_peer_ip_address(&request);
        debug!("peer_address = {:?}", &peer_ip);
        // 1. validate input
        //
        //
        if bytes.len() > MAX_BYTES {
            return HttpResponse::err_text_response(format!(
                "ERROR: more than {} bytes of data sent",
                &MAX_BYTES
            ));
        }
        let bytes_vec = bytes.to_vec();
        let form_data = match String::from_utf8(bytes_vec) {
            Ok(form_data) => form_data,
            Err(_) => {
                return HttpResponse::err_text_response("ERROR: invalid utf8 in form data");
            }
        };
        let mut parsed_form_data = match serde_json::from_str(&form_data) as Result<LoginData, _> {
            Ok(parsed_form_data) => parsed_form_data,
            Err(_) => {
                return HttpResponse::err_text_response("ERROR: could not parse json form data");
            }
        };
        debug!("parsed_form_data={:?}", &parsed_form_data);
        // is the login_name valid?
        // prevent sending bogus data to the ldap server.
        if !&application_configuration
            .configuration_file
            .ldap_configuration
            .user_regex
            .is_some()
        {
            return HttpResponse::err_text_response("ERROR: valid user regex is not defined");
        }
        let valid_user_regex = application_configuration
            .configuration_file
            .ldap_configuration
            .user_regex
            .as_ref()
            .unwrap();
        if !valid_user_regex.is_match(&parsed_form_data.login_name) {
            return HttpResponse::err_text_response("ERROR: invalid login name format");
        }
        if parsed_form_data.login_password.len() > MAX_PASSWORD_LENGTH {
            return HttpResponse::err_text_response("ERROR: password is too long!");
        }
        // what ID was assigned to the resource request?
        let request_id = match Uuid::parse_str(&parsed_form_data.request_id) {
            Ok(request_id) => request_id,
            Err(_) => {
                return HttpResponse::err_text_response("ERROR: cannot parse request id");
            }
        };
        debug!("request_id = {}", &request_id.to_string());
        // what url/resource has been requested before login?
        let url_requested;
        {
            // sending of the async ldap queries with the RwLock still locked
            // is not possible, so we will close it right after accessing
            // the data
            let mut auth_state_write_lock = application_configuration
                .shared_request_data
                .write()
                .unwrap();
            let auth_request = match auth_state_write_lock
                .authentication_state_hashmap
                .get_mut(&request_id)
            {
                None => {
                    warn!("login with invalid request id {}", &request_id);
                    return HttpResponse::err_text_response(
                        "ERROR: invalid request id, login expired",
                    );
                }
                Some(a) => a,
            };
            if auth_request.has_been_used {
                warn!(
                    "id {} has already been used, possible replay attack!",
                    &request_id
                );
                return HttpResponse::err_text_response("ERROR: login failed");
            } else {
                // mark resource request as used so that this ID cannot be used anymore
                auth_request.has_been_used = true;
                url_requested = auth_request.url_requested.clone();
            }
            // is authentication taking place from the same ip address as the resource request?
            if peer_ip.ne(&auth_request.peer_ip) {
                warn!(
                    "IP address changed since resource request: peer_address = {:?}, auth_request = {}",
                    &peer_ip, &auth_request
                );
                return HttpResponse::err_text_response("ERROR: login failed");
            }
        }

        // input data is validated and
        // uuid of the request has been found
        // let ldap_search_result;
        // {
        // 2. check if user exists
        // keep it in a block to make the compiler happy
        // because of the result lifetime
        //
        //
        let ldap_search_result = match &application_configuration
            .configuration_file
            .ldap_configuration
            .ldap_search_by_uid(
                &parsed_form_data.login_name,
                Some(
                    &application_configuration
                        .configuration_file
                        .ldap_configuration
                        .ldap_user_filter,
                ),
            )
            .await
        {
            Err(e) => {
                warn!(
                    "error while looking up user {}: {}",
                    &parsed_form_data.login_name, &e
                );
                return HttpResponse::err_text_response("ERROR: login failed");
            }
            Ok(l) => l.clone(),
        };
        // dirty hack to build a json string from the ldap query result,
        // so it can be serialized.
        let ldap_result = match serde_json::from_str(&ldap_search_result.replace(['[', ']'], ""))
            as Result<LdapSearchResult, _>
        {
            Err(e) => {
                warn!(
                    "can not serde_json::from_str({}): {}",
                    &ldap_search_result, &e
                );
                return HttpResponse::err_text_response("ERROR: login failed");
            }
            Ok(r) => r,
        };
        if ldap_result.user_name != parsed_form_data.login_name {
            warn!(
                "user {} does not exist in ldap",
                &parsed_form_data.login_name
            );
            return HttpResponse::err_text_response("ERROR: login failed");
        }

        // 3. try to bind with the given password, AKA login
        //
        //
        info!(
            "user {} exists in ldap, trying bind...",
            &parsed_form_data.login_name
        );
        // the password was encoded before the transfer to make sure
        // that special characters would be transferred correctly.
        // tested with
        // PASS!"§$%&/()=?ß\´`+*~'#-_.:,;<>|WORD
        let mut base64_decoded_password =
            match String::from_utf8(base64::decode(&parsed_form_data.login_password).unwrap()) {
                Ok(decoded_password) => decoded_password.trim_matches(char::from(0)).to_string(),
                Err(e) => {
                    warn!(
                        "could not base64 decode password from user {}: {}",
                        &parsed_form_data.login_name, &e
                    );
                    return HttpResponse::err_text_response("ERROR: login not possible");
                }
            };
        parsed_form_data.login_password.zeroize();
        match &application_configuration
            .configuration_file
            .ldap_configuration
            .ldap_login(&parsed_form_data.login_name, &base64_decoded_password)
            .await
        {
            Err(e) => {
                base64_decoded_password.zeroize();
                warn!(
                    "user {} could not log in: {}",
                    &parsed_form_data.login_name, &e
                );
                return HttpResponse::err_text_response("ERROR: login failed");
            }
            Ok(_) => {
                base64_decoded_password.zeroize();
                info!("login success for user {}", &parsed_form_data.login_name);

                if let Some(cookie_uuid) = application_configuration
                    .shared_authenticated_users
                    .write()
                    .unwrap()
                    .new_cookie_uuid_for(
                        &parsed_form_data.login_name,
                        &ldap_result.first_name,
                        &ldap_result.last_name,
                        &ldap_result.mail,
                        &peer_ip,
                    )
                {
                    let rsa_read_lock = application_configuration.rsa_keys.read().unwrap();
                    // when the rsa key pair already has been loaded,
                    // the cookie value is encrypted with the rsa public
                    // key otherwise its simply base64 encoded.
                    let cookie = build_new_authentication_cookie(
                        &cookie_uuid.to_string(),
                        application_configuration
                            .configuration_file
                            .max_cookie_age_seconds,
                        &application_configuration.configuration_file.get_domain(),
                        &rsa_read_lock,
                    );
                    let proto_fqdn = format!(
                        "https://{}",
                        &application_configuration.configuration_file.fqdn
                    );
                    let redirect_url = format!("{}{}", &proto_fqdn, &url_requested);
                    debug!("redirect_url = {:?}", &redirect_url);
                    // set authentication cookie and answer
                    // with url to open.
                    return HttpResponse::ok_text_response_with_cookie(redirect_url, cookie);
                } else {
                    warn!(
                        "cannot create cookie id for user {}",
                        &parsed_form_data.login_name
                    );
                    return HttpResponse::err_text_response("ERROR: login failed");
                }
            }
        }
    }

    fn build_valid_user_regex(&mut self) -> Result<(), Box<dyn Error>> {
        let user_regex = Regex::new(&self.valid_user_regex)?;
        self.user_regex = Some(user_regex);
        Ok(())
    }
}

impl AuthenticationRedirect for LdapAuthConfiguration {
    fn get_authentication_redirect_response(
        _request_path_with_query: &str,
        request_uuid: &Uuid,
        application_configuration: &ApplicationConfiguration,
    ) -> HttpResponse {
        let redirect_url = format!(
            "https://{}/authentication/ldap/ldap.html?request={}",
            &application_configuration.configuration_file.fqdn,
            &request_uuid.to_string()
        );
        debug!(
            "get_authentication_redirect_response() => {}",
            &redirect_url
        );
        let authentication_redirect_response = HttpResponse::build(StatusCode::SEE_OTHER)
            .append_header((http::header::LOCATION, redirect_url))
            .append_header(("Access-Control-Allow-Origin", "*"))
            .finish();
        authentication_redirect_response
    }
}

#[async_trait]
impl GetUserData for LdapAuthConfiguration {
    async fn get_display_name(
        mail: &str,
        application_configuration: &web::Data<ApplicationConfiguration>,
    ) -> Result<String, String> {
        // 2. check if user exists
        let ldap_search_result = match &application_configuration
            .configuration_file
            .ldap_configuration
            .ldap_search_by_mail(
                mail,
                Some(
                    &application_configuration
                        .configuration_file
                        .ldap_configuration
                        .ldap_mail_filter,
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

struct Peer;

impl PeerIpAddress for Peer {
    fn get_peer_ip_address(request: &HttpRequest) -> String {
        match request.peer_addr() {
            None => UNKNOWN_PEER_IP.to_string(),
            Some(s) => s.ip().to_string(),
        }
    }
}
