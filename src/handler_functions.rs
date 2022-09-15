//#[macro_use]
extern crate env_logger;
use crate::aes_functions::{DecryptAes, EncryptAes};
use crate::authenticated_user::{AuthenticatedAdministrator, AuthenticatedUser};
use crate::authentication_functions::{
    get_authenticated_user, update_authenticated_user_cookie_lifetime,
};
#[cfg(feature = "ldap-auth")]
use crate::authentication_ldap::LdapAuthConfiguration;
use crate::configuration::ApplicationConfiguration;
use crate::get_userdata_trait::GetUserData;
use crate::http_traits::CustomHttpResponse;
#[cfg(feature = "mail-noauth-notls")]
pub use crate::mail_noauth_notls::SendEMail;
use crate::secret_functions::Secret;
use actix_files::NamedFile;
use actix_web::web::Bytes;
use actix_web::{http::header, http::StatusCode, web, HttpRequest, HttpResponse, Responder};
use log::{debug, info, warn};
use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, CONTROLS};
use secstr::SecStr;
use serde::{Deserialize, Serialize};
use std::fs::remove_file;
use std::path::Path;

#[cfg(feature = "ldap-auth")]
type UserDataImpl = LdapAuthConfiguration;

/// Characters that will be percent encoded
/// https://url.spec.whatwg.org/#fragment-percent-encode-set
const FRAGMENT: &AsciiSet = &CONTROLS.add(b'/').add(b'=');

/// redirect browser to our index page
pub async fn redirect_to_index(
    application_configuration: web::Data<ApplicationConfiguration>,
) -> HttpResponse {
    // url of our index page
    let index_url = format!(
        "https://{}/index.html",
        &application_configuration.configuration_file.fqdn
    );
    debug!("redirecting to index_url = {}", &index_url);
    let response = HttpResponse::build(StatusCode::SEE_OTHER)
        .append_header((header::LOCATION, index_url))
        .append_header(("Access-Control-Allow-Origin", "*"))
        .finish();
    response
}

/// show a monitoring system that we are still alive
pub async fn still_alive(
    application_configuration: web::Data<ApplicationConfiguration>,
) -> impl Responder {
    if application_configuration
        .rsa_password
        .read()
        .unwrap()
        .rsa_private_key_password
        .is_some()
    {
        return HttpResponse::Ok().body("Yes sir, I can boogie!");
    } else {
        return HttpResponse::Ok().body("System not ready!");
    }
}

/// returns a hint what account should be used for login
pub async fn get_login_hint(
    application_configuration: web::Data<ApplicationConfiguration>,
) -> impl Responder {
    let login_hint = &application_configuration
        .configuration_file
        .login_hint
        .clone();
    HttpResponse::ok_text_response(login_hint.to_string())
}

/// returns a hint abou valid mail addresses
pub async fn get_mail_hint(
    application_configuration: web::Data<ApplicationConfiguration>,
) -> impl Responder {
    match &application_configuration.configuration_file.mail_hint {
        Some(mail_hint) => {
            format!("{{\"MailHint\": \"{}\"}}", &mail_hint)
        }
        None => "{\"MailHint\": \"\"}".to_string(),
    }
}

/// returns a href and target to the imprint page
pub async fn get_imprint_link(
    application_configuration: web::Data<ApplicationConfiguration>,
) -> impl Responder {
    let imprint_link = &application_configuration.configuration_file.imprint.clone();
    HttpResponse::ok_json_response(
        serde_json::to_string(&imprint_link)
            .unwrap_or("ERROR: failed to serialize imprint link".to_string()),
    )
}

/// return the custom colors.css file if it exists
pub async fn get_colors_css() -> impl Responder {
    let path_local = Path::new("local/css/colors.css");
    let path_static = Path::new("static/css/colors.css");
    let file_path = match path_local.exists() {
        true => path_local,
        _ => path_static,
    };
    NamedFile::open_async(file_path).await
}

/// return the custom site logo if it exists
pub async fn get_company_logo() -> impl Responder {
    let path_local = Path::new("local/gfx/company-logo.png");
    let path_static = Path::new("static/gfx/hardcodes-logo.png");
    let file_path = match path_local.exists() {
        true => path_local,
        _ => path_static,
    };
    NamedFile::open_async(file_path).await
}

/// return the custom favicon if it exists
pub async fn get_favicon() -> impl Responder {
    let path_local = Path::new("local/gfx/favicon.png");
    let path_static = Path::new("static/gfx/favicon.png");
    let file_path = match path_local.exists() {
        true => path_local,
        _ => path_static,
    };
    NamedFile::open_async(file_path).await
}

/// Returns true or false as json value so that
/// the web form can check if the rsa password
/// is already stored in the running server.
///
/// # Arguments
///
/// - `application_configuration`: application configuration
///
/// # Returns
///
/// - `HttpResponse`
pub async fn is_server_ready(
    application_configuration: web::Data<ApplicationConfiguration>,
) -> HttpResponse {
    if application_configuration
        .rsa_password
        .read()
        .unwrap()
        .rsa_private_key_password
        .is_some()
    {
        return HttpResponse::ok_json_response("{\"isReady\": true}");
    } else {
        return HttpResponse::ok_json_response("{\"isReady\": false}");
    }
}

/// Stores the password for the rsa private key in a
/// secure string during runtime of the server.
///
/// # Arguments
///
/// - `path`: tail of the url = password
/// - `application_configuration`: application configuration
///
/// # Returns
///
/// - `HttpResponse`
pub async fn set_password_for_rsa_rivate_key(
    _admin: AuthenticatedAdministrator,
    base64_encoded_password: web::Path<String>,
    application_configuration: web::Data<ApplicationConfiguration>,
) -> HttpResponse {
    // the password was encoded before the transfer to make sure
    // that special characters would be transferred correctly.
    // tested with
    // PASS!"§$%&/()=?ß\´`+*~'#-_.:,;<>|WORD
    let base64_decoded_password =
        match String::from_utf8(base64::decode(&base64_encoded_password.as_str()).unwrap()) {
            Ok(password) => password.trim_matches(char::from(0)).to_string(),
            Err(e) => {
                warn!("could not base64 decode password: {}", &e);
                return HttpResponse::err_text_response("ERROR: password was not set");
            }
        };
    debug!("new rsa password = {}", &base64_decoded_password);
    if let Ok(mut rsa_password_write_lock) = application_configuration.rsa_password.write() {
        rsa_password_write_lock.rsa_private_key_password =
            Some(SecStr::from(base64_decoded_password.clone()));
    } else {
        return HttpResponse::err_text_response("ERROR: can not acquire a lock on system data!");
    }
    // the lock must be removed at this point because
    // application_configuration.load_rsa_keys()
    // will quire a lock on itself. If we didn't remove the
    // lock here, we will never return...
    info!("password has been set, loading rsa keys");
    match application_configuration.load_rsa_keys() {
        Err(e) => {
            // loading the rsa keys did not work, throw the password away
            let _result = application_configuration.clear_rsa_password();
            warn!("error loading rsa private key: {:?}", e);
            return HttpResponse::err_text_response("ERROR: could not load rsa private key!");
        }
        Ok(_) => {
            info!("rsa keys have been loaded successfully");
            return HttpResponse::ok_text_response("OK");
        }
    }
}

/// Stores a secret and its meta date as encrypted file on disk
///
/// # Arguments
///
/// - `bytes` - the POSTed bytes from the form
/// - `application_configuration`: application configuration
///
/// # Returns
///
/// - `HttpResponse`
pub async fn store_secret(
    bytes: Bytes,
    application_configuration: web::Data<ApplicationConfiguration>,
) -> HttpResponse {
    debug!("store_secret()");
    let bytes_vec = bytes.to_vec();
    let form_data = match String::from_utf8(bytes_vec) {
        Ok(form_data) => form_data,
        Err(_) => {
            return HttpResponse::err_text_response("ERROR: could not parse form data");
        }
    };
    debug!("{}", form_data);
    let mut parsed_form_data = match serde_json::from_str(&form_data) as Result<Secret, _> {
        Ok(parsed_form_data) => parsed_form_data,
        Err(_) => {
            return HttpResponse::err_text_response("ERROR: could not parse json form data");
        }
    };
    debug!("parsed_form_data={:?}", &parsed_form_data);
    // get the display name of the receiver
    let display_name = match <UserDataImpl as GetUserData>::get_display_name(
        &parsed_form_data.to_email,
        &application_configuration,
    )
    .await
    {
        Ok(display_name) => display_name,
        Err(e) => {
            warn!(
                "cannot find mail address {}, error: {}",
                &parsed_form_data.to_email, &e
            );
            return HttpResponse::err_text_response(format!(
                "ERROR: cannot find mail address {}",
                &parsed_form_data.to_email
            ));
        }
    };
    parsed_form_data.to_display_name = display_name;
    // aes encrypt the secret before rsa encryption
    let aes_encryption_result = match parsed_form_data.secret.to_aes_enrypted_b64() {
        Ok(aes_encryption_result) => aes_encryption_result,
        Err(e) => {
            return HttpResponse::err_text_response(format!("ERROR: {}", &e));
        }
    };
    // store aes encrypted secret instead of plaintext secret
    parsed_form_data.secret = aes_encryption_result.encrypted_data.clone();
    // rsa encrypt all data
    let rsa_read_lock = application_configuration.rsa_keys.read().unwrap();
    let encrypted_form_data = match parsed_form_data.to_encrypted(&rsa_read_lock) {
        Ok(encrypted_form_data) => encrypted_form_data,
        Err(e) => {
            return HttpResponse::err_text_response(format!("ERROR: {}", &e));
        }
    };

    // write data to disk
    let mut shared_secret_write_lock = application_configuration.shared_secret.write().unwrap();
    let uuid = shared_secret_write_lock.create_uuid();
    // get rid of write lock as fast as possible
    drop(shared_secret_write_lock);
    let path = Path::new(
        &application_configuration
            .configuration_file
            .secret_directory,
    )
    .join(&uuid.to_string());
    info!("writing secret to file {}", &path.display());
    match encrypted_form_data.write_to_disk(&path).await {
        Err(e) => {
            warn!("{}", &e);
            return HttpResponse::err_text_response(format!(
                "ERROR: could not write secret {} to disk!",
                &path.display()
            ));
        }
        Ok(_) => {
            info!("success, file {} written", &path.display());
            // build url payload for email
            let url_payload = format!(
                "{};{};{}",
                &uuid.to_string(),
                &aes_encryption_result.encryption_iv,
                aes_encryption_result.encryption_key
            );
            debug!("url_payload = {}", &url_payload);
            // rsa encrypt url payload
            let encrypted_url_payload = match rsa_read_lock
                .encrypt_str(&url_payload)
            {
                Ok(encrypted_url_payload) => encrypted_url_payload,
                Err(e) => {
                    return HttpResponse::err_text_response(format!("ERROR: {}", &e));
                }
            };
            let encrypted_percent_encoded_url_payload = utf8_percent_encode(&encrypted_url_payload, FRAGMENT);
            debug!(
                "encrypted_percent_encoded_url_payload = {}",
                &encrypted_percent_encoded_url_payload
            );
            // send email to receiver
            let mail_body_template = match application_configuration
                .configuration_file
                .email_configuration
                .load_mail_template()
            {
                Ok(mail_body_template) => mail_body_template,
                Err(e) => {
                    return HttpResponse::err_text_response(format!("ERROR: {}", &e));
                }
            };
            let mail_body = &parsed_form_data.build_mail_body(
                &mail_body_template,
                &encrypted_percent_encoded_url_payload.to_string(),
            );
            let mail_subject = &parsed_form_data.build_context(
                &application_configuration
                    .configuration_file
                    .email_configuration
                    .mail_subject,
            );
            info!(
                "sending email to {} for secret {}",
                &parsed_form_data.to_email,
                &uuid.to_string()
            );
            match &application_configuration
                .configuration_file
                .email_configuration
                .send_mail(&parsed_form_data.to_email, &mail_subject, &mail_body)
            {
                Err(e) => {
                    warn!(
                        "error sending mail to {}: {}",
                        &parsed_form_data.to_email, &e
                    );
                    return HttpResponse::err_text_response(format!("ERROR: {}", &e));
                }
                Ok(_) => {
                    return HttpResponse::ok_text_response("OK");
                }
            };
        }
    };
}

/// Loads a stored secret and decrypts it
///
/// # Arguments
///
/// - encrypted_percent_encoded_url_payload: web::Path<String>, tail of the url
/// - `application_configuration`: application configuration
///
/// # Returns
///
/// - `HttpResponse`
pub async fn reveal_secret(
    req: HttpRequest,
    encrypted_percent_encoded_url_payload: web::Path<String>,
    application_configuration: web::Data<ApplicationConfiguration>,
) -> HttpResponse {
    debug!("reveal_secret()");
    match get_authenticated_user(&req) {
        Err(err) => HttpResponse::from_error(err),
        Ok(auth_request) => {
            debug!(
                "encrypted_percent_encoded_url_payload {}",
                &encrypted_percent_encoded_url_payload
            );
            let encrypted_url_payload =
                percent_decode_str(&encrypted_percent_encoded_url_payload).decode_utf8_lossy();
            debug!("encrypted_url_payload {}", &encrypted_url_payload);
            // rsa decrypt all data
            let rsa_read_lock = application_configuration.rsa_keys.read().unwrap();
            match rsa_read_lock.decrypt_str(&encrypted_url_payload) {
                Err(e) => {
                    return HttpResponse::err_text_response(format!("ERROR: {}", &e));
                }
                Ok(url_payload) => {
                    debug!("url_payload = {}", &url_payload);
                    let mut split_iter = url_payload.split(";");
                    let uuid = split_iter.next().unwrap_or("uuid");
                    let iv_base64 = split_iter.next().unwrap_or("iv");
                    let key_base64 = split_iter.next().unwrap_or("key");
                    // load data from file
                    let path = Path::new(
                        &application_configuration
                            .configuration_file
                            .secret_directory,
                    )
                    .join(&uuid);
                    info!("reading secret from file {}", &path.display());
                    match Secret::read_from_disk(&path).await {
                        Err(e) => {
                            return HttpResponse::err_text_response(format!("ERROR: {}", &e));
                        }
                        Ok(encrypted_secret) => {
                            info!("success, file {} read", &path.display());
                            // rsa decrypt the stored values
                            match encrypted_secret.to_decrypted(&rsa_read_lock) {
                                Err(e) => {
                                    return HttpResponse::err_text_response(format!(
                                        "ERROR: {}",
                                        &e
                                    ));
                                }
                                Ok(mut aes_encrypted) => {
                                    debug!("aes_encrypted = {}", &aes_encrypted.secret);
                                    if aes_encrypted.to_email != auth_request.mail {
                                        warn!(
                                            "user{} (mail = {}) wants to access secret {} (to_email = {})",
                                            &auth_request.user_name, &auth_request.mail, &uuid, &aes_encrypted.to_email
                                        );
                                        return HttpResponse::err_text_response(
                                            "ERROR: access to secret not permitted!",
                                        );
                                    }
                                    match aes_encrypted
                                        .secret
                                        .decrypt_b64_aes(&key_base64, &iv_base64)
                                    {
                                        Err(e) => {
                                            return HttpResponse::err_text_response(format!(
                                                "ERROR: {}",
                                                &e
                                            ));
                                        }
                                        Ok(decrypted_secret) => {
                                            aes_encrypted.secret = decrypted_secret;
                                            match serde_json::to_string(&aes_encrypted) {
                                                Err(e) => {
                                                    return HttpResponse::err_text_response(
                                                        format!("ERROR: {}", &e),
                                                    );
                                                }
                                                Ok(json_response) => {
                                                    debug!("json_response = {}", &json_response);
                                                    // remove the secret file before revealing data.
                                                    match remove_file(&path) {
                                                        Err(e) => {
                                                            warn!(
                                                                "secret {} cannot be deleted: {}",
                                                                &path.display(),
                                                                &e
                                                            );
                                                            return HttpResponse::err_text_response(
                                                                format!("ERROR: secret cannot be deleted from server"));
                                                        }
                                                        Ok(_) => {
                                                            info!(
                                                                "revealing secret with id {}",
                                                                &uuid
                                                            );
                                                            return HttpResponse::ok_json_response(
                                                                json_response,
                                                            );
                                                        }
                                                    };
                                                }
                                            };
                                        }
                                    };
                                }
                            };
                        }
                    }
                }
            };
        }
    }
}

/// Details about the authenticated user
#[derive(Serialize, Deserialize)]
struct UserDetails {
    #[serde(rename = "DisplayName")]
    display_name: String,
    #[serde(rename = "Email")]
    mail: String,
}

/// Get display name and email address of the authenticated user
///
/// # Arguments
///
/// - `user`: `AuthenticatedUser` to get details from
///
/// # Returns
///
/// - `HttpResponse`
pub async fn get_authenticated_user_details(user: AuthenticatedUser) -> HttpResponse {
    debug!("get_authenticated_user_details()");
    let user_details = UserDetails {
        display_name: format!("{} {}", &user.first_name, &user.last_name),
        mail: user.mail,
    };
    match serde_json::to_string(&user_details) {
        Err(e) => {
            HttpResponse::err_text_response(format!("ERROR: cannot get user details: {}", &e))
        }
        Ok(json) => HttpResponse::ok_json_response(json),
    }
}

/// Get admin protected sysop.html
pub async fn get_sysop_html(_admin: AuthenticatedAdministrator) -> impl Responder {
    NamedFile::open_async("admin-html/sysop.html").await
}

/// Get admin protected sysop.js
pub async fn get_sysop_js(_admin: AuthenticatedAdministrator) -> impl Responder {
    NamedFile::open_async("admin-html/js/sysop.js").await
}

/// renew cookie lifetime for the authenticated user
///
/// # Arguments
///
/// - `req`: `HttpRequest` containing the header with the cookies for authentication
/// - _user`: `AuthenticatedUser` = make sure a user is logged in
///
/// # Returns
///
/// - `HttpResponse`
pub async fn keep_session_alive(req: HttpRequest, _user: AuthenticatedUser) -> HttpResponse {
    update_authenticated_user_cookie_lifetime(&req)
}
