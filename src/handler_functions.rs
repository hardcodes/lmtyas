//#[macro_use]
extern crate env_logger;
use crate::aes_functions::{DecryptAes, EncryptAes};
use crate::authenticated_user::{AuthenticatedAdministrator, AuthenticatedUser};
use crate::authentication_functions::update_authenticated_user_cookie_lifetime;
use crate::base64_trait::Base64VecU8Conversions;
use crate::configuration::ApplicationConfiguration;
#[cfg(feature = "get-userdata-ldap")]
use crate::get_userdata_ldap::GetUserDataLdapBackend;
use crate::get_userdata_trait::GetUserData;
#[cfg(feature = "no-userdata-backend")]
use crate::get_userdata_trait::NoUserDataBackend;
use crate::http_traits::CustomHttpResponse;
#[cfg(feature = "mail-noauth-notls")]
pub use crate::mail_noauth_notls::SendEMail;
#[cfg(feature = "mail-noauth-notls-smime")]
pub use crate::mail_noauth_notls_smime::SendEMail;
use crate::secret_functions::Secret;
#[cfg(feature = "mail-noauth-notls-smime")]
use crate::string_trait::StringTrimNewline;
use crate::UNKOWN_RECEIVER_EMAIL;
use actix_files::NamedFile;
use actix_web::web::Bytes;
use actix_web::{http::header, http::StatusCode, web, HttpRequest, HttpResponse, Responder};
use log::{debug, info, warn};
use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, CONTROLS};
use secstr::SecStr;
use serde::{Deserialize, Serialize};
use std::fs::read_to_string;
use std::fs::remove_file;
use std::path::Path;
use zeroize::Zeroize;

#[cfg(feature = "no-userdata-backend")]
type UserDataImpl = NoUserDataBackend;
#[cfg(feature = "get-userdata-ldap")]
type UserDataImpl = GetUserDataLdapBackend;

/// Characters that will be percent encoded
/// https://url.spec.whatwg.org/#fragment-percent-encode-set
const FRAGMENT: &AsciiSet = &CONTROLS.add(b'/').add(b'=');
/// max length of form data
const MAX_FORM_BYTES_LEN: usize = 10100 * 10;
/// max length of form fields
const MAX_FORM_INPUT_LEN: usize = 10100;

/// Redirect browser to our index page.
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

/// Show a monitoring system that we are still alive.
pub async fn still_alive(
    application_configuration: web::Data<ApplicationConfiguration>,
) -> impl Responder {
    if application_configuration
        .rsa_keys
        .read()
        .unwrap()
        .rsa_private_key
        .is_some()
    {
        HttpResponse::Ok().body("Yes sir, I can boogie!")
    } else {
        HttpResponse::Ok().body("System not ready!")
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

/// Returns a hint about valid mail addresses.
pub async fn get_mail_hint(
    application_configuration: web::Data<ApplicationConfiguration>,
) -> impl Responder {
    const EMPTY_MAIL_HINT_JSON: &str = "{\"MailHint\": \"\"}";
    match &application_configuration.configuration_file.mail_hint {
        Some(mail_hint) => {
            format!("{{\"MailHint\": \"{}\"}}", &mail_hint)
        }
        None => EMPTY_MAIL_HINT_JSON.to_string(),
    }
}

/// Returns a href and target to the imprint page.
pub async fn get_imprint_link(
    application_configuration: web::Data<ApplicationConfiguration>,
) -> impl Responder {
    const SERDE_SERIALIZE_IMPRINT_ERROR: &str = "ERROR: failed to serialize imprint link";
    let imprint_link = &application_configuration.configuration_file.imprint.clone();
    HttpResponse::ok_json_response(
        serde_json::to_string(&imprint_link)
            .unwrap_or_else(|_| -> String { SERDE_SERIALIZE_IMPRINT_ERROR.to_string() }),
    )
}

/// Return the custom colors.css file if it exists.
pub async fn get_colors_css() -> impl Responder {
    let path_local = Path::new("local/css/colors.css");
    let path_static = Path::new("web-content/static/css/colors.css");
    let file_path = match path_local.exists() {
        true => path_local,
        _ => path_static,
    };
    NamedFile::open_async(file_path).await
}

/// Return the custom company-logo.png if it exists.
pub async fn get_company_logo() -> impl Responder {
    let path_local = Path::new("local/gfx/company-logo.png");
    let path_static = Path::new("web-content/static/gfx/hardcodes-logo.png");
    let file_path = match path_local.exists() {
        true => path_local,
        _ => path_static,
    };
    NamedFile::open_async(file_path).await
}

/// Return the custom favicon.png if it exists.
pub async fn get_favicon() -> impl Responder {
    let path_local = Path::new("local/gfx/favicon.png");
    let path_static = Path::new("web-content/static/gfx/favicon.png");
    let file_path = match path_local.exists() {
        true => path_local,
        _ => path_static,
    };
    NamedFile::open_async(file_path).await
}

/// Returns true or false as json value so that
/// the web form can check if the rsa private key
/// is already stored in the running server.
pub async fn is_server_ready(
    application_configuration: web::Data<ApplicationConfiguration>,
) -> HttpResponse {
    if application_configuration
        .rsa_keys
        .read()
        .unwrap()
        .rsa_private_key
        .is_some()
    {
        HttpResponse::ok_json_response("{\"isReady\": true}")
    } else {
        HttpResponse::ok_json_response("{\"isReady\": false}")
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
    if base64_encoded_password.len() > MAX_FORM_BYTES_LEN {
        warn!("form data exceeds {} bytes!", MAX_FORM_BYTES_LEN);
        return HttpResponse::err_text_response(format!(
            "ERROR: more than {} bytes of data sent",
            &MAX_FORM_BYTES_LEN
        ));
    }
    // the password was encoded before the transfer to make sure
    // that special characters would be transferred correctly.
    // tested with
    // PASS!"§$%&/()=?ß\´`+*~'#-_.:,;<>öäü|WORD
    let base64_decoded_password = match Vec::from_base64_encoded(base64_encoded_password.as_str()) {
        Ok(v) => v,
        Err(e) => {
            warn!("Cannot decode base64 rsa password: {}", &e);
            return HttpResponse::err_text_response("ERROR: password was not set");
        }
    };

    let mut decoded_password = match String::from_utf8(base64_decoded_password) {
        Ok(password) => password.trim_matches(char::from(0)).to_string(),
        Err(e) => {
            warn!("could not base64 decode password: {}", &e);
            return HttpResponse::err_text_response("ERROR: password was not set");
        }
    };
    debug!("new rsa password = {}", &decoded_password);
    if decoded_password.len() > MAX_FORM_INPUT_LEN {
        return HttpResponse::err_text_response(format!(
            "ERROR: password > {} chars",
            MAX_FORM_INPUT_LEN
        ));
    }
    if let Ok(mut rsa_password_write_lock) = application_configuration.rsa_password.write() {
        rsa_password_write_lock.rsa_private_key_password = Some(SecStr::from(decoded_password));
    } else {
        decoded_password.zeroize();
        return HttpResponse::err_text_response("ERROR: can not acquire a lock on system data!");
    }
    // the lock must be removed at this point because
    // application_configuration.load_rsa_keys()
    // will quire a lock on itself. If we don't remove the
    // lock here, we will never return...
    info!("password has been set, loading rsa keys...");
    match application_configuration.load_rsa_keys() {
        Err(e) => {
            // loading the rsa keys did not work, throw the password away
            let _result = application_configuration.clear_rsa_password();
            warn!("error loading rsa private key: {:?}", e);
            HttpResponse::err_text_response("ERROR: could not load rsa private key!")
        }
        Ok(_) => {
            info!("rsa keys have been loaded successfully");
            // Clear the password now, since the rsa keys have been loaded.
            let _result = application_configuration.clear_rsa_password();
            // load the S/Mime certificate if the feature is enabled
            #[cfg(feature = "mail-noauth-notls-smime")]
            {
                info!("decrypting S/Mime private key password...");
                let rsa_read_lock = application_configuration.rsa_keys.read().unwrap();
                let decrypted_password = match rsa_read_lock.hybrid_decrypt_str(
                    &application_configuration
                        .configuration_file
                        .email_configuration
                        .mail_smime_configuration
                        .enrypted_password,
                ) {
                    Err(e) => {
                        warn!("could not decrypt S/Mime private key password: {:?}", e);
                        return HttpResponse::err_text_response(
                            "ERROR: could not load S/Mime configuration!",
                        );
                    }
                    Ok(mut password) => {
                        String::trim_newline(&mut password);
                        debug!("password: {}", &password);
                        SecStr::from(password)
                    }
                };
                info!("sucessfully decrypted S/Mime private key password.");
                let mut smime_certificate_write_lock =
                    application_configuration.smime_certificate.write().unwrap();
                if let Err(e) = smime_certificate_write_lock.load_smime_certificate(
                    &application_configuration
                        .configuration_file
                        .email_configuration
                        .mail_smime_configuration
                        .rsa_private_key_file,
                    &decrypted_password,
                ) {
                    warn!("could not load S/Mime configuration: {:?}", e);
                    return HttpResponse::err_text_response(
                        "ERROR: could not load S/Mime configuration!",
                    );
                }
            }

            // Delete cookie after rsa password has been set because it
            // is not enrypted yet.
            HttpResponse::ok_text_response_with_empty_unix_epoch_cookie("OK")
        }
    }
}

/// Stores a secret and its meta date as encrypted file on disk.
///
/// # Arguments
///
/// - `bytes`:                     the POSTed bytes from the form
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
    if form_data.len() > MAX_FORM_BYTES_LEN {
        warn!("form data exceeds {} bytes!", MAX_FORM_BYTES_LEN);
        return HttpResponse::err_text_response(format!(
            "ERROR: more than {} bytes of data sent",
            &MAX_FORM_BYTES_LEN
        ));
    }
    let mut parsed_form_data = match serde_json::from_str(&form_data) as Result<Secret, _> {
        Ok(parsed_form_data) => parsed_form_data,
        Err(_) => {
            return HttpResponse::err_text_response("ERROR: could not parse json form data");
        }
    };
    debug!("parsed_form_data={:?}", &parsed_form_data);
    if parsed_form_data.from_email.len() > MAX_FORM_INPUT_LEN {
        return HttpResponse::err_text_response(format!(
            "ERROR: from email > {} chars",
            MAX_FORM_INPUT_LEN
        ));
    }
    if parsed_form_data.to_email.len() > MAX_FORM_INPUT_LEN {
        return HttpResponse::err_text_response(format!(
            "ERROR: to email > {} chars",
            MAX_FORM_INPUT_LEN
        ));
    }
    if parsed_form_data.context.len() > MAX_FORM_INPUT_LEN {
        return HttpResponse::err_text_response(format!(
            "ERROR: context > {} chars",
            MAX_FORM_INPUT_LEN
        ));
    }
    let secret_length = get_base64_encoded_secret_len(&parsed_form_data.secret);
    if secret_length > MAX_FORM_INPUT_LEN {
        return HttpResponse::err_text_response(format!(
            "ERROR: secret > {} bytes!",
            MAX_FORM_INPUT_LEN
        ));
    }
    let display_name = match <UserDataImpl as GetUserData>::get_receiver_display_name(
        &parsed_form_data.to_email,
        &application_configuration,
    )
    .await
    {
        Ok(display_name) => display_name,
        Err(e) => {
            info!(
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
    // aes encrypt the secret before rsa or hybrid rsa/aes encryption
    let aes_encryption_result = match parsed_form_data.secret.to_aes_enrypted_b64() {
        Ok(aes_encryption_result) => aes_encryption_result,
        Err(e) => {
            return HttpResponse::err_text_response(format!("ERROR: {}", &e));
        }
    };
    // store aes encrypted secret instead of plaintext secret
    parsed_form_data.secret = aes_encryption_result.encrypted_data.clone();
    // rsa encrypt all data
    let encrypted_form_data =
        match parsed_form_data.to_encrypted(&application_configuration.rsa_keys.read().unwrap()) {
            Ok(encrypted_form_data) => encrypted_form_data,
            Err(e) => {
                return HttpResponse::err_text_response(format!("ERROR: {}", &e));
            }
        };

    // write data to disk
    let uuid = application_configuration
        .shared_secret
        .write()
        .unwrap()
        .create_uuid();

    let path = Path::new(
        &application_configuration
            .configuration_file
            .secret_directory,
    )
    .join(uuid.to_string());
    info!("writing secret to file {}", &path.display());
    if let Err(e) = encrypted_form_data.write_to_disk(&path).await {
        warn!("{}", &e);
        return HttpResponse::err_text_response(format!(
            "ERROR: could not write secret {} to disk!",
            &path.display()
        ));
    };

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
    let encrypted_url_payload = match application_configuration
        .rsa_keys
        .read()
        .unwrap()
        .encrypt_str(&url_payload)
    {
        Ok(encrypted_url_payload) => encrypted_url_payload,
        Err(e) => {
            return HttpResponse::err_text_response(format!("ERROR: {}", &e));
        }
    };
    let encrypted_percent_encoded_url_payload =
        utf8_percent_encode(&encrypted_url_payload, FRAGMENT);
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
            warn!("error loading mail template: {}", &e);
            return HttpResponse::err_text_response("ERROR: cannot send email!");
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

    #[cfg(not(feature = "mail-noauth-notls-smime"))]
    let mail_signature = None;
    #[cfg(feature = "mail-noauth-notls-smime")]
    let mail_signature = match application_configuration
        .smime_certificate
        .read()
        .unwrap()
        .sign_mail_body(mail_body)
    {
        Err(e) => {
            warn!("error signing email: {}", &e);
            return HttpResponse::err_text_response("ERROR: cannot sign email!");
        }
        Ok(signature) => Some(signature),
    };

    if let Err(e) = &application_configuration
        .configuration_file
        .email_configuration
        .send_mail(
            &parsed_form_data.to_email,
            mail_subject,
            mail_body,
            mail_signature,
        )
    {
        warn!(
            "error sending email to {} for secret {}: {}",
            &parsed_form_data.to_email,
            &uuid.to_string(),
            &e
        );
        return HttpResponse::err_text_response("ERROR: cannot send email!");
    };
    HttpResponse::ok_text_response("OK")
}

/// Returns the length of a base64 decoded secret. If it cannot be decoded
/// at all, MAX_FORM_INPUT_LEN + 1 will be returned as length.
fn get_base64_encoded_secret_len(parsed_secret: &str) -> usize {
    let decoded_secret = match Vec::from_base64_encoded(parsed_secret) {
        Ok(s) => s,
        Err(e) => {
            warn!("error decoding secret, assuming input too long: {}", &e);
            return MAX_FORM_INPUT_LEN + 1;
        }
    };
    if decoded_secret.len() > MAX_FORM_INPUT_LEN {
        warn!("secret is too large: {} bytes!", &decoded_secret.len());
    }
    decoded_secret.len()
}

/// Loads a stored secret and decrypts it
///
/// # Arguments
///
/// - encrypted_percent_encoded_url_payload: tail of the url
/// - `application_configuration`:           application configuration
/// - `user`:                                authenticated user calling this function
///
/// # Returns
///
/// - `HttpResponse`
pub async fn reveal_secret(
    encrypted_percent_encoded_url_payload: web::Path<String>,
    application_configuration: web::Data<ApplicationConfiguration>,
    user: AuthenticatedUser,
) -> HttpResponse {
    debug!(
        "reveal_secret(), encrypted_percent_encoded_url_payload {}",
        &encrypted_percent_encoded_url_payload
    );
    let encrypted_url_payload =
        percent_decode_str(&encrypted_percent_encoded_url_payload).decode_utf8_lossy();
    // rsa decrypt all data
    let url_payload = match application_configuration
        .rsa_keys
        .read()
        .unwrap()
        .decrypt_str(&encrypted_url_payload)
    {
        Err(e) => {
            return HttpResponse::err_text_response(format!("ERROR: {}", &e));
        }
        Ok(url_payload) => url_payload,
    };
    debug!("url_payload = {}", &url_payload);
    // get details from the payload
    let mut split_iter = url_payload.split(';');
    let uuid = split_iter.next().unwrap_or("uuid");
    let iv_base64 = split_iter.next().unwrap_or("iv");
    let key_base64 = split_iter.next().unwrap_or("key");
    // load data from file
    let path = Path::new(
        &application_configuration
            .configuration_file
            .secret_directory,
    )
    .join(uuid);
    info!("reading secret from file {}", &path.display());
    let encrypted_secret = match Secret::read_from_disk(&path).await {
        Ok(encrypted_secret) => encrypted_secret,
        Err(e) => {
            info!(
                "secret file {} cannot be read from user {}: {}",
                &path.display(),
                &user.user_name,
                e
            );
            return HttpResponse::err_text_response(
                "ERROR: Secret cannot be read! Already revealed?",
            );
        }
    };
    info!("success, file {} read", &path.display());
    // rsa decrypt the stored values
    let rsa_read_lock = application_configuration.rsa_keys.read().unwrap();
    let mut aes_encrypted = match encrypted_secret.to_decrypted(&rsa_read_lock) {
        Err(e) => {
            return HttpResponse::err_text_response(format!("ERROR: {}", &e));
        }
        Ok(aes_encrypted) => aes_encrypted,
    };
    debug!("aes_encrypted = {}", &aes_encrypted.secret);

    // check if user is entitled to reveal this secret
    if aes_encrypted.to_email.to_lowercase() != user.mail.to_lowercase() {
        warn!(
            "user{} (mail = {}) wants to access secret {} (to_email = {})",
            &user.user_name, &user.mail, &uuid, &aes_encrypted.to_email
        );
        return HttpResponse::err_text_response("ERROR: access to secret not permitted!");
    }
    let decrypted_secret = match aes_encrypted.secret.decrypt_b64_aes(key_base64, iv_base64) {
        Ok(decrypted_secret) => decrypted_secret,
        Err(e) => {
            return HttpResponse::err_text_response(format!("ERROR: {}", &e));
        }
    };
    // put the plaintext secret into the struct
    aes_encrypted.secret = decrypted_secret;
    let json_response = match serde_json::to_string(&aes_encrypted) {
        Err(e) => {
            return HttpResponse::err_text_response(format!("ERROR: {}", &e));
        }
        Ok(json_response) => json_response,
    };
    debug!("json_response = {}", &json_response);
    // remove the secret file before revealing data.
    match remove_file(&path) {
        Err(e) => {
            warn!("secret {} cannot be deleted: {}", &path.display(), &e);
            HttpResponse::err_text_response("ERROR: secret cannot be deleted from server")
        }
        Ok(_) => {
            info!("revealing secret with id {}", &uuid);
            HttpResponse::ok_json_response(json_response)
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

/// Validate email address of the receiver before sending the form.
/// An invalid email address will prevent sending the form.
/// Return `mail` as result string if the mail could be validated,
/// else return `crate::UNKOWN_RECEIVER_EMAIL` as result string to
/// the frontend.
pub async fn get_validated_receiver_email(
    path: web::Path<String>,
    _user: AuthenticatedUser,
    application_configuration: web::Data<ApplicationConfiguration>,
) -> HttpResponse {
    debug!("get_validated_receiver_email()");
    let email = path.into_inner();
    let receiver_email = match <UserDataImpl as GetUserData>::validate_email_address(
        &email,
        &application_configuration,
    )
    .await
    {
        Ok(receiver_email) => receiver_email,
        Err(e) => {
            debug!("cannot find mail address {}, error: {}", &email, &e);
            return HttpResponse::ok_text_response(UNKOWN_RECEIVER_EMAIL.to_string());
        }
    };
    HttpResponse::ok_text_response(receiver_email.to_ascii_lowercase())
}

/// Get admin protected sysop.html.
pub async fn get_sysop_html(_admin: AuthenticatedAdministrator) -> impl Responder {
    NamedFile::open_async("web-content/admin-html/sysop.html").await
}

/// Get admin protected sysop.js.
pub async fn get_sysop_js(_admin: AuthenticatedAdministrator) -> impl Responder {
    NamedFile::open_async("web-content/admin-html/js/sysop.js").await
}

/// Renew cookie lifetime for the authenticated user by settings the
/// current timestamp.
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

/// Custom 404 handler
///
/// Returns 404.html or plain error message if file cannot be found.
pub async fn not_found_404() -> HttpResponse {
    let file_path = Path::new("web-content/static/404.html");
    let file_content =
        read_to_string(file_path).unwrap_or_else(|_| -> String { "404 not found".to_string() });
    HttpResponse::build(StatusCode::NOT_FOUND)
        .content_type("text/html; charset=UTF-8")
        .body(file_content)
}
