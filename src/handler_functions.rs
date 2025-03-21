//#[macro_use]
extern crate env_logger;
#[cfg(feature = "api-access-token")]
use crate::access_token::ValidatedAccessTokenPayload;
use crate::aes_trait::DecryptAes;
use crate::authenticated_user::{AccessScope, AuthenticatedAdministrator, AuthenticatedUser};
use crate::authentication_functions::update_authenticated_user_cookie_lifetime;
use crate::configuration::ApplicationConfiguration;
use crate::csrf_html_template::{inject_csrf_token, CsrfTemplateFile, ValidateCsrfToken};
#[cfg(feature = "get-userdata-ldap")]
use crate::get_userdata_ldap::GetUserDataLdapBackend;
use crate::get_userdata_trait::GetUserData;
#[cfg(feature = "no-userdata-backend")]
use crate::get_userdata_trait::NoUserDataBackend;
use crate::http_traits::CustomHttpResponse;
#[cfg(feature = "mail-noauth-notls")]
pub use crate::mail_noauth_notls::SendEMail;
use crate::secret_functions::Secret;
use crate::UNKNOWN_RECEIVER_EMAIL;
use crate::{MAX_FORM_BYTES_LEN, MAX_FORM_INPUT_LEN};
use actix_files::NamedFile;
use actix_web::web::Bytes;
use actix_web::{http::header, http::StatusCode, web, HttpRequest, HttpResponse, Responder};
use hacaoi::base64_trait::{Base64StringConversions, Base64VecU8Conversions};
use hacaoi::rsa::RsaKeysFunctions;
use log::{debug, info, warn};
use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, CONTROLS};
use serde::{Deserialize, Serialize};
use std::fs::read_to_string;
use std::fs::remove_file;
use std::io::Error;
use std::path::Path;
use zeroize::Zeroize;

#[cfg(feature = "no-userdata-backend")]
type UserDataImpl = NoUserDataBackend;
#[cfg(feature = "get-userdata-ldap")]
type UserDataImpl = GetUserDataLdapBackend;

#[cfg(feature = "hacaoi-openssl")]
type SecretAes256Cbc = hacaoi::aes::Aes256Cbc<hacaoi::aes::AesOpenSslScope>;
#[cfg(feature = "hacaoi-rust-crypto")]
type SecretAes256Cbc = hacaoi::aes::Aes256Cbc<hacaoi::aes::AesRustCryptoScope>;
use hacaoi::aes::Aes256CbcFunctions;

/// Characters that will be percent encoded
/// https://url.spec.whatwg.org/#fragment-percent-encode-set
const FRAGMENT: &AsciiSet = &CONTROLS.add(b'/').add(b'=');
/// Error message for missing or wrong CSRF token.
const ERROR_CRSF_VALIDATION: &str = "ERROR: cross-site-request-forgery verification failed";

/// Redirect browser to our index page.
pub async fn redirect_to_index() -> HttpResponse {
    debug!("redirecting to /index.html");
    let response = HttpResponse::build(StatusCode::SEE_OTHER)
        .append_header((header::LOCATION, "/index.html".to_string()))
        .finish();
    response
}

/// Show a monitoring system that we are still alive.
pub async fn still_alive(
    application_configuration: web::Data<ApplicationConfiguration>,
) -> impl Responder {
    if application_configuration
        .hybrid_crypto_for_secrets
        .read()
        .unwrap()
        .is_some()
    {
        HttpResponse::Ok().body("Yes sir, I can boogie!")
    } else {
        HttpResponse::Ok().body("System alive but not ready!")
    }
}

/// returns a hint what account should be used for login
pub async fn get_login_hint(
    application_configuration: web::Data<ApplicationConfiguration>,
) -> impl Responder {
    let login_hint = application_configuration
        .configuration_file
        .login_hint
        .clone();
    HttpResponse::ok_text_response(login_hint)
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

/// Returns a href and target to the privacy statement page.
pub async fn get_privacy_link(
    application_configuration: web::Data<ApplicationConfiguration>,
) -> impl Responder {
    const SERDE_SERIALIZE_PRIVACY_ERROR: &str = "ERROR: failed to serialize privacy link";
    let privacy_link = &application_configuration.configuration_file.privacy.clone();
    HttpResponse::ok_json_response(
        serde_json::to_string(&privacy_link)
            .unwrap_or_else(|_| -> String { SERDE_SERIALIZE_PRIVACY_ERROR.to_string() }),
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

/// Return the custom lmtyas.css file if it exists.
pub async fn get_lmtyas_css() -> impl Responder {
    let path_local = Path::new("local/css/lmtyas.css");
    let path_static = Path::new("web-content/static/css/lmtyas.css");
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

/// Return the custom imprint.html if it exists.
pub async fn get_imprint_html() -> impl Responder {
    let path_local = Path::new("local/html/imprint.html");
    if path_local.exists() {
        return NamedFile::open_async(path_local).await;
    }
    warn!("route access forbidden!");
    Err(Error::new(
        std::io::ErrorKind::NotFound,
        "ERROR: forbidden!",
    ))
}

/// Return the custom privacy.html if it exists.
pub async fn get_privacy_html() -> impl Responder {
    let path_local = Path::new("local/html/privacy.html");
    if path_local.exists() {
        return NamedFile::open_async(path_local).await;
    }
    warn!("route access forbidden!");
    Err(Error::new(
        std::io::ErrorKind::NotFound,
        "ERROR: forbidden!",
    ))
}

/// Returns true or false as json value so that
/// the web form can check if the rsa private key
/// is already stored in the running server.
pub async fn is_server_ready(
    application_configuration: web::Data<ApplicationConfiguration>,
) -> HttpResponse {
    if application_configuration
        .hybrid_crypto_for_secrets
        .read()
        .unwrap()
        .is_some()
    {
        HttpResponse::ok_json_response("{\"isReady\": true}")
    } else {
        HttpResponse::ok_json_response("{\"isReady\": false}")
    }
}

/// Loads the RSA private key and unlocks it
/// with the provided password.
pub async fn set_password_for_rsa_rivate_key(
    admin: AuthenticatedAdministrator,
    mut base64_encoded_password_csrf_token: String,
    application_configuration: web::Data<ApplicationConfiguration>,
) -> HttpResponse {
    if base64_encoded_password_csrf_token.len() > MAX_FORM_BYTES_LEN {
        warn!("form data exceeds {} bytes! {}", MAX_FORM_BYTES_LEN, &admin);
        base64_encoded_password_csrf_token.zeroize();
        return HttpResponse::err_text_response(format!(
            "ERROR: more than {} bytes of data sent",
            &MAX_FORM_BYTES_LEN
        ));
    }
    let (base64_encoded_password, csrf_token) =
        match base64_encoded_password_csrf_token.split_once(';') {
            None => {
                warn!("csrf token missing! {}", &admin);
                base64_encoded_password_csrf_token.zeroize();
                return HttpResponse::err_text_response(ERROR_CRSF_VALIDATION);
            }
            Some((password, token)) => (password, token),
        };
    if csrf_token != admin.csrf_token() {
        warn!("csrf token does not match! {}", &admin);
        base64_encoded_password_csrf_token.zeroize();
        return HttpResponse::err_text_response(ERROR_CRSF_VALIDATION);
    }
    // The password was encoded before the transfer to make sure
    // that special characters would be transferred correctly.
    //
    // Tested with
    // ```ignore
    // PASS^°§$%&/()=?ß\´`+*~'#"-_.:,;<>{}[]öäüÜÄÖáàãÁÀâåæÂÅéèêëÉÈÊËçœŒ|WORD
    // ``````
    let base64_decoded_password = match Vec::from_base64_encoded(base64_encoded_password) {
        Ok(v) => v,
        Err(e) => {
            base64_encoded_password_csrf_token.zeroize();
            warn!("Cannot decode base64 rsa password: {}, {}", &e, &admin);
            return HttpResponse::err_text_response("ERROR: password was not set");
        }
    };
    base64_encoded_password_csrf_token.zeroize();
    let mut decoded_password = match String::from_utf8(base64_decoded_password) {
        Ok(password) => password.trim_matches(char::from(0)).to_string(),
        Err(e) => {
            warn!("could not base64 decode password: {}, {}", &e, &admin);
            return HttpResponse::err_text_response("ERROR: password was not set");
        }
    };
    info!("password has been set, loading rsa keys... {}", &admin);
    let hybrid_crypto = match application_configuration.load_rsa_keys(&decoded_password) {
        Err(e) => {
            // loading the rsa keys did not work, throw the password away
            decoded_password.zeroize();
            warn!("error loading rsa private key: {}, {}", e, admin);
            return HttpResponse::err_text_response("ERROR: could not load rsa private key!");
        }
        Ok(hybrid_crypto) => {
            // Clear the password now, since the rsa keys have been loaded.
            decoded_password.zeroize();
            info!("rsa keys have been loaded successfully {}", &admin);
            hybrid_crypto
        }
    };
    let mut rwlockguard = application_configuration
        .hybrid_crypto_for_secrets
        .write()
        .unwrap();
    *rwlockguard = Some(hybrid_crypto);
    HttpResponse::ok_text_response("OK")
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
    user: AuthenticatedUser,
    application_configuration: web::Data<ApplicationConfiguration>,
) -> HttpResponse {
    debug!("store_secret()");

    let mut parsed_form_data = match parse_and_validate_secret_form_data(
        &bytes,
        &application_configuration,
        &user,
        ValidateCsrfToken::Yes,
    )
    .await
    {
        Ok(parsed_form_data) => parsed_form_data,
        Err(e) => {
            return HttpResponse::err_text_response(e.to_string());
        }
    };

    if let Err(e) =
        encrypt_store_send_secret(&mut parsed_form_data, &application_configuration, None).await
    {
        return HttpResponse::err_text_response(e.to_string());
    }
    HttpResponse::ok_text_response("OK")
}

/// Returns the length of a base64 decoded secret. If it cannot be decoded
/// at all, MAX_FORM_INPUT_LEN + 1 will be returned as length.
fn get_base64_encoded_secret_len(parsed_secret: &str) -> usize {
    let mut decoded_secret = match Vec::from_base64_encoded(parsed_secret) {
        Ok(s) => s,
        Err(e) => {
            warn!("error decoding secret, assuming input too long: {}", &e);
            return MAX_FORM_INPUT_LEN + 1;
        }
    };
    if decoded_secret.len() > MAX_FORM_INPUT_LEN {
        warn!("secret is too large: {} bytes!", &decoded_secret.len());
    }
    let len = decoded_secret.len();
    decoded_secret.zeroize();
    len
}

/// Parses and validates secret form data, so that it can be used from
/// multpile functions.
/// This function is async because we call
/// `<UserDataImpl as GetUserData>::get_receiver_display_name`
/// which queries an external server.
async fn parse_and_validate_secret_form_data(
    bytes: &Bytes,
    application_configuration: &web::Data<ApplicationConfiguration>,
    user: &AuthenticatedUser,
    validate_csrf_token: ValidateCsrfToken,
) -> Result<Secret, Box<dyn std::error::Error>> {
    let bytes_vec = bytes.to_vec();
    let form_data = match String::from_utf8(bytes_vec) {
        Ok(form_data) => form_data,
        Err(_) => {
            warn!("could not parse form data to utf8 string! {}", &user);
            return Err("ERROR: could not parse form data".into());
        }
    };
    debug!("{}", form_data);
    if form_data.len() > MAX_FORM_BYTES_LEN {
        warn!("form data exceeds {} bytes! {}", MAX_FORM_BYTES_LEN, &user);
        return Err(format!(
            "ERROR: more than {} bytes of data sent {}",
            &MAX_FORM_BYTES_LEN, &user
        )
        .into());
    }
    let mut parsed_form_data = match serde_json::from_str(&form_data) as Result<Secret, _> {
        Ok(parsed_form_data) => parsed_form_data,
        Err(e) => {
            warn!(
                "could not parse json form data with secret: {} {}",
                &e, &user
            );
            return Err("ERROR: could not parse json form data".into());
        }
    };
    debug!("parsed_form_data={:?}", &parsed_form_data);
    if ValidateCsrfToken::Yes == validate_csrf_token {
        match parsed_form_data.csrf_token {
            None => {
                warn!("empty csrf token! {}", &user);
                return Err(ERROR_CRSF_VALIDATION.into());
            }
            Some(ref form_data_csrf_token) => {
                if *form_data_csrf_token != user.csrf_token {
                    warn!("csrf token does not match! {}", &user);
                    return Err(ERROR_CRSF_VALIDATION.into());
                }
            }
        }
    }
    if parsed_form_data.from_email.len() > MAX_FORM_INPUT_LEN {
        warn!("from email > {} chars!", MAX_FORM_INPUT_LEN);
        return Err(format!("ERROR: from email > {} chars {}", MAX_FORM_INPUT_LEN, &user).into());
    }
    if parsed_form_data.to_email.len() > MAX_FORM_INPUT_LEN {
        warn!("to email > {} chars!", MAX_FORM_INPUT_LEN);
        return Err(format!("ERROR: to email > {} chars {}", MAX_FORM_INPUT_LEN, &user).into());
    }
    if parsed_form_data.context.len() > MAX_FORM_INPUT_LEN {
        warn!("context > {} chars!", MAX_FORM_INPUT_LEN);
        return Err(format!("ERROR: context > {} chars {}", MAX_FORM_INPUT_LEN, &user).into());
    }
    let secret_length = get_base64_encoded_secret_len(&parsed_form_data.secret);
    if secret_length > MAX_FORM_INPUT_LEN {
        warn!("secret > {} bytes! {}", MAX_FORM_INPUT_LEN, &user);
        return Err(format!("ERROR: secret > {} bytes!", MAX_FORM_INPUT_LEN).into());
    }
    // Check if that looks like an email address before we query some external data source.
    if !application_configuration
        .email_regex
        .is_match(&parsed_form_data.to_email)
    {
        warn!(
            "received invalid destination email address in form data from user {}",
            &user
        );
        // we should return here but for now we just monitor the logs.
    }

    let display_name = match <UserDataImpl as GetUserData>::get_receiver_display_name(
        &parsed_form_data.to_email,
        application_configuration,
    )
    .await
    {
        Ok(display_name) => display_name,
        Err(e) => {
            info!(
                "cannot find receiver email address {}, error: {} {}",
                &parsed_form_data.to_email, &e, &user
            );
            return Err(format!(
                "ERROR: cannot find email address {}",
                &parsed_form_data.to_email
            )
            .into());
        }
    };
    parsed_form_data.to_display_name = display_name;
    // whatever the user sends us, we will use the data we already know.
    parsed_form_data.from_display_name = user.display_name();
    parsed_form_data.from_email.clone_from(&user.mail);
    Ok(parsed_form_data)
}

/// Encrypts parsed secret form data,
/// stores it on disk and sends the email with
/// the link to reveal the secret.
/// This way it can be used from multiple functions.
async fn encrypt_store_send_secret(
    parsed_form_data: &mut Secret,
    application_configuration: &web::Data<ApplicationConfiguration>,
    mail_template_file_option: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // aes encrypt the secret itself before rsa or hybrid rsa/aes encryption
    // of the whole `Secret` struct with meta data.
    let aes = SecretAes256Cbc::random();
    let aes_encrypted_secret = match aes.encrypt_str_to_b64(&parsed_form_data.secret) {
        Ok(encrypted) => encrypted,
        Err(e) => {
            warn!("could not aes encrypt data: {}", &e);
            return Err("ERROR: could not aes encrypt data!".into());
        }
    };

    // replace plaintext secret with the aes encrypted secret
    // before writing to disk.
    let mut plaintext_secret =
        std::mem::replace(&mut parsed_form_data.secret, aes_encrypted_secret);
    plaintext_secret.zeroize();
    // rsa encrypt all data
    let encrypted_form_data = match parsed_form_data.to_encrypted(
        &application_configuration
            .hybrid_crypto_for_secrets
            .read()
            .unwrap(),
    ) {
        Ok(encrypted_form_data) => encrypted_form_data,
        Err(e) => {
            warn!("could not create encrypted form data: {}", &e);
            return Err(format!("ERROR: {}", &e).into());
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
        return Err(format!("ERROR: could not write secret {} to disk!", &path.display()).into());
    };

    info!("success, file {} written", &path.display());
    // build url payload for email
    let url_payload = format!(
        "{};{};{}",
        &uuid.to_string(),
        &aes.iv().to_base64_urlsafe_encoded(),
        &aes.key().to_base64_urlsafe_encoded()
    );
    debug!("url_payload = {}", &url_payload);
    // rsa encrypt url payload
    let hybrid_crypto_rwlock = application_configuration
        .hybrid_crypto_for_secrets
        .read()
        .unwrap();
    let encrypted_url_payload;
    if let Some(rsa_keys) = hybrid_crypto_rwlock.as_deref() {
        match rsa_keys.encrypt_str_pkcs1v15_padding_to_b64(&url_payload) {
            Ok(encrypted_payload) => {
                encrypted_url_payload = encrypted_payload;
            }
            Err(e) => {
                warn!("could not rsa encrypt url payload: {}", &e);
                return Err(format!("ERROR: {}", &e).into());
            }
        }
    } else {
        info!("RSA private key has not been loaded, cannot store secret.");
        return Err("System not ready for encryption!".into());
    }
    drop(hybrid_crypto_rwlock);
    let encrypted_percent_encoded_url_payload =
        utf8_percent_encode(&encrypted_url_payload, FRAGMENT);
    debug!(
        "encrypted_percent_encoded_url_payload = {}",
        &encrypted_percent_encoded_url_payload
    );
    // load the optional mail template file or the default in the application configuration.
    let mail_body_template_option = match mail_template_file_option {
        None => application_configuration
            .configuration_file
            .email_configuration
            .load_mail_template(),
        Some(template_filename) => {
            ValidatedAccessTokenPayload::load_mail_template(&template_filename)
        }
    };
    let mail_body_template = match mail_body_template_option {
        Ok(mail_body_template) => mail_body_template,
        Err(e) => {
            warn!("error loading mail template: {}", &e);
            return Err("ERROR: cannot send email!".into());
        }
    };
    // Build body and subject, then send email to receiver.
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

    if let Err(e) = &application_configuration
        .configuration_file
        .email_configuration
        .send_mail(
            &parsed_form_data.to_email,
            &parsed_form_data.from_email,
            mail_subject,
            mail_body,
        )
    {
        warn!(
            "error sending email to {} for secret {}: {}",
            &parsed_form_data.to_email,
            &uuid.to_string(),
            &e
        );
        return Err("ERROR: cannot send email!".into());
    };
    Ok(())
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
    let hybrid_crypto_rwlock = application_configuration
        .hybrid_crypto_for_secrets
        .read()
        .unwrap();

    let url_payload;
    if let Some(rsa_keys) = hybrid_crypto_rwlock.as_deref() {
        match rsa_keys.decrypt_b64_pkcs1v15_padding_to_string(&encrypted_url_payload) {
            Err(e) => {
                warn!("could not rsa decrypt url payload: {}", &e);
                return HttpResponse::err_text_response(format!("ERROR: {}", &e));
            }
            Ok(payload) => {
                url_payload = payload;
            }
        }
    } else {
        info!("RSA private key has not been loaded, cannot reveal secret.");
        return HttpResponse::err_text_response("System not ready for decryption!");
    }
    drop(hybrid_crypto_rwlock);
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
    // cargo clippy is unhappy here, but we `drop`ed hybrid_crypto_rwlock.
    let hybrid_encrypted_secret_file_content = match Secret::read_from_disk(&path).await {
        Ok(hybrid_encrypted_secret) => hybrid_encrypted_secret,
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
    // Decrypt the stored values that are either
    // - rsa enrypted only or
    // - hybrid encrypted
    let hybrid_crypto_rwlock = application_configuration
        .hybrid_crypto_for_secrets
        .read()
        .unwrap();
    let mut hybrid_decrypted_file_content;
    if let Some(hybrid_crypto) = hybrid_crypto_rwlock.as_ref() {
        match hybrid_encrypted_secret_file_content.to_decrypted(hybrid_crypto) {
            Err(e) => {
                return HttpResponse::err_text_response(format!("ERROR: {}", &e));
            }
            Ok(decrypted_file_content) => {
                hybrid_decrypted_file_content = decrypted_file_content;
            }
        }
    } else {
        info!("RSA private key has not been loaded, cannot reveal secret.");
        return HttpResponse::err_text_response("System not ready for decryption!");
    }
    drop(hybrid_crypto_rwlock);
    debug!("aes_encrypted = {}", &hybrid_decrypted_file_content.secret);

    // check if user is entitled to reveal this secret
    if hybrid_decrypted_file_content.to_email.to_lowercase() != user.mail.to_lowercase() {
        warn!(
            "user {} (mail = {}) wants unjustified access to secret {} (entitled to_email = {})",
            &user.user_name, &user.mail, &uuid, &hybrid_decrypted_file_content.to_email
        );
        return HttpResponse::err_text_response("ERROR: access to secret not permitted!");
    }
    let decrypted_secret = match hybrid_decrypted_file_content
        .secret
        .decrypt_b64_aes(key_base64, iv_base64)
    {
        Ok(decrypted_secret) => decrypted_secret,
        Err(e) => {
            info!("could not aes decrypt data: {}", &e);
            return HttpResponse::err_text_response(format!("ERROR: {}", &e));
        }
    };
    // put the plaintext secret into the struct
    hybrid_decrypted_file_content.secret = decrypted_secret;
    let json_response = match serde_json::to_string(&hybrid_decrypted_file_content) {
        Err(e) => {
            warn!("could not build decrypted json struct: {}", &e);
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
        display_name: user.display_name(),
        mail: user.mail.clone(),
    };
    match serde_json::to_string(&user_details) {
        Err(e) => {
            warn!("cannot get user details: {}", &e);
            HttpResponse::err_text_response("ERROR: cannot get user details!")
        }
        Ok(json) => HttpResponse::ok_json_response(json),
    }
}

/// Validate email address of the receiver before sending the form.
/// An invalid email address will prevent sending the form.
/// Returns lower case `receiver_email` as result string if the mail
/// could be validated, else return `crate::UNKOWN_RECEIVER_EMAIL`
/// as result string to the frontend.
pub async fn get_validated_receiver_email(
    email_path: web::Path<String>,
    user: AuthenticatedUser,
    application_configuration: web::Data<ApplicationConfiguration>,
) -> HttpResponse {
    debug!("get_validated_receiver_email()");
    let email = email_path.into_inner();
    // Check if that looks like an email address before we query some external data source.
    if !application_configuration.email_regex.is_match(&email) {
        info!(
            "received invalid email format from user {}",
            &user.user_name
        );
        return HttpResponse::ok_text_response(UNKNOWN_RECEIVER_EMAIL.to_string());
    }

    let receiver_email = match <UserDataImpl as GetUserData>::validate_email_address(
        &email,
        &application_configuration,
    )
    .await
    {
        Ok(receiver_email) => receiver_email,
        Err(e) => {
            info!("cannot find mail address {}, error: {}", &email, &e);
            return HttpResponse::ok_text_response(UNKNOWN_RECEIVER_EMAIL.to_string());
        }
    };
    HttpResponse::ok_text_response(receiver_email.to_ascii_lowercase())
}

/// Get admin protected sysop.js.
pub async fn get_sysop_js(_admin: AuthenticatedAdministrator) -> impl Responder {
    NamedFile::open_async("web-content/admin-html/js/sysop.js").await
}

/// Renew cookie lifetime for the authenticated user by setting the
/// current timestamp.
pub async fn keep_session_alive(req: HttpRequest, _user: AuthenticatedUser) -> HttpResponse {
    update_authenticated_user_cookie_lifetime(&req)
}

/// Custom 404 handler
///
/// Returns 404.html or plain error message if file cannot be found.
pub async fn not_found_404() -> HttpResponse {
    let file_path = Path::new("web-content/static/404.html");
    let file_content =
        read_to_string(file_path).unwrap_or_else(|_| -> String { "404 not found".into() });
    HttpResponse::build(StatusCode::NOT_FOUND)
        .content_type("text/html; charset=UTF-8")
        .body(file_content)
}

/// Stores a secret and its meta data as encrypted file on disk.
/// This function is used by scripts where the caller presents
/// an access token for authentication that we provided manually beforehand.
#[cfg(feature = "api-access-token")]
pub async fn api_v1_store_secret(
    bytes: Bytes,
    validated_access_token_payload: ValidatedAccessTokenPayload,
    application_configuration: web::Data<ApplicationConfiguration>,
) -> HttpResponse {
    debug!("api_v1_store_secret()");

    // At this point the `AccessTokenPayload` has been validated
    // and is presented as `ValidatedAccessTokenPayload` with extra
    // meta data, e.g. like ip address, name and email of the sender.
    // We construct an artificial `AuthenticatedUser` to send the email
    // with the link to the secret.
    let script_user = AuthenticatedUser::new(
        validated_access_token_payload.sub,
        validated_access_token_payload.from_display_name,
        "".to_string(),
        validated_access_token_payload.from_email,
        AccessScope::ScriptUser,
        validated_access_token_payload.ip_address,
    );
    let mut parsed_form_data = match parse_and_validate_secret_form_data(
        &bytes,
        &application_configuration,
        &script_user,
        ValidateCsrfToken::No,
    )
    .await
    {
        Ok(parsed_form_data) => parsed_form_data,
        Err(e) => {
            return HttpResponse::err_text_response(e.to_string());
        }
    };

    if let Err(e) = encrypt_store_send_secret(
        &mut parsed_form_data,
        &application_configuration,
        validated_access_token_payload.mail_template_file,
    )
    .await
    {
        return HttpResponse::err_text_response(e.to_string());
    }
    HttpResponse::ok_text_response("OK")
}

/// Default route if feature is disabled.
#[cfg(not(feature = "api-access-token"))]
pub async fn api_store_secret(_req: HttpRequest) -> HttpResponse {
    warn!("route access forbidden (api access token)!");
    HttpResponse::err_text_response("ERROR forbidden!")
}

/// Returns tell.html page with injected CSRF token,
pub async fn csrf_template_tell_html(user: AuthenticatedUser) -> HttpResponse {
    debug!("tell.html is requested from {}", &user);
    match inject_csrf_token(CsrfTemplateFile::Tell, &user.csrf_token).await {
        Err(e) => {
            warn!("{}", e);
            not_found_404().await
        }
        Ok(body) => HttpResponse::Ok()
            .content_type("text/html; charset=UTF-8")
            .append_header(("X-Content-Type-Options", "nosniff"))
            .body(body),
    }
}

/// Returns sysop.html page with injected CSRF token,
pub async fn csrf_template_sysop_html(admin: AuthenticatedAdministrator) -> HttpResponse {
    debug!("sysop.html is requested from {}", &admin);
    match inject_csrf_token(CsrfTemplateFile::Sysop, &admin.csrf_token()).await {
        Err(e) => {
            warn!("{}", e);
            not_found_404().await
        }
        Ok(body) => HttpResponse::Ok()
            .content_type("text/html; charset=UTF-8")
            .append_header(("X-Content-Type-Options", "nosniff"))
            .body(body),
    }
}
