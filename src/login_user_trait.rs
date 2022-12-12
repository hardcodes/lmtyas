//#[macro_use]
extern crate env_logger;
use crate::configuration::ApplicationConfiguration;
use crate::http_traits::CustomHttpResponse;
pub use crate::mail_noauth_notls::SendEMail;
use actix_web::web::Bytes;
use actix_web::{web, HttpResponse, HttpRequest};
use async_trait::async_trait;
use log::{debug, error};
use std::error::Error;

#[async_trait(?Send)]
pub trait Login {
    /// This function is called when a user logs in.
    ///
    /// Arguments
    /// 
    /// - `bytes`:                     the bytes send from the browser
    ///                                more complicated to parse than, e.g. using `web::Form<FormData>`
    ///                                but universal. Future versions might implement SAML and
    ///                                have different needs that can be satisfied this way.
    /// - `application_configuration`: application configuration
    ///
    /// # Returns
    ///
    /// - `HttpResponse`
    async fn login_user(
        bytes: Bytes,
        http_request: HttpRequest,
        application_configuration: web::Data<ApplicationConfiguration>,
    ) -> HttpResponse {
        debug!("bytes = {:?}", &bytes);
        debug!("http_request = {:?}", &http_request);
        debug!(
            "application_configuration.configuration_file = {:?}",
            &application_configuration.configuration_file
        );
        error!("login_user() - default implementaion, no login possible");
        HttpResponse::err_text_response("ERROR: default implementaion, no login possible")
    }
    /// Hook for login implementations that need to load the
    /// user database from a file.
    /// The default does nothing, so you must not
    /// provide a dummy implementation when no file
    /// is needed at all.
    fn load_login_configuration(&mut self) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    /// This function will be called when the application configuration
    /// has been loaded.
    /// No default implementation, so you are forced to build a regex.
    fn build_valid_user_regex(&mut self) -> Result<(), Box<dyn Error>>;
}
