//#[macro_use]
extern crate env_logger;
use crate::configuration::ApplicationConfiguration;
use actix_web::web;
use async_trait::async_trait;

/// This trait is used to force one implementation of a get_display_name()
/// function. The implementation may change depending on the authentication
/// method used.
#[async_trait]
pub trait GetUserData {
    /// This function is called when a secret is transmitted
    /// to get the display name of the receiver. At this
    /// point we only know of the email address.
    async fn get_receiver_display_name(
        mail: &str,
        application_configuration: &web::Data<ApplicationConfiguration>,
    ) -> Result<String, String>;

    /// This function is called to validate the entered receiver email address
    /// before the form is transmitted to the server.
    /// 
    /// If there is no way to validate the email address, simply
    /// return `mail` as result string.
    async fn validate_email_address(
        mail: &str,
        application_configuration: &web::Data<ApplicationConfiguration>,
    ) -> Result<String, String>;
}

pub struct NoUserDataBackend;

#[async_trait]
impl GetUserData for NoUserDataBackend {
    async fn get_receiver_display_name(_mail: &str,
        _application_configuration: &web::Data<ApplicationConfiguration>,
    ) -> Result<String, String>{
        Ok("".to_string())
    }

    async fn validate_email_address(mail: &str,
        _application_configuration: &web::Data<ApplicationConfiguration>,
    ) -> Result<String, String>{
        Ok(mail.to_string())
    }

}
