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
    ///
    /// Arguments
    ///
    /// - `mail`:                      email address of the user we want more details about
    /// - `application_configuration`: application configuration
    ///
    /// # Returns
    ///
    /// - `Result<String, Box<dyn Error>>`
    async fn get_receiver_display_name(
        mail: &str,
        application_configuration: &web::Data<ApplicationConfiguration>,
    ) -> Result<String, String>;
}
