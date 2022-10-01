#[async_trait]
pub trait Login {
    /// This function is called to query data for the
    /// receiving user of a secret.
    ///
    /// Arguments
    ///
    /// - `user_name`:                 uid of the user to query data from.
    /// - `application_configuration`: application configuration
    ///
    /// # Returns
    ///
    /// - `HttpResponse`
    async fn query_user_data(
        user_name: web::Path<String>,
        application_configuration: web::Data<ApplicationConfiguration>,
    ) -> HttpResponse;
}
