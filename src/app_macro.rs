/// This macro rule contains all routes that are used to build the service.
/// Creating them with a macro makes them reusable for testing. Idea taken from
/// https://stackoverflow.com/questions/72415245/actix-web-integration-tests-reusing-the-main-thread-application
/// See answer from Ovidiu Gheorghies.
#[macro_export]
macro_rules! app (
    ($application_configuration: expr, $content_security_policy: expr, $max_payload: expr) => ({
        App::new()
            // Enable the logger.
            .wrap(
                middleware::Logger::new("%a %{CUSTOM_REQUEST}xi %s %b %{User-Agent}i %T")
                    // exclude the password from appearing in the log
                    .exclude_regex("/authenticated/sysop/set_password_for_rsa_rivate_key")
                    .exclude_regex("/authenticated/secret/reveal")
                    .custom_request_replace("CUSTOM_REQUEST", |req| {
                        extract_request_path(format!("{} {}", &req.method(), &req.uri()).as_str())
                    }),
            )
            .wrap(
                middleware::DefaultHeaders::new()
                    .add((
                        "Strict-Transport-Security",
                        "max-age=31536000; includeSubDomains",
                    ))
                    // Disable caching. This is no CDN or social media site with
                    // high throughput. But some browsers tend to show outdated
                    // versions of our data. Better make sure they do not cache at all.
                    .add(("Cache-Control", "no-cache"))
                    .add(("Content-Security-Policy", $content_security_policy))
                    .add(("X-Frame-Options", "DENY"))
                    .add(("X-Content-Type-Options", "nosniff")),
            )
            // clone of the application configuration
            .app_data(web::Data::new($application_configuration.clone()))
            // By default, the payload size limit is 256kB and there is no mime type condition.
            .app_data(web::PayloadConfig::new($max_payload))
            // set one route without authentication so that monitoring software can check if we are still running
            .service(web::scope("/monitoring").route("/still_alive", web::get().to(still_alive)))
            // routes without authentication to get information about the running server
            .service(
                web::scope("/system")
                    .route("/is_server_ready", web::get().to(is_server_ready))
                    .route("/get/login-hint", web::get().to(get_login_hint))
                    .route("/get/mail-hint", web::get().to(get_mail_hint))
                    .route("/get/imprint-link", web::get().to(get_imprint_link))
                    .route("/get/privacy-link", web::get().to(get_privacy_link)),
            )
            .service(web::resource("/").route(web::get().to(redirect_to_index)))
            // routes for authenticated administrators only
            .service(
                web::scope("authenticated/sysop")
                    .wrap(CheckAuthentication)
                    .route(
                        "/set_password_for_rsa_rivate_key/{password}",
                        web::post().to(set_password_for_rsa_rivate_key),
                    )
                    // serve files to admins only
                    // for just two files dedicated functions are fine
                    // with more to come a more generic approach must be used
                    .route("/sysop.html", web::get().to(get_sysop_html))
                    .route("/js/sysop.js", web::get().to(get_sysop_js)),
            )
            // routes for authenticated regular users
            .service(
                web::scope("authenticated/secret")
                    .wrap(CheckAuthentication)
                    .route("/tell", web::post().to(store_secret))
                    .route(
                        "/reveal/{encrypted_percent_encoded_url_payload}",
                        web::get().to(reveal_secret),
                    ),
            )
            .service(
                web::scope("authenticated/user")
                    .wrap(CheckAuthentication)
                    .route(
                        "/get/details/from",
                        web::get().to(get_authenticated_user_details),
                    ),
            )
            .service(
                web::scope("authenticated/receiver")
                    .wrap(CheckAuthentication)
                    .route(
                        "/get/validated_email/{email}",
                        web::get().to(get_validated_receiver_email),
                    ),
            )
            .service(
                web::scope("authenticated")
                    .wrap(CheckAuthentication)
                    .route("/keep_session_alive", web::get().to(keep_session_alive)),
            )
            .service(
                web::scope("api")
                .route("/v1/secret", web::post().to(api_store_secret))
            )
            .service(
                web::scope("html")
                    .wrap(CheckAuthentication)
                    .service(Files::new("/", "web-content/authenticated/").index_file("tell.html")),
            )
            .service(
                web::scope("authentication")
                    .route(
                        // the `const AUTH_ROUTE` selects the route
                        // where the authentication is processed.
                        authentication_url::AUTH_ROUTE,
                        // the `AuthConfiguration` type is defined by a selected
                        // feature that implements the `Login` trait. This trait
                        // can process posted form data or other means of login
                        // data, e.g. saml2 oder oidc resonses.
                        //
                        // Exclude POST in `Login` trait implementation if needed!
                        web::post().to(<AuthConfiguration as Login>::login_user),
                    )
                    .route(
                        // See explanation above.
                        authentication_url::AUTH_ROUTE,
                        // Exclude GET in `Login` trait implementation if needed!
                        web::get().to(<AuthConfiguration as Login>::login_user),
                    )
                    // the `const AUTH_PATH` and `const AUTH_INDEX_PAGE`
                    // are defined by a selected authentication feature that
                    // points to a possible login or index page.
                    .service(
                        Files::new("/", authentication_url::AUTH_PATH)
                            .index_file(authentication_url::AUTH_INDEX_PAGE),
                    ),
            )
            // serve custom favicon if it exists
            .route("/gfx/favicon.png", web::get().to(get_favicon))
            // serve custom site logo if it exists
            .route("/gfx/company-logo.png", web::get().to(get_company_logo))
            // serve custom colors.css file if it exists
            .route("/css/colors.css", web::get().to(get_colors_css))
            // serve custom lmtyas.css file if it exists
            .route("/css/lmtyas.css", web::get().to(get_lmtyas_css))
            .service(Files::new("/", "./web-content/static/").index_file("index.html"))
            .service(
                web::resource("").route(
                    web::route()
                        .guard(guard::Trace())
                        .to(HttpResponse::MethodNotAllowed),
                ),
            )
            .default_service(web::to(not_found_404))
    });
);
