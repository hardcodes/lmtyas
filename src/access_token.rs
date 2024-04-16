use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub struct AccessTokenHeader{
    pub alg: String,
    pub typ: String,
}

pub struct AccessTokenPayload{
    pub iss: String,
    pub sub: Uuid,
    pub aud: String,
    pub nbf: String,
    pub iat: String,
    pub exp: String,
    pub jti: String,
}

pub struct AccessToken{
    header: AccessTokenHeader,
    payload: AccessTokenPayload,
}

pub struct AccessTokenConfiguration {
    pub api_access_files: String,
    pub rsa_private_key_file: String,
    pub rsa_public_key_file: String,
}

pub struct AccessTokenFile{
    pub ip_adresses: Vec<String>,
    pub nbf: String,
    pub iat: String,
    pub exp: String,
}
