use lmtyas::rsa_functions::RsaKeys;
use regex::Regex;
use secstr::SecStr;
use std::path::Path;

const WORKSPACE_DIR: &str = env!("CARGO_MANIFEST_DIR");

#[test]
fn rsa_functions() {
    const RSA_PASSPHRASE: &str = "12345678901234";
    // see https://www.rfc-editor.org/rfc/rfc3548#section-3
    const BASE64_REGEX: &str = r"^[A-Za-z0-9\+/=]+$";
    let base64_regex = Regex::new(BASE64_REGEX).unwrap();
    const PLAINTEXT: &str = "plaintext";

    let secure_rsa_passphrase = SecStr::from(RSA_PASSPHRASE);
    let mut rsa_keys = RsaKeys::new();
    if let Err(e) = rsa_keys.read_from_files(
        Path::new(WORKSPACE_DIR).join("resources/tests/rsa/lmtyas_rsa_private.key"),
        Path::new(WORKSPACE_DIR).join("resources/tests/rsa/lmtyas_rsa_public.key"),
        &secure_rsa_passphrase,
    ) {
        panic!("cannot load rsa keys! {}", &e);
    };

    let rsa_encrytpted = rsa_keys.rsa_encrypt_str(PLAINTEXT);
    let rsa_encrytpted2 = rsa_keys.rsa_encrypt_str(PLAINTEXT);
    let rsa_encrypted_unwrapped = match rsa_encrytpted {
        Ok(r) => r,
        Err(e) => {
            panic!("cannot unwrap rsa encrypted result! {}", &e);
        }
    };
    let rsa_encrypted_unwrapped2 = match rsa_encrytpted2 {
        Ok(r) => r,
        Err(e) => {
            panic!("cannot unwrap rsa encrypted result2! {}", &e);
        }
    };

    assert!(
        base64_regex.is_match(&rsa_encrypted_unwrapped),
        "rsa encrypted data is not converted correctly to base64: {}",
        &rsa_encrypted_unwrapped
    );
    let decrypted = rsa_keys.rsa_decrypt_str(&rsa_encrypted_unwrapped);
    assert_eq!(
        PLAINTEXT,
        decrypted.unwrap(),
        "rsa decrypted message does not match plaintext!"
    );
    assert_ne!(
        rsa_encrypted_unwrapped, rsa_encrypted_unwrapped2,
        "rsa encrypted data should not be equal after 2 calls!"
    );
}

#[test]
fn rsa_functions_hybrid() {
    const RSA_PASSPHRASE: &str = "12345678901234";
    // see https://www.rfc-editor.org/rfc/rfc3548#section-3
    const BASE64_REGEX: &str = r"^[A-Za-z0-9\+/=.]+$";
    let base64_regex = Regex::new(BASE64_REGEX).unwrap();
    const PLAINTEXT: &str = "plaintext";

    let secure_rsa_passphrase = SecStr::from(RSA_PASSPHRASE);
    let mut rsa_keys = RsaKeys::new();
    if let Err(e) = rsa_keys.read_from_files(
        Path::new(WORKSPACE_DIR).join("resources/tests/rsa/lmtyas_rsa_private.key"),
        Path::new(WORKSPACE_DIR).join("resources/tests/rsa/lmtyas_rsa_public.key"),
        &secure_rsa_passphrase,
    ) {
        panic!("cannot load rsa keys! {}", &e);
    };

    let rsa_encrytpted = rsa_keys.hybrid_encrypt_str(PLAINTEXT);
    let rsa_encrytpted2 = rsa_keys.hybrid_encrypt_str(PLAINTEXT);
    let rsa_encrypted_unwrapped = match rsa_encrytpted {
        Ok(r) => r,
        Err(e) => {
            panic!("cannot unwrap rsa hybrid encrypted result! {}", &e);
        }
    };
    let rsa_encrypted_unwrapped2 = match rsa_encrytpted2 {
        Ok(r) => r,
        Err(e) => {
            panic!("cannot unwrap rsa hybrid encrypted result2! {}", &e);
        }
    };

    assert!(
        base64_regex.is_match(&rsa_encrypted_unwrapped),
        "rsa hybrid encrypted data is not converted correctly to base64: {}",
        &rsa_encrypted_unwrapped
    );
    let decrypted = rsa_keys.hybrid_decrypt_str(&rsa_encrypted_unwrapped);
    assert_eq!(
        PLAINTEXT,
        decrypted.unwrap(),
        "rsa hybrid decrypted message does not match plaintext!"
    );
    assert_ne!(
        rsa_encrypted_unwrapped, rsa_encrypted_unwrapped2,
        "rsa hybrid encrypted data should not be equal after 2 calls!"
    );

    assert!(
        rsa_keys.hybrid_decrypt_str("RHVtbXk=").is_err(),
        "inputting invalid data into hybrid_decrypt_str should yield error"
    );
}
