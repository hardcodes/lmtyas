use lmtyas::aes_functions::{DecryptAes, EncryptAes};
use regex::Regex;

#[test]
fn aes_functions() {
    const BASE64_REGEX: &str = "^[A-Za-z0-9-_=]+$";
    let base64_regex = Regex::new(BASE64_REGEX).unwrap();
    const PLAINTEXT: &str = r#"PASS!"§$%&/()=?ß\´`+*~'#-_.:,;<>öäü|WORD"#;
    let aes_encrytpted = PLAINTEXT.to_string().to_aes_enrypted_b64();
    let aes_encrytpted2 = PLAINTEXT.to_string().to_aes_enrypted_b64();
    let aes_encrypted_unwrapped = match aes_encrytpted {
        Ok(a) => a,
        Err(e) => {
            panic!("cannot unwrap aes encrypted result! {}", &e);
        }
    };
    let aes_encrypted_unwrapped2 = match aes_encrytpted2 {
        Ok(a) => a,
        Err(e) => {
            panic!("cannot unwrap aes encrypted result2! {}", &e);
        }
    };
    // Check if encrypted value is URL safe
    // https://www.rfc-editor.org/rfc/rfc3548#section-4
    assert!(
        base64_regex.is_match(&aes_encrypted_unwrapped.encrypted_data),
        "aes encrypted data is not converted correctly to base64: {}",
        &aes_encrypted_unwrapped.encrypted_data
    );
    let decrypted = aes_encrypted_unwrapped.encrypted_data.decrypt_b64_aes(
        &aes_encrypted_unwrapped.encryption_key,
        &aes_encrypted_unwrapped.encryption_iv,
    );
    assert_eq!(
        PLAINTEXT,
        decrypted.unwrap(),
        "aes decrypted message does not match plaintext!"
    );
    assert_ne!(
        aes_encrypted_unwrapped.encryption_key, aes_encrypted_unwrapped2.encryption_key,
        "encryption keys should not be equal after 2 calls!"
    );
    assert_ne!(
        aes_encrypted_unwrapped.encryption_iv, aes_encrypted_unwrapped2.encryption_iv,
        "encryption iv should not be equal after 2 calls!"
    );
}
