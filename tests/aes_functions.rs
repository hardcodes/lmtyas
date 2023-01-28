use lmtyas::aes_functions::{DecryptAes, EncryptAes};
use regex::Regex;

#[test]
fn test_aes_functions() {
    const BASE64_REGEX: &str = "^[A-Za-z0-9-_=]+$";
    let base64_regex = Regex::new(BASE64_REGEX).unwrap();
    const PLAINTEXT: &str = "plaintext";
    let aes_encrytpted = PLAINTEXT.to_string().to_aes_enrypted_b64();
    let aes_encrytpted2 = PLAINTEXT.to_string().to_aes_enrypted_b64();
    if let Ok(aes_encrypted_unwrapped) = aes_encrytpted {
        if let Ok(aes_encrypted_unwrapped2) = aes_encrytpted2 {
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
                aes_encrypted_unwrapped.encryption_key,
                aes_encrypted_unwrapped2.encryption_key,
                "encryption keys should not be equal after 2 calls!"
            );
            assert_ne!(
                aes_encrypted_unwrapped.encryption_iv,
                aes_encrypted_unwrapped2.encryption_iv,
                "encryption iv should not be equal after 2 calls!"
            );
        } else {
            panic!("cannot unwrap aes encrypted result2!")
        }
    } else {
        panic!("cannot unwrap aes encrypted result!")
    }
}
