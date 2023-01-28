use lmtyas::aes_functions::{DecryptAes, EncryptAes};

#[test]
fn test_aes_functions() {
    const PLAINTEXT: &str = "plaintext";
    let aes_encrytpted = PLAINTEXT.to_string().to_aes_enrypted_b64();
    if let Ok(aes_encrypted_unwrapped) = aes_encrytpted {
        let decrypted = aes_encrypted_unwrapped.encrypted_data.decrypt_b64_aes(
            &aes_encrypted_unwrapped.encryption_key,
            &aes_encrypted_unwrapped.encryption_iv,
        );
        assert_eq!(
            PLAINTEXT,
            decrypted.unwrap(),
            "aes decrypted message does not match plaintext!"
        );
    } else {
        panic!("cannot unwrap aes encrypted result!")
    }
}
