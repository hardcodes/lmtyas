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
    // base64 encoded "Not encrypted"
    const NOT_ENCRYPTED: &str = "Tm90IGVuY3J5cHRlZA==";

    let secure_rsa_passphrase = SecStr::from(RSA_PASSPHRASE);
    let mut rsa_keys = RsaKeys::new();
    if let Err(e) = rsa_keys.read_from_files(
        Path::new(WORKSPACE_DIR).join("resources/tests/rsa/lmtyas_rsa_private.key"),
        Path::new(WORKSPACE_DIR).join("resources/tests/rsa/lmtyas_rsa_public.key"),
        &secure_rsa_passphrase,
    ) {
        panic!("cannot load rsa keys! {}", &e);
    };

    let rsa_public_encrytpted = rsa_keys.rsa_public_key_encrypt_str(PLAINTEXT);
    let rsa_public_encrytpted2 = rsa_keys.rsa_public_key_encrypt_str(PLAINTEXT);
    let rsa_public_encrypted_unwrapped = match rsa_public_encrytpted {
        Ok(r) => r,
        Err(e) => {
            panic!("cannot unwrap rsa encrypted result! {}", &e);
        }
    };
    let rsa_public_encrypted_unwrapped2 = match rsa_public_encrytpted2 {
        Ok(r) => r,
        Err(e) => {
            panic!("cannot unwrap rsa encrypted result2! {}", &e);
        }
    };

    assert!(
        base64_regex.is_match(&rsa_public_encrypted_unwrapped),
        "rsa encrypted data is not converted correctly to base64: {}",
        &rsa_public_encrypted_unwrapped
    );
    let rsa_private_decrypted =
        rsa_keys.rsa_private_key_decrypt_str(&rsa_public_encrypted_unwrapped);
    assert_eq!(
        PLAINTEXT,
        rsa_private_decrypted.unwrap(),
        "rsa decrypted message does not match plaintext!"
    );
    assert_ne!(
        rsa_public_encrypted_unwrapped, rsa_public_encrypted_unwrapped2,
        "rsa encrypted data should not be equal after 2 calls!"
    );
    let rsa_private_decrypted_fail = rsa_keys.rsa_private_key_decrypt_str(&NOT_ENCRYPTED);
    assert!(
        rsa_private_decrypted_fail.is_err(),
        "should not be able to decrypt this message!"
    );

    const HYBRID_ENCRYPTED: &str = "v1.aqkErs/pC4fRO/TULm7ziRqE8ShY0gCQOzx0/u1DHtHOTnO9JUWFLwXUl0kX3Q0nf5kK2icN6nV8GxFxSnIcDLQ3PDnULANtsuD5ZQNAlTu0RWJj1aOqd9QR9aw2mgMR5/qN8qhnU/OnSZt17xRFHFRYa4aZcisFkGzILCRsv5NH7MI/dT6PUELT1HrNI046A3V1mE6MzVBgFiFjmWyp7yp3to2cL7tRyNODAIcjZXeD6CECykd8Js7REHuW5eAQ2wrlMZpG9kaEZTas9GWhYRvBDzXkLF7mEWo0MaEVpe2vojB6osNkYFvPdEK4cHolrgg5Ho7FpvSkbRO1rVJ+DTx7+kisBzIyFIgy8FTjJnncWJx1WeCnXyzMV50eFTYi3GnxuWdGB3oDAV/LgpaGM0xZ7n5pmMce5IDfU+bjQaSL/kLodQUnivuT3T17zhUOzYp7F6KbOTlcFw/KvklsWvhLKsB2o90zpyllH/eBwY1Gq6vdRTUpuj8IsEs5nWvvxvFaAccO2q2bd519YgQ8H5VsUTqdhTAEp26zZh4mADgwucHfGnlIWR0DY5rkuJ3Af9so2nPjrNCpxtQwalpXDr/eIP7yr2pSVgJF2cXmEjQYF+YEQ8IEYclLUR9e3byz4h+b2QTaBXPZD5zihC7/XK3Fzcjdpi5q0oWDq6rpn8Q=.NO0EWqlWFqDNOuMV1Y7u0J/pTgIlPybIvFDT5F1CYrw=";
    const HYBRID_PLAINTEXT: &str = "coffee-is-better-than-java";
    let decrypted = rsa_keys.hybrid_decrypt_str(HYBRID_ENCRYPTED);
    assert_eq!(
        HYBRID_PLAINTEXT,
        decrypted.unwrap(),
        "hybrid decrypted message does not match plaintext!"
    );

    let hybrid_encrypted = rsa_keys.hybrid_encrypt_str(PLAINTEXT).unwrap();
    let hybrid_decrypted = rsa_keys.hybrid_decrypt_str(&hybrid_encrypted).unwrap();
    assert_eq!(
        PLAINTEXT, hybrid_decrypted,
        "hybrid decrypted message does not match plaintext!"
    );

    // see resources/tests/access_token_files/5ca81a4c-9c04-4c94-a2e7-c8349288445b
    const VALID_SIGNED_DATA: &str = "5ca81a4c-9c04-4c94-a2e7-c8349288445b";
    // signature was created in bash:
    // ```bash
    // UUID="5ca81a4c-9c04-4c94-a2e7-c8349288445b"
    // SIG=$(mktemp)
    // echo -n "${UUID}"|openssl dgst -sha512 -sign resources/tests/rsa/lmtyas_rsa_private.key > "${SIG}"
    // # Enter pass phrase for resources/tests/rsa/lmtyas_rsa_private.key: 12345678901234
    // cat "${SIG}"|base64 -w 0 # we would encode it for transport
    // # wtHWCqUULzycA1q5YgW/W6l3qqFgWhcDhX5EQ+2GfTm9NQdTt8YfBTZjxtstM4/gG0YTfmlKajvkhz95Vo4pHbXPSgWAI0uu3rWIfZf47ApBMt76JvSI75KPC73StTBeRNaXCrXd3yCUsMgqQou/gEnendZgc4c6FU8aQqQQJVkjDZ0Rfswjz0kAPDcn1uiiLo0m6FGglIKQhPFwm6W8bAzbXzKZyXXTUx+l+ew4r/v+fZM4rM3LS4hm4DbY9Q4SD5SHalXAARrxvAcsMINycAQDMt6BZkdUd9gk3tbHiAaS7Bfpp11mIdEiyOhUkRSWA/201mD+qOEVe0g8QPbuYhnlf2t4ZiBlA4JM7M6Wtgjtss5c7fGp7M0jY0xhkMeqxfnKbPlbLDH3nvRTzzs2w/pXBSgceEqheKhEQsVvhj4hVsk9fk0O/DNa4veA5zZSNEm5GoMK6me3wLxABKoHpEZ9Bbp7m7jH4TkX6mpIYi1t/bL0HKsq2Fn0aPj88VkbURkJoer/r24T9YyTEJGamMt+f8nLI68iQ+u9DSRKKvM5zG5JtapYhK/mnB6d7w0h0w7eLqZZLo1X8cUcDxR80OL64Kxg0CndhwbcRabj5/YSZNBKodsc2DDwLujF9PQ9IBVF98K0fYHwMb6VAJY9PDoLPt0LAFiFd2aSA5i6Ja4=
    // rm -f "${SIG}"
    // ```
    const VALID_SIGNATURE: &str = "wtHWCqUULzycA1q5YgW/W6l3qqFgWhcDhX5EQ+2GfTm9NQdTt8YfBTZjxtstM4/gG0YTfmlKajvkhz95Vo4pHbXPSgWAI0uu3rWIfZf47ApBMt76JvSI75KPC73StTBeRNaXCrXd3yCUsMgqQou/gEnendZgc4c6FU8aQqQQJVkjDZ0Rfswjz0kAPDcn1uiiLo0m6FGglIKQhPFwm6W8bAzbXzKZyXXTUx+l+ew4r/v+fZM4rM3LS4hm4DbY9Q4SD5SHalXAARrxvAcsMINycAQDMt6BZkdUd9gk3tbHiAaS7Bfpp11mIdEiyOhUkRSWA/201mD+qOEVe0g8QPbuYhnlf2t4ZiBlA4JM7M6Wtgjtss5c7fGp7M0jY0xhkMeqxfnKbPlbLDH3nvRTzzs2w/pXBSgceEqheKhEQsVvhj4hVsk9fk0O/DNa4veA5zZSNEm5GoMK6me3wLxABKoHpEZ9Bbp7m7jH4TkX6mpIYi1t/bL0HKsq2Fn0aPj88VkbURkJoer/r24T9YyTEJGamMt+f8nLI68iQ+u9DSRKKvM5zG5JtapYhK/mnB6d7w0h0w7eLqZZLo1X8cUcDxR80OL64Kxg0CndhwbcRabj5/YSZNBKodsc2DDwLujF9PQ9IBVF98K0fYHwMb6VAJY9PDoLPt0LAFiFd2aSA5i6Ja4=";
    let ok_signature_validation_result = rsa_keys.rsa_public_key_validate_sha512_signature(VALID_SIGNED_DATA, VALID_SIGNATURE).unwrap();
    assert_eq!(ok_signature_validation_result, true, "could not verify signature!");
    const INVALID_B64_SIGNATURE: &str = "yada<>[]§$%&";
    let err_signature_validation_result = rsa_keys.rsa_public_key_validate_sha512_signature(VALID_SIGNED_DATA, INVALID_B64_SIGNATURE);
    assert_eq!(err_signature_validation_result.unwrap_err().to_string(), "Could not base64 decode signature: Invalid byte 38, offset 12.", "signature verification should fail!");
    // some random uuid
    const INVALID_SIGNED_DATA: &str = "ceb0684f-1baa-4b87-a7c8-648404862d6d";
    let err_signature_validation_result = rsa_keys.rsa_public_key_validate_sha512_signature(INVALID_SIGNED_DATA, VALID_SIGNATURE).unwrap();
    assert_eq!(err_signature_validation_result, false, "signature verification should fail!");
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
