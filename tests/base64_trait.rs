pub use lmtyas::base64_trait::Base64StringConversions;

const PLAINTEXT: &str = r#"PASS!"§$%&/()=?ß\´`+*~'#-_.:,;<>|WORD"#;
const B64: &str = r#"UEFTUyEiwqckJSYvKCk9P8OfXMK0YCsqficjLV8uOiw7PD58V09SRA=="#;
const PLAINTEXT_URLSAFE: &str = r#"subjects?_d=1"#;
const B64_URLSAFE: &str = r#"c3ViamVjdHM_X2Q9MQ=="#;
const NO_BASE64: &str = "this is not base64 encoded";

#[test]
fn test_base64_trait() {
    let base64 = PLAINTEXT.to_string().to_base64_encoded_string();
    assert_eq!(base64, B64, "not the expected base64 encoded value!");

    let plaintext = match String::from_base64_encoded(&base64){
        Ok(s) => s,
        Err(e) => {
            panic!("can not decode base64 encoded string slice: {}", &e);
        }
    };
    assert_eq!(plaintext, PLAINTEXT, "not the expected plaintext");

    if String::from_base64_encoded(NO_BASE64).is_ok(){
        panic!("should not be able to decode this!");
    }

    let base64_urlsafe = PLAINTEXT_URLSAFE.to_string().to_base64_urlsafe_encoded_string();
    assert_eq!(base64_urlsafe, B64_URLSAFE, "not the expected url safe base64 encoded value!");

    let plaintext_urlsafe = match String::from_base64_urlsafe_encoded(&base64_urlsafe){
        Ok(s) => s,
        Err(e) => {
            panic!("can not decode url safe base64 encoded string slice: {}", &e);
        }
    };

    assert_eq!(plaintext_urlsafe, PLAINTEXT_URLSAFE, "not the expected url safe plaintext");

    if String::from_base64_urlsafe_encoded(NO_BASE64).is_ok(){
        panic!("should not be able to decode this!");
    }
}