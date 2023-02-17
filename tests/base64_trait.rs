use lmtyas::base64_trait::{Base64StringConversions, Base64VecU8Conversions};

const PLAINTEXT: &str = r#"PASS!"§$%&/()=?ß\´`+*~'#-_.:,;<>|WORD"#;
const B64: &str = r#"UEFTUyEiwqckJSYvKCk9P8OfXMK0YCsqficjLV8uOiw7PD58V09SRA=="#;
const PLAINTEXT_URLSAFE: &str = r#"subjects?_d=1"#;
const B64_URLSAFE: &str = r#"c3ViamVjdHM_X2Q9MQ=="#;
const NO_BASE64: &str = "this is not base64 encoded";

#[test]
fn test_base64_trait() {
    let base64 = PLAINTEXT.to_string().to_base64_encoded();
    assert_eq!(base64, B64, "not the expected base64 encoded value!");

    let plain_u8 = match Vec::from_base64_encoded(&base64){
        Ok(s) => s,
        Err(e) => {
            panic!("can not decode base64 encoded string slice: {}", &e);
        }
    };
    let plaintext = String::from_utf8(plain_u8).unwrap();
    assert_eq!(plaintext, PLAINTEXT, "not the expected plaintext");

    let plain_vec: Vec<u8> = PLAINTEXT.as_bytes().to_vec();
    let base64_2 = plain_vec.to_base64_encoded();
    assert_eq!(base64_2, B64, "not the expected base64 encoded value!");

    let plain_u8 = match Vec::from_base64_encoded(&base64){
        Ok(s) => s,
        Err(e) => {
            panic!("can not decode base64 encoded string slice: {}", &e);
        }
    };
    let plaintext = String::from_utf8(plain_u8).unwrap();
    assert_eq!(plaintext, PLAINTEXT, "not the expected plaintext");

    if Vec::from_base64_encoded(NO_BASE64).is_ok(){
        panic!("should not be able to decode this!");
    }

    let base64_urlsafe = PLAINTEXT_URLSAFE.to_string().to_base64_urlsafe_encoded();
    assert_eq!(base64_urlsafe, B64_URLSAFE, "not the expected url safe base64 encoded value!");

    let plain_u8_urlsafe = match Vec::from_base64_urlsafe_encoded(&base64_urlsafe){
        Ok(s) => s,
        Err(e) => {
            panic!("can not decode url safe base64 encoded string slice: {}", &e);
        }
    };

    let plaintext_urlsafe = String::from_utf8(plain_u8_urlsafe).unwrap();
    assert_eq!(plaintext_urlsafe, PLAINTEXT_URLSAFE, "not the expected url safe plaintext");

    if Vec::from_base64_urlsafe_encoded(NO_BASE64).is_ok(){
        panic!("should not be able to decode this!");
    }
}