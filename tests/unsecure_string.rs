use lmtyas::unsecure_string::SecureStringToUnsecureString;
use secstr::SecStr;

#[test]
fn unsecure_string() {
    const UNSECURE: &str = "unsecure";
    let secure_string = SecStr::from(UNSECURE);
    let unsecure_string = secure_string.to_unsecure_string();
    assert_eq!(
        unsecure_string, UNSECURE,
        "strings should match after converting them back from a SecStr!"
    );
}
