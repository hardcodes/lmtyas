use lmtyas::string_trait::StringTrimNewline;

#[test]
fn string_trait_trim_newline() {
    let mut string_rn = "test\r\n".to_string();
    String::trim_newline(&mut string_rn);
    assert_eq!("test", string_rn, "could not remove \\r\\n from String");

    let mut string_n = "test\n".to_string();
    String::trim_newline(&mut string_n);
    assert_eq!("test", string_n, "could not remove \\n from String");

    let mut string_r = "test\r".to_string();
    String::trim_newline(&mut string_r);
    assert_eq!("test", string_r, "could not remove \\r from String");
}
