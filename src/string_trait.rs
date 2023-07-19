pub trait StringTrimNewline {
    fn trim_newline(s: &mut String);
}

impl StringTrimNewline for String{
    /// trim `\r` or `\r\n` from a `String`.
    fn trim_newline(s: &mut String) {
        if s.ends_with('\n') {
            s.pop();
            if s.ends_with('\r') {
                s.pop();
            }
        }
    }
}
