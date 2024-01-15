use lmtyas::log_functions::extract_request_path;

#[test]
fn extract_request_path_test() {
    assert_eq!(extract_request_path(r"/test"), "/test");
    assert_eq!(extract_request_path(r"/before?"), "/before");
    assert_eq!(extract_request_path(r"/before?after="), "/before");
    assert_eq!(extract_request_path(r"/before???"), "/before");
    assert_eq!(extract_request_path(r"/before?after=value?what=happend"), "/before");
    assert_eq!(extract_request_path(r"https://my.server.tld/route/to/hell?after=value?what=happend"), r"https://my.server.tld/route/to/hell");
    assert_eq!(extract_request_path(r"https://my.server.tld/route/to/hell???after=value?what=happend"), r"https://my.server.tld/route/to/hell");
}   
