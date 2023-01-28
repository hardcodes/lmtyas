use lmtyas::log_functions::extract_request_path;

#[test]
fn test_extract_request_path(){
    assert_eq!(extract_request_path(r#"/test"#), "/test");
    assert_eq!(extract_request_path(r#"/before?"#), "/before");
    assert_eq!(extract_request_path(r#"/before?after="#), "/before");
}