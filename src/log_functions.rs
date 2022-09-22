/// strip of parameters from the request uri/path
/// so that it does not appear in the log file.
#[inline]
pub fn extract_request_path(path: &str) -> String {
    // no parameters in path
    if !path.contains('?') {
        return path.to_string();
    }
    // strip parameters
    let mut parts = path.split('?');
    parts
        .next()
        .unwrap_or("failed to strip request parameters")
        .to_string()
}
