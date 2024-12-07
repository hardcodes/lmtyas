use std::error::Error;
use std::fmt;
use std::fs::read_to_string;
use std::path::Path;

/// CSRF token pattern that will be replaced in template files
const CSRF_TOKEN_PATTERN: &str = r"{CSRF_TOKEN}";

/// Enum of template files.
#[derive(Debug, PartialEq, Eq)]
pub enum CsrfTemplateFile {
    /// tell.html
    Tell,
    /// sysop.html
    Sysop,
}

impl fmt::Display for CsrfTemplateFile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CsrfTemplateFile::Tell => {
                write!(f, "web-content/authenticated/tell.html")
            }
            CsrfTemplateFile::Sysop => {
                write!(f, "web-content/admin-html/sysop.html")
            }
        }
    }
}

/// Loads template file and injects the given CSRF token and returns it
/// as HttpResult.
pub fn inject_csrf_token(
    selected_csrf_template_file: CsrfTemplateFile,
    csrf_token_payload: &str,
) -> Result<String, Box<dyn Error>> {
    let file_content = match read_to_string(Path::new(&selected_csrf_template_file.to_string())) {
        Err(e) => {
            return Err(format!(
                "cannot load csrf template file '{}': {}",
                &selected_csrf_template_file, e
            )
            .into());
        }
        Ok(f) => f,
    };
    Ok(file_content.replace(CSRF_TOKEN_PATTERN, csrf_token_payload))
}
