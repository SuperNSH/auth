//! Parsing the redirect the provider sends back.

use crate::error::AuthError;
use url::Url;

/// The OAuth fields a redirect carries. Apple's `form_post` responses arrive
/// as a form body; the receiving host turns them into a query-string URL
/// before handing them here (our Apple authorize requests use `query` mode).
pub(crate) struct Callback {
    pub code: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
    pub state: Option<String>,
}

pub(crate) fn parse(url: &str) -> Result<Callback, AuthError> {
    let url = Url::parse(url)
        .map_err(|e| AuthError::Unknown(format!("callback URL is not a URL: {e}")))?;
    let mut callback = Callback {
        code: None,
        error: None,
        error_description: None,
        state: None,
    };
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "code" => callback.code = Some(value.into_owned()),
            "error" => callback.error = Some(value.into_owned()),
            "error_description" => callback.error_description = Some(value.into_owned()),
            "state" => callback.state = Some(value.into_owned()),
            _ => {}
        }
    }
    Ok(callback)
}
