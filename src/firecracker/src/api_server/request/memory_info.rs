use micro_http::Method;
use vmm::rpc_interface::VmmAction;

use crate::api_server::parsed_request::{ParsedRequest, RequestError};

pub(crate) fn parse_get_memory<'a, T>(mut path_tokens: T) -> Result<ParsedRequest, RequestError>
where
    T: Iterator<Item = &'a str>,
{
    match path_tokens.next() {
        Some("mappings") => Ok(ParsedRequest::new_sync(VmmAction::GetMemoryMappings)),
        Some("dirty") => match path_tokens.next() {
            Some("reset") => Ok(ParsedRequest::new_sync(VmmAction::ResetMemoryDirty)),
            None => Ok(ParsedRequest::new_sync(VmmAction::GetMemoryDirty)),
            _ => Err(RequestError::InvalidPathMethod(
                "/memory/dirty/...".to_string(),
                Method::Get,
            )),
        },
        Some(unknown_path) => Err(RequestError::InvalidPathMethod(
            format!("/memory/{}", unknown_path),
            Method::Get,
        )),
        None => Ok(ParsedRequest::new_sync(VmmAction::GetMemory)),
    }
}
