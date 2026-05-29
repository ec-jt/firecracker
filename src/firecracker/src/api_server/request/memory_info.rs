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
        Some("kvm-dirty") => Ok(ParsedRequest::new_sync(VmmAction::GetKvmDirty)),
        Some("kvm-dirty-writes") => Ok(ParsedRequest::new_sync(VmmAction::GetKvmDirtyWrites)),
        Some("dirty-delta") => Ok(ParsedRequest::new_sync(VmmAction::GetDirtyDelta)),
        Some("dirty-delta-packed") => match path_tokens.next() {
            Some("keyframe") => Ok(ParsedRequest::new_sync(
                VmmAction::GetDirtyDeltaPacked { keyframe: true },
            )),
            None => Ok(ParsedRequest::new_sync(
                VmmAction::GetDirtyDeltaPacked { keyframe: false },
            )),
            Some(unknown) => Err(RequestError::InvalidPathMethod(
                format!("/memory/dirty-delta-packed/{}", unknown),
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
