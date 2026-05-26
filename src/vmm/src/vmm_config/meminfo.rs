use serde::Serialize;

use crate::persist::GuestRegionUffdMapping;

/// Serializeable struct that contains information about guest's memory mappings
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct MemoryMapingsResponse {
    /// Vector with mappings from guest physical to host virtual memoryv
    pub mappings: Vec<GuestRegionUffdMapping>,
}

/// Information about guest memory resident pages and pages that are all-0s
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct MemoryResponse {
    /// Bitmap for resident pages. The bitmap is encoded as a vector of u64 values.
    /// Each bit represents whether a page is present in the resident memory set
    pub resident: Vec<u64>,
    /// Bitmap for empty pages. The bitmap is encoded as a vector of u64 values.
    /// Each bit represents whether a page is empty (all 0s).
    pub empty: Vec<u64>,
}

/// Information about dirty guest memory pages
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct MemoryDirty {
    /// Bitmap for dirty pages. The bitmap is encoded as a vector of u64 values.
    /// Each bit represents whether a page has been written since the last snapshot.
    pub bitmap: Vec<u64>,
}

/// Information about dirty blocks on a block device
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct DriveDirty {
    /// Bitmap for dirty blocks. Each bit represents one block_size block.
    pub bitmap: Vec<u64>,
    /// Block size in bytes (typically 4096)
    pub block_size: u64,
    /// Total number of blocks
    pub total_blocks: u64,
    /// Number of dirty blocks
    pub dirty_count: u64,
}
