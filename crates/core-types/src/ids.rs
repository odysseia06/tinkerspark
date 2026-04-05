use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for an open file within a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileId(Uuid);

impl FileId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for FileId {
    fn default() -> Self {
        Self::new()
    }
}

/// Unique identifier for an analysis tree node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(Uuid);

impl NodeId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for NodeId {
    fn default() -> Self {
        Self::new()
    }
}

/// Unique identifier for a patch operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PatchId(Uuid);

impl PatchId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for PatchId {
    fn default() -> Self {
        Self::new()
    }
}
