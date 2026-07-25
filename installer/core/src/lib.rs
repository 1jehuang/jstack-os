#![forbid(unsafe_code)]

pub mod canonical;
pub mod destination;
pub mod integrity;
pub mod model;
pub mod planner;
pub mod release;
pub mod state_graph;
pub mod windows_firmware;
pub mod windows_inventory;

pub use canonical::{canonical_json, canonical_sha256};
pub use destination::*;
pub use integrity::*;
pub use model::*;
pub use planner::{PlanError, create_install_plan, partition_fingerprint};
pub use release::*;
pub use state_graph::*;
pub use windows_firmware::{
    BOOT_NEXT_BYTES, BOOT_VARIABLE_ATTRIBUTES, EFI_GLOBAL_VARIABLE_GUID, FirmwareError,
    FirmwareMutationCapability, FirmwareVariables, arm_boot_next, decode_boot_next,
    encode_boot_next, is_readable, is_writable, read_boot_next, require_attributes,
};
pub use windows_inventory::*;
