// SPDX-License-Identifier: MIT

//! Factories accept only the exact validated installed adapter selection.

use super::{
    native_process::{NativeAdapterMode, NativeAdapterSelection},
    native_wire::{NativeWireAdapter, NativeWireError},
    original_adapter::OriginalWireAdapter,
};

pub(crate) fn for_installed(
    selection: &NativeAdapterSelection,
    generation: String,
) -> Result<Box<dyn NativeWireAdapter>, NativeWireError> {
    match selection.mode() {
        NativeAdapterMode::Original => Ok(Box::new(OriginalWireAdapter::new(
            generation,
            selection.expected_extension_id().to_owned(),
        )?)),
        NativeAdapterMode::Own => Err(NativeWireError::Protocol(
            "Own selection must retain the direct Own protocol writer".to_owned(),
        )),
    }
}
