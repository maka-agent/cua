// SPDX-License-Identifier: MIT

//! Factories accept only the exact validated installed adapter selection.

use super::{
    chatgpt_adapter::ChatgptWireAdapter,
    extension_process::{ExtensionAdapterMode, ExtensionAdapterSelection},
    extension_wire::{ExtensionWireAdapter, ExtensionWireError},
};

pub(crate) fn for_installed(
    selection: &ExtensionAdapterSelection,
    generation: String,
) -> Result<Box<dyn ExtensionWireAdapter>, ExtensionWireError> {
    match selection.mode() {
        ExtensionAdapterMode::Chatgpt => Ok(Box::new(ChatgptWireAdapter::new(
            generation,
            selection.expected_extension_id().to_owned(),
        )?)),
        ExtensionAdapterMode::Maka => Err(ExtensionWireError::Protocol(
            "Maka selection must retain the direct Maka protocol writer".to_owned(),
        )),
    }
}
