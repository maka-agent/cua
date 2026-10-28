// SPDX-License-Identifier: Apache-2.0

//! Canonical fixed browser UI source shared by CDP and extension transports.

/// The existing Maka renderer, never an executable wire argument.
pub const FIXED_BROWSER_UI_SCRIPT: &str = include_str!("extension_assets/maka-ui/cursor.js");
