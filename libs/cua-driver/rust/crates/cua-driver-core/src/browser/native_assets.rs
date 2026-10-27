// SPDX-License-Identifier: MIT
//! Own extension source embedded in the own CLI build.

pub(super) const EXTENSION_ASSETS: &[(&str, &str)] = &[
    (
        "background.mjs",
        include_str!("native_assets/background.mjs"),
    ),
    ("chunking.mjs", include_str!("native_assets/chunking.mjs")),
    (
        "claim-preparation.mjs",
        include_str!("native_assets/claim-preparation.mjs"),
    ),
    ("connector.mjs", include_str!("native_assets/connector.mjs")),
    (
        "created-tab-presentation.mjs",
        include_str!("native_assets/created-tab-presentation.mjs"),
    ),
    ("manifest.json", include_str!("native_assets/manifest.json")),
    (
        "native-downloads.mjs",
        include_str!("native_assets/native-downloads.mjs"),
    ),
    (
        "page-preparation.mjs",
        include_str!("native_assets/page-preparation.mjs"),
    ),
    (
        "prepared-connector.mjs",
        include_str!("native_assets/prepared-connector.mjs"),
    ),
    (
        "provider-connector.mjs",
        include_str!("native_assets/provider-connector.mjs"),
    ),
    (
        "scoped-headers.mjs",
        include_str!("native_assets/scoped-headers.mjs"),
    ),
    (
        "tab-preparation.mjs",
        include_str!("native_assets/tab-preparation.mjs"),
    ),
];
