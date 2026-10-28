// SPDX-License-Identifier: MIT

//! Closed fixed-read requests for context from an authorized, unclaimed user tab.

use serde::{Deserialize, Serialize};

/// Google Workspace export formats used by user-tab context acquisition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum BrowserWorkspaceExportFormat {
    /// A Google Docs Markdown export, including its observed image references.
    #[serde(rename = "md")]
    Markdown,
    /// The actual PDF export body.
    #[serde(rename = "pdf")]
    Pdf,
    /// The actual Excel export body.
    #[serde(rename = "xlsx")]
    Xlsx,
}

/// A fixed extraction operation; it accepts no script or debugger command.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub enum BrowserUserTabRead {
    /// Read the page's current HTML-like document text and form values.
    Page,
    /// Read the current trimmed user selection.
    Selection,
    /// Export a recognized Google Workspace document in an allowed format.
    GoogleWorkspaceExport {
        /// The requested actual Workspace export format.
        format: BrowserWorkspaceExportFormat,
    },
    /// Observe captions from the same current YouTube watch video.
    YoutubeTranscript,
}
