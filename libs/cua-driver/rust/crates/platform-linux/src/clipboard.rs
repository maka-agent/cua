use std::{
    path::Path,
    sync::{Mutex, MutexGuard},
    time::Duration,
};

use clipboard_rs::{
    Clipboard, ClipboardContext, ClipboardContextX11Options, ContentFormat, common::RustImage,
};
use cua_driver_core::clipboard::ClipboardBackend;

#[derive(Default)]
struct Contexts {
    automatic: Option<Result<ClipboardContext, String>>,
    native_x11: Option<ClipboardContext>,
}

pub struct LinuxClipboard {
    // One actual backend custody lock covers the generic tools and an owned
    // native paste through restoration. The two provider selections retain
    // their existing implementations; generic Wayland selection is unchanged.
    contexts: Mutex<Contexts>,
}

impl LinuxClipboard {
    pub fn new() -> Self {
        Self {
            contexts: Mutex::new(Contexts::default()),
        }
    }

    fn automatic<T>(
        &self,
        operation: impl FnOnce(&ClipboardContext) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut contexts = self
            .contexts
            .lock()
            .map_err(|_| "clipboard lock was poisoned".to_owned())?;
        let context = contexts
            .automatic
            .get_or_insert_with(|| ClipboardContext::new().map_err(|error| error.to_string()))
            .as_ref()
            .map_err(Clone::clone)?;
        operation(context)
    }

    pub(crate) fn native_x11(&self) -> Result<NativeClipboard<'_>, String> {
        let mut contexts = self
            .contexts
            .lock()
            .map_err(|_| "clipboard lock was poisoned".to_owned())?;
        if contexts.native_x11.is_none() {
            // Original whole-read timeout is three seconds. Its 50ms wait is
            // the existing engine's empty-event polling pause, not this limit.
            let context = ClipboardContext::new_x11(ClipboardContextX11Options {
                read_timeout: Some(Duration::from_secs(3)),
            })
            .map_err(|error| error.to_string())?;
            contexts.native_x11 = Some(context);
        }
        Ok(NativeClipboard { contexts })
    }

    pub(crate) fn retained_native_x11(&self) -> Result<NativeClipboard<'_>, String> {
        let contexts = self
            .contexts
            .lock()
            .map_err(|_| "clipboard lock was poisoned".to_owned())?;
        if contexts.native_x11.is_none() {
            return Err("owned X11 clipboard context is no longer available".into());
        }
        Ok(NativeClipboard { contexts })
    }
}

/// An actual same-backend clipboard lock held by the admitted blocking worker.
/// It is never sent to another worker or treated as permission/turn authority.
pub(crate) struct NativeClipboard<'a> {
    contexts: MutexGuard<'a, Contexts>,
}
impl NativeClipboard<'_> {
    fn context(&self) -> &ClipboardContext {
        self.contexts
            .native_x11
            .as_ref()
            .expect("native X11 clipboard prepared under custody")
    }
    pub(crate) fn read_utf8(&self) -> Result<Vec<u8>, String> {
        self.context()
            .get_buffer("UTF8_STRING")
            .map_err(|error| error.to_string())
    }
    pub(crate) fn write_utf8(&self, bytes: Vec<u8>) -> Result<(), String> {
        self.context()
            .set_buffer("UTF8_STRING", bytes)
            .map_err(|error| error.to_string())
    }
}

fn absolute_existing_file(path: &str) -> Result<String, String> {
    let path = Path::new(path);
    if !path.is_absolute() {
        return Err("clipboard file paths must be absolute".into());
    }
    let canonical = path.canonicalize().map_err(|error| error.to_string())?;
    if !canonical.is_file() {
        return Err("clipboard path must identify an existing file".into());
    }
    Ok(canonical.to_string_lossy().into_owned())
}

impl ClipboardBackend for LinuxClipboard {
    fn available_formats(&self) -> Result<Vec<String>, String> {
        self.automatic(|context| {
            context
                .available_formats()
                .map_err(|error| error.to_string())
        })
    }
    fn read_text(&self) -> Result<Option<String>, String> {
        self.automatic(|context| {
            if context.has(ContentFormat::Text) {
                context
                    .get_text()
                    .map(Some)
                    .map_err(|error| error.to_string())
            } else {
                Ok(None)
            }
        })
    }
    fn write_text(&self, text: String) -> Result<(), String> {
        self.automatic(|context| context.set_text(text).map_err(|error| error.to_string()))
    }
    fn write_image(&self, absolute_path: &str) -> Result<(), String> {
        let path = absolute_existing_file(absolute_path)?;
        let image =
            clipboard_rs::RustImageData::from_path(&path).map_err(|error| error.to_string())?;
        self.automatic(|context| context.set_image(image).map_err(|error| error.to_string()))
    }
    fn write_file_url(&self, absolute_path: &str) -> Result<(), String> {
        let path = absolute_existing_file(absolute_path)?;
        self.automatic(|context| {
            context
                .set_files(vec![path])
                .map_err(|error| error.to_string())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construction_does_not_start_native_clipboard() {
        let backend = LinuxClipboard::new();
        let contexts = backend.contexts.lock().unwrap();
        assert!(contexts.automatic.is_none());
        assert!(contexts.native_x11.is_none());
    }

    #[test]
    fn rejects_relative_local_paths_before_clipboard_access() {
        let backend = LinuxClipboard::new();
        assert!(
            backend
                .write_file_url("relative.txt")
                .unwrap_err()
                .contains("absolute")
        );
        assert!(
            backend
                .write_image("relative.png")
                .unwrap_err()
                .contains("absolute")
        );
    }

    /// Run only on a disposable task-owned X11 display, never a personal desktop.
    #[test]
    #[ignore = "requires an isolated X11 display"]
    fn native_x11_preserves_exact_selection_bytes() {
        let backend = LinuxClipboard::new();
        let saved = vec![0xff, 0, 0x80, b'\n', b'x'];
        {
            let clipboard = backend.native_x11().unwrap();
            clipboard.write_utf8(saved.clone()).unwrap();
            assert_eq!(clipboard.read_utf8().unwrap(), saved);
            clipboard
                .write_utf8("replacement 世界".as_bytes().to_vec())
                .unwrap();
        }
        {
            let clipboard = backend.retained_native_x11().unwrap();
            clipboard.write_utf8(saved.clone()).unwrap();
            std::thread::sleep(Duration::from_millis(50));
            assert_eq!(clipboard.read_utf8().unwrap(), saved);
        }
        assert!(
            backend.contexts.lock().unwrap().automatic.is_none(),
            "explicit native X11 must not initialize or replace generic provider selection"
        );
    }

    /// Needs an X server; CI runs it under `xvfb-run` in ci-rust-linux.yml.
    #[test]
    #[ignore = "requires an X11 display (run under xvfb-run)"]
    fn native_clipboard_round_trips_text_on_x11() {
        let backend = LinuxClipboard::new();
        backend
            .write_text("cua-driver clipboard test".into())
            .unwrap();
        assert_eq!(
            backend.read_text().unwrap().as_deref(),
            Some("cua-driver clipboard test")
        );
    }
}
