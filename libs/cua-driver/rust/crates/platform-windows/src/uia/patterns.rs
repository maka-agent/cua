//! Direct UIA pattern actuators shared with native backend verification.
//!
//! The caller resolves and admits the element, discovers the exact pattern,
//! and retains its existing foreground guards. These functions do not select
//! another pattern or fall back to any input transport. A provider may still
//! have its own side effects; successful HRESULTs need independent read-back.

use windows::core::BSTR;
use windows::Win32::UI::Accessibility::{IUIAutomationInvokePattern, IUIAutomationValuePattern};

/// Invoke an already resolved UIA InvokePattern once.
pub fn invoke(pattern: &IUIAutomationInvokePattern) -> windows::core::Result<()> {
    unsafe { pattern.Invoke() }
}

/// Set an already resolved UIA ValuePattern once.
pub fn set_value(pattern: &IUIAutomationValuePattern, value: &BSTR) -> windows::core::Result<()> {
    unsafe { pattern.SetValue(value) }
}
