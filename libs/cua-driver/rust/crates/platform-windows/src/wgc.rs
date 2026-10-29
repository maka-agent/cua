//! Windows.Graphics.Capture (WGC) backend for window screenshots.
//!
//! Used when PrintWindow returns black (UWP / DirectComposition) AND/OR
//! when the target window is occluded by another window. WGC captures
//! the window's own composited frames out of DWM regardless of z-order,
//! which is the only correct way to screenshot UWP apps like Calculator
//! when they're behind the user's terminal.
//!
//! Constraints:
//! - Minimum OS: Windows 10 version 1903 (~April 2019). ~100% of users
//!   today; we surface a structured error on older builds.
//! - Cannot capture **minimized** windows. They have no rendered content.
//!   `get_window_state` still returns the UIA tree for a minimized target
//!   (the screenshot is reported unavailable). We surface this as an
//!   error with the recommended fallback.
//! - First call per process pays ~50ms for D3D11 device creation +
//!   COM activation factory lookup. Subsequent calls don't cache the
//!   device — could be optimized later, but a single-shot screenshot
//!   tool isn't the place to fight that.

use anyhow::{bail, Context, Result};
use std::time::Duration;

use windows::{
    core::Interface,
    Graphics::{
        Capture::{Direct3D11CaptureFramePool, GraphicsCaptureItem},
        DirectX::{Direct3D11::IDirect3DDevice, DirectXPixelFormat},
    },
    Win32::{
        Foundation::HWND,
        Graphics::{
            Direct3D::{D3D_DRIVER_TYPE_HARDWARE, D3D_FEATURE_LEVEL_11_0},
            Direct3D11::{
                D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D,
                D3D11_CPU_ACCESS_READ, D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_MAPPED_SUBRESOURCE,
                D3D11_MAP_READ, D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
            },
            Dxgi::IDXGIDevice,
        },
        System::WinRT::{
            Direct3D11::{CreateDirect3D11DeviceFromDXGIDevice, IDirect3DDxgiInterfaceAccess},
            Graphics::Capture::IGraphicsCaptureItemInterop,
        },
        UI::WindowsAndMessaging::IsIconic,
    },
};

/// Capture a window via WGC, returning BGRA pixels + (width, height).
/// Caller is responsible for encoding to PNG (or whatever format) via
/// `cua_driver_core::image_utils::encode_bgra_to_png`.
pub fn screenshot_window_via_wgc(hwnd: u64) -> Result<(Vec<u8>, u32, u32)> {
    unsafe { wgc_capture_impl(HWND(hwnd as *mut _)) }
}

unsafe fn wgc_capture_impl(hwnd: HWND) -> Result<(Vec<u8>, u32, u32)> {
    if IsIconic(hwnd).as_bool() {
        bail!(
            "WGC cannot capture a minimized window (no rendered content). \
             Call bring_to_front with this window_id to restore it first. \
             `get_window_state` still returns the \
             UIA tree for a minimized window (the screenshot is reported \
             unavailable)."
        );
    }

    let (d3d_device, d3d_context, direct3d_device) = create_wgc_device()?;

    // 3. GraphicsCaptureItem for our target HWND.
    let interop_factory: IGraphicsCaptureItemInterop =
        windows::core::factory::<GraphicsCaptureItem, IGraphicsCaptureItemInterop>()
            .context("IGraphicsCaptureItemInterop activation factory")?;
    let item: GraphicsCaptureItem = interop_factory.CreateForWindow(hwnd).context(
        "IGraphicsCaptureItemInterop::CreateForWindow failed — \
             requires Win10 1903+ and the target window must exist",
    )?;
    let item_size = item.Size().context("GraphicsCaptureItem::Size")?;
    if item_size.Width <= 0 || item_size.Height <= 0 {
        bail!(
            "WGC item size is {}x{} — target may be hidden/cloaked. \
             Try restoring the window or use UIA.",
            item_size.Width,
            item_size.Height
        );
    }

    // 4. Frame pool + capture session.
    //    `CreateFreeThreaded` (not `Create`) — `Create` requires the
    //    calling thread to have a CoreDispatcher/event loop running
    //    for FrameArrived to fire, which we don't have inside a
    //    daemon's spawn_blocking thread. `CreateFreeThreaded`
    //    dispatches FrameArrived on a system thread-pool thread, which
    //    is exactly what our mpsc channel handler expects. Without
    //    this, FrameArrived silently never fires and our 1500 ms wait
    //    always times out.
    //
    //    Frame count 2 — WGC docs recommend ≥2 to avoid GPU stalls
    //    while the consumer reads the previous frame. We only consume
    //    one but the GPU side is happier with breathing room.
    let pool = Direct3D11CaptureFramePool::CreateFreeThreaded(
        &direct3d_device,
        DirectXPixelFormat::B8G8R8A8UIntNormalized,
        2,
        item_size,
    )
    .context("Direct3D11CaptureFramePool::CreateFreeThreaded")?;
    let session = pool
        .CreateCaptureSession(&item)
        .context("Direct3D11CaptureFramePool::CreateCaptureSession")?;

    // 5. Hide the WGC capture indicator (yellow border) if the build
    //    supports it. Available since Win11 (IsBorderRequired property).
    //    Best-effort — older Win10 won't have the setter; ignore failure.
    let _ = session.SetIsBorderRequired(false);
    let _ = session.SetIsCursorCaptureEnabled(false);

    // 6. Start capture, then poll TryGetNextFrame until a frame is
    //    available or we time out. We tried FrameArrived events first
    //    (both `Create` and `CreateFreeThreaded` pool variants) but
    //    the event never fired in our daemon's thread environment —
    //    likely an STA/COM-apartment mismatch we couldn't isolate.
    //    Polling suits single-shot capture anyway: WGC drops frames
    //    in the pool as DWM composes them, and TryGetNextFrame returns Ok(None) /
    //    NULL until one's available. 50 ms polling interval keeps the
    //    "frame finally arrived" detection latency low without burning
    //    CPU on a tight spin.
    session
        .StartCapture()
        .context("GraphicsCaptureSession::StartCapture")?;

    let deadline = std::time::Instant::now() + Duration::from_millis(1500);
    let mut frame_opt = None;
    while std::time::Instant::now() < deadline {
        match pool.TryGetNextFrame() {
            Ok(f) => {
                frame_opt = Some(f);
                break;
            }
            Err(_) => {
                // TryGetNextFrame returns an error when no frame is
                // available yet. Wait briefly, retry.
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
    let frame = frame_opt.ok_or_else(|| {
        anyhow::anyhow!(
            "WGC TryGetNextFrame returned no frame within 1500 ms — \
         DWM may not be compositing this window (cloaked / not actually \
         rendered). Fall through to screen-region BitBlt."
        )
    })?;

    let content_size = frame.ContentSize().context("frame.ContentSize")?;
    let content_width =
        u32::try_from(content_size.Width).context("WGC frame content width is negative")?;
    let content_height =
        u32::try_from(content_size.Height).context("WGC frame content height is negative")?;
    if content_width == 0 || content_height == 0 {
        bail!("WGC frame content size is {content_width}x{content_height}");
    }

    // 8. Pull the underlying ID3D11Texture2D out of the WinRT frame
    //    surface via the IDirect3DDxgiInterfaceAccess shim.
    let surface = frame.Surface().context("frame.Surface")?;
    let access: IDirect3DDxgiInterfaceAccess = surface
        .cast()
        .context("IDirect3DSurface → IDirect3DDxgiInterfaceAccess cast")?;
    let frame_texture: ID3D11Texture2D = access
        .GetInterface()
        .context("IDirect3DDxgiInterfaceAccess::GetInterface(ID3D11Texture2D)")?;

    // 9. Create a staging texture we can map for CPU read, copy frame in.
    let mut desc = D3D11_TEXTURE2D_DESC::default();
    frame_texture.GetDesc(&mut desc);
    // The pool-sized surface can contain undefined pixels outside ContentSize.
    // A larger content size means this frame was clipped and is incomplete.
    if content_width > desc.Width || content_height > desc.Height {
        bail!(
            "WGC frame content {content_width}x{content_height} exceeds surface {}x{}",
            desc.Width,
            desc.Height
        );
    }
    desc.Usage = D3D11_USAGE_STAGING;
    desc.BindFlags = 0;
    desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ.0 as u32;
    desc.MiscFlags = 0;
    let mut staging: Option<ID3D11Texture2D> = None;
    d3d_device
        .CreateTexture2D(&desc, None, Some(&mut staging))
        .context("CreateTexture2D(staging)")?;
    let staging = staging.context("CreateTexture2D returned a None texture")?;
    d3d_context.CopyResource(&staging, &frame_texture);

    // 10. Map the staging texture, copy BGRA out row-by-row (RowPitch may
    //     be padded — can't just copy `Width * 4 * Height` straight).
    let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
    d3d_context
        .Map(&staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped))
        .context("ID3D11DeviceContext::Map")?;
    let width = content_width as usize;
    let height = content_height as usize;
    let stride = mapped.RowPitch as usize;
    let mut bgra = vec![0u8; width * height * 4];
    let src_base = mapped.pData as *const u8;
    for row in 0..height {
        std::ptr::copy_nonoverlapping(
            src_base.add(row * stride),
            bgra.as_mut_ptr().add(row * width * 4),
            width * 4,
        );
    }
    d3d_context.Unmap(&staging, 0);

    // 11. Cleanup: close the session and pool explicitly. RAII would
    //     handle this but being explicit makes the lifetimes easier to
    //     audit. (No FrameArrived to unhook — we polled instead.)
    let _ = session.Close();
    let _ = pool.Close();

    Ok((bgra, content_width, content_height))
}

unsafe fn create_wgc_device() -> Result<(ID3D11Device, ID3D11DeviceContext, IDirect3DDevice)> {
    let mut d3d_device: Option<ID3D11Device> = None;
    let mut d3d_context: Option<ID3D11DeviceContext> = None;
    D3D11CreateDevice(
        None,
        D3D_DRIVER_TYPE_HARDWARE,
        windows::Win32::Foundation::HMODULE(std::ptr::null_mut()),
        D3D11_CREATE_DEVICE_BGRA_SUPPORT,
        Some(&[D3D_FEATURE_LEVEL_11_0]),
        D3D11_SDK_VERSION,
        Some(&mut d3d_device),
        None,
        Some(&mut d3d_context),
    )
    .context("D3D11CreateDevice failed (hardware feature-level 11.0 + BGRA)")?;
    let d3d_device = d3d_device.context("D3D11CreateDevice returned a None device")?;
    let d3d_context = d3d_context.context("D3D11CreateDevice returned a None context")?;

    let dxgi_device: IDXGIDevice = d3d_device
        .cast()
        .context("ID3D11Device → IDXGIDevice cast")?;
    let inspectable = CreateDirect3D11DeviceFromDXGIDevice(&dxgi_device)
        .context("CreateDirect3D11DeviceFromDXGIDevice failed")?;
    let direct3d_device: IDirect3DDevice = inspectable
        .cast()
        .context("CreateDirect3D11DeviceFromDXGIDevice → IDirect3DDevice cast")?;

    Ok((d3d_device, d3d_context, direct3d_device))
}

/// A JPEG of a sampled window viewport taken from its nearest monitor.
pub(crate) struct MonitorRegionJpeg {
    pub jpeg: Vec<u8>,
    pub encoded_width: u32,
    pub encoded_height: u32,
    pub cropped_width: u32,
    pub cropped_height: u32,
    pub dpi: u32,
}

/// Reusable monitor capture state. The owning ToolState must serialize access.
/// Device proxies are resolved on each calling thread; no immediate D3D context
/// is retained across calls.
pub(crate) struct MonitorRegionCapture {
    sessions: std::collections::HashMap<usize, CachedMonitorSession>,
    device: windows::core::AgileReference<IDirect3DDevice>,
}

impl MonitorRegionCapture {
    pub(crate) fn new() -> Result<Self> {
        // Reuse the Windows projection's apartment-aware activation mechanism.
        let _: IGraphicsCaptureItemInterop =
            windows::core::factory::<GraphicsCaptureItem, IGraphicsCaptureItemInterop>()?;
        // SAFETY: the helper creates local devices using initialized output
        // storage. The immediate context is released on this calling thread.
        let (_, _, device) = unsafe { create_wgc_device() }?;
        let device = windows::core::AgileReference::new(&device)?;
        Ok(Self {
            sessions: std::collections::HashMap::new(),
            device,
        })
    }

    /// Capture physical desktop bounds using the selected window's monitor.
    /// Cropped pixel dimensions do not replace the supplied action viewport.
    pub(crate) fn capture(
        &mut self,
        hwnd: u64,
        sampled_bounds: [i32; 4],
        caller_timeout: Duration,
    ) -> Result<MonitorRegionJpeg> {
        use windows::Win32::{
            Graphics::Gdi::{
                GetMonitorInfoW, MonitorFromWindow, MONITORINFO, MONITOR_DEFAULTTONEAREST,
            },
            UI::HiDpi::GetDpiForWindow,
        };

        let [left, top, width, height] = sampled_bounds;
        anyhow::ensure!(width > 0 && height > 0, "window viewport is empty");
        let hwnd = HWND(hwnd as usize as *mut _);
        let mut monitor_info = MONITORINFO {
            cbSize: std::mem::size_of::<MONITORINFO>() as u32,
            ..Default::default()
        };
        // SAFETY: HWND is observed only. The monitor-info pointer references a
        // fully initialized output buffer. Target identity is the caller's lease.
        let (monitor, dpi) = unsafe {
            let monitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
            anyhow::ensure!(!monitor.0.is_null(), "window has no capture monitor");
            GetMonitorInfoW(monitor, &mut monitor_info).ok()?;
            (monitor, GetDpiForWindow(hwnd).max(96))
        };
        let region = [
            left.wrapping_sub(monitor_info.rcMonitor.left),
            top.wrapping_sub(monitor_info.rcMonitor.top),
            width,
            height,
        ];
        let key = monitor.0 as usize;
        let device = self.device.resolve()?;
        if let Some(session) = self.sessions.get_mut(&key) {
            if let Ok(image) = session.capture(&device, region, dpi, caller_timeout) {
                return Ok(image);
            }
            self.sessions.remove(&key);
        }
        let mut session = CachedMonitorSession::new(monitor, &device)?;
        let image = session.capture(&device, region, dpi, caller_timeout)?;
        self.sessions.insert(key, session);
        Ok(image)
    }

    pub(crate) fn clear(&mut self) {
        self.sessions.clear();
    }
}

impl Drop for MonitorRegionCapture {
    fn drop(&mut self) {
        self.clear();
    }
}

struct CachedMonitorSession {
    item: GraphicsCaptureItem,
    pool: Direct3D11CaptureFramePool,
    session: windows::Graphics::Capture::GraphicsCaptureSession,
    size: windows::Graphics::SizeInt32,
}

impl CachedMonitorSession {
    fn new(
        monitor: windows::Win32::Graphics::Gdi::HMONITOR,
        device: &IDirect3DDevice,
    ) -> Result<Self> {
        let factory: IGraphicsCaptureItemInterop =
            windows::core::factory::<GraphicsCaptureItem, IGraphicsCaptureItemInterop>()?;
        // SAFETY: this monitor handle was obtained from MonitorFromWindow during
        // the current capture, and no ownership of it is transferred.
        let item: GraphicsCaptureItem = unsafe { factory.CreateForMonitor(monitor) }?;
        let size = item.Size()?;
        anyhow::ensure!(
            size.Width > 0 && size.Height > 0,
            "capture monitor is empty"
        );
        let pool = Direct3D11CaptureFramePool::CreateFreeThreaded(
            device,
            DirectXPixelFormat::B8G8R8A8UIntNormalized,
            1,
            size,
        )?;
        let session = match pool.CreateCaptureSession(&item) {
            Ok(session) => session,
            Err(error) => {
                let _ = pool.Close();
                return Err(error.into());
            }
        };
        let capture = Self {
            item,
            pool,
            session,
            size,
        };
        capture.session.SetIsCursorCaptureEnabled(true)?;
        capture.session.SetIsBorderRequired(false)?;
        capture.session.StartCapture()?;
        Ok(capture)
    }

    fn capture(
        &mut self,
        device: &IDirect3DDevice,
        region: [i32; 4],
        dpi: u32,
        caller_timeout: Duration,
    ) -> Result<MonitorRegionJpeg> {
        use std::sync::{mpsc, Mutex};
        use windows::Foundation::TypedEventHandler;

        let size = self.item.Size()?;
        anyhow::ensure!(
            size.Width > 0 && size.Height > 0,
            "capture monitor is empty"
        );
        if size.Width != self.size.Width || size.Height != self.size.Height {
            self.pool
                .Recreate(device, DirectXPixelFormat::B8G8R8A8UIntNormalized, 1, size)?;
            self.size = size;
        }
        while let Ok(frame) = self.pool.TryGetNextFrame() {
            let _ = frame.Close();
        }
        let (sender, receiver) =
            mpsc::sync_channel::<std::result::Result<MonitorRegionJpeg, String>>(1);
        let sender = Mutex::new(Some(sender));
        let handler =
            TypedEventHandler::<Direct3D11CaptureFramePool, windows::core::IInspectable>::new(
                move |pool, _| {
                    let Some(sender) = sender
                        .lock()
                        .expect("monitor capture sender poisoned")
                        .take()
                    else {
                        return Ok(());
                    };
                    let result = match pool.as_ref() {
                        Some(pool) => encode_latest_monitor_frame(pool, region, dpi),
                        None => Err(anyhow::anyhow!("capture callback has no frame pool")),
                    };
                    // Native error information is converted while the callback's
                    // apartment is alive; only owned bytes and text cross threads.
                    let _ = sender.send(result.map_err(|error| error.to_string()));
                    Ok(())
                },
            );
        let token = self.pool.FrameArrived(&handler)?;
        let _registration = MonitorFrameRegistration {
            pool: self.pool.clone(),
            token,
        };
        receiver
            .recv_timeout(caller_timeout.min(Duration::from_secs(2)))
            .context("monitor capture did not produce an image before its deadline")?
            .map_err(anyhow::Error::msg)
    }
}

impl Drop for CachedMonitorSession {
    fn drop(&mut self) {
        let _ = self.session.Close();
        let _ = self.pool.Close();
    }
}

struct MonitorFrameRegistration {
    pool: Direct3D11CaptureFramePool,
    token: windows::Foundation::EventRegistrationToken,
}

impl Drop for MonitorFrameRegistration {
    fn drop(&mut self) {
        let _ = self.pool.RemoveFrameArrived(self.token);
    }
}

fn encode_latest_monitor_frame(
    pool: &Direct3D11CaptureFramePool,
    region: [i32; 4],
    dpi: u32,
) -> Result<MonitorRegionJpeg> {
    let mut latest = None;
    loop {
        match pool.TryGetNextFrame() {
            Ok(frame) => {
                latest = Some(encode_monitor_region(&frame, region, dpi));
                let _ = frame.Close();
            }
            Err(error) => {
                return latest.unwrap_or_else(|| Err(error.into()));
            }
        }
    }
}

fn encode_monitor_region(
    frame: &windows::Graphics::Capture::Direct3D11CaptureFrame,
    region: [i32; 4],
    dpi: u32,
) -> Result<MonitorRegionJpeg> {
    use windows::{
        core::HSTRING,
        Foundation::{PropertyType, PropertyValue},
        Graphics::Imaging::{
            BitmapAlphaMode, BitmapEncoder, BitmapPixelFormat, BitmapPropertySet, BitmapTypedValue,
            SoftwareBitmap,
        },
        Storage::Streams::{Buffer, DataReader, InMemoryRandomAccessStream},
    };

    let bitmap = SoftwareBitmap::CreateCopyFromSurfaceAsync(&frame.Surface()?)?.get()?;
    let bitmap_width = bitmap.PixelWidth()?;
    let bitmap_height = bitmap.PixelHeight()?;
    anyhow::ensure!(
        bitmap_width > 0 && bitmap_height > 0,
        "captured monitor is empty"
    );
    anyhow::ensure!(
        bitmap.BitmapPixelFormat()? == BitmapPixelFormat::Bgra8
            && bitmap.BitmapAlphaMode()? == BitmapAlphaMode::Straight,
        "captured monitor bitmap has an unsupported pixel format"
    );
    let [x, y, width, height] = region;
    let left = x.clamp(0, bitmap_width);
    let top = y.clamp(0, bitmap_height);
    let right = x.wrapping_add(width).clamp(0, bitmap_width);
    let bottom = y.wrapping_add(height).clamp(0, bitmap_height);
    let cropped_width = right - left;
    let cropped_height = bottom - top;
    anyhow::ensure!(
        cropped_width > 0 && cropped_height > 0,
        "window viewport is outside the captured monitor"
    );
    let full_bytes = (bitmap_width as u32)
        .checked_mul(bitmap_height as u32)
        .and_then(|pixels| pixels.checked_mul(4))
        .context("monitor bitmap byte length overflows")?;
    let buffer = Buffer::Create(full_bytes)?;
    bitmap.CopyToBuffer(&buffer)?;
    let mut full = vec![0; full_bytes as usize];
    DataReader::FromBuffer(&buffer)?.ReadBytes(&mut full)?;
    let stride = bitmap_width as usize * 4;
    let row_bytes = cropped_width as usize * 4;
    let mut pixels = Vec::with_capacity(row_bytes * cropped_height as usize);
    for row in top as usize..bottom as usize {
        let start = row * stride + left as usize * 4;
        pixels.extend_from_slice(&full[start..start + row_bytes]);
    }
    let dpi = dpi.max(96);
    let scale = |extent: i32| -> u32 {
        ((i64::from(extent) * 96 + i64::from(dpi / 2)) / i64::from(dpi)).max(1) as u32
    };
    let encoded_width = scale(cropped_width);
    let encoded_height = scale(cropped_height);
    let options = BitmapPropertySet::new()?;
    let quality =
        BitmapTypedValue::Create(&PropertyValue::CreateSingle(0.8_f32)?, PropertyType::Single)?;
    options.Insert(&HSTRING::from("ImageQuality"), &quality)?;
    let stream = InMemoryRandomAccessStream::new()?;
    let encoder = BitmapEncoder::CreateWithEncodingOptionsAsync(
        BitmapEncoder::JpegEncoderId()?,
        &stream,
        &options,
    )?
    .get()?;
    let transform = encoder.BitmapTransform()?;
    transform.SetScaledWidth(encoded_width)?;
    transform.SetScaledHeight(encoded_height)?;
    encoder.SetPixelData(
        BitmapPixelFormat::Bgra8,
        BitmapAlphaMode::Straight,
        cropped_width as u32,
        cropped_height as u32,
        f64::from(dpi),
        f64::from(dpi),
        &pixels,
    )?;
    encoder.FlushAsync()?.get()?;
    let jpeg_len = u32::try_from(stream.Size()?)
        .context("encoded monitor image exceeds stream read limits")?;
    let reader = DataReader::CreateDataReader(&stream.GetInputStreamAt(0)?)?;
    let loaded = reader.LoadAsync(jpeg_len)?.get()?;
    anyhow::ensure!(
        loaded == jpeg_len,
        "encoded monitor image stream is incomplete"
    );
    let mut jpeg = vec![0; jpeg_len as usize];
    reader.ReadBytes(&mut jpeg)?;
    Ok(MonitorRegionJpeg {
        jpeg,
        encoded_width,
        encoded_height,
        cropped_width: cropped_width as u32,
        cropped_height: cropped_height as u32,
        dpi,
    })
}
