//! SOS 共享内存模块
//!
//! SHMEM 创建/打开、布局常量、SosShmemCapturer 读帧、自定义捕获器工厂注入。
//!
//! 使用 Windows 原生 `CreateFileMappingW(INVALID_HANDLE_VALUE)` +
//! `MapViewOfFile`，以系统分页文件为后端，零磁盘写入。

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Memory::{
    CreateFileMappingW, MapViewOfFile, OpenFileMappingW, UnmapViewOfFile,
    MEMORY_BASIC_INFORMATION, MEMORY_MAPPED_VIEW_ADDRESS, FILE_MAP_ALL_ACCESS,
    PAGE_READWRITE, VirtualQuery,
};

// ── SHMEM 帧数据区布局常量（写端 run_capture_shmem 与 读端 SosShmemCapturer 共享） ──

pub const SHMEM_NAME: &str = "sos";
pub const SHMEM_ADDR_CAPTURE_FRAME_INFO: usize = 120;
pub const SHMEM_ADDR_CAPTURE_WOULDBLOCK: usize = 144;
pub const SHMEM_ADDR_CAPTURE_FRAME_COUNTER: usize = 148;
pub const SHMEM_ADDR_CAPTURE_FRAME: usize = 192;

// ── SOS 自有共享内存封装 ──

/// SOS 自有的命名共享内存封装。
///
/// 使用 Windows `CreateFileMappingW(INVALID_HANDLE_VALUE)` + `MapViewOfFile`
/// 创建分页文件后端的命名共享内存，**不留任何磁盘文件痕迹**。
/// Drop 时自动 `UnmapViewOfFile` + `CloseHandle` 清理。
pub struct SosShmem {
    mapping: HANDLE,
    view: MEMORY_MAPPED_VIEW_ADDRESS,
    len: usize,
}

unsafe impl Send for SosShmem {}
unsafe impl Sync for SosShmem {}

impl Drop for SosShmem {
    fn drop(&mut self) {
        unsafe {
            UnmapViewOfFile(self.view);
            let _ = CloseHandle(self.mapping);
        }
    }
}

impl SosShmem {
    /// Windows 内核对象名（`CreateFileMappingW` 的命名空间）
    fn os_id(name: &str) -> Vec<u16> {
        let wide: Vec<u16> = format!("RustDeskSOS_{}\0", name)
            .encode_utf16()
            .collect();
        wide
    }

    pub fn create(name: &str, size: usize) -> hbb_common::ResultType<Self> {
        let wname = Self::os_id(name);
        let high = ((size as u64 >> 32) & 0xFFFF_FFFF) as u32;
        let low = (size as u64 & 0xFFFF_FFFF) as u32;

        let mapping = unsafe {
            CreateFileMappingW(
                HANDLE(-1isize as _), // INVALID_HANDLE_VALUE → 分页文件后端
                None,
                PAGE_READWRITE,
                high,
                low,
                PCWSTR(wname.as_ptr()),
            )
        }?;

        let view = unsafe { MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, size) };

        if view.Value.is_null() {
            let err = unsafe { windows::Win32::Foundation::GetLastError() };
            unsafe { let _ = CloseHandle(mapping); };
            return Err(anyhow::anyhow!(
                "SosShmem create '{}' MapViewOfFile failed: win32 error {}",
                name,
                err.0
            ));
        }

        log::info!(
            "SosShmem created: name={} size={} mapping=0x{:x} ptr=0x{:x}",
            name,
            size,
            mapping.0 as usize,
            view.Value as usize
        );
        Ok(SosShmem {
            mapping,
            view,
            len: size,
        })
    }

    pub fn open_existing(name: &str) -> hbb_common::ResultType<Self> {
        let wname = Self::os_id(name);

        let mapping = unsafe { OpenFileMappingW(FILE_MAP_ALL_ACCESS.0, false, PCWSTR(wname.as_ptr())) }?;

        // 映射整个文件映射视图（传递 0 表示映射整个文件）
        let view = unsafe { MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, 0) };

        if view.Value.is_null() {
            let err = unsafe { windows::Win32::Foundation::GetLastError() };
            unsafe { let _ = CloseHandle(mapping); };
            return Err(anyhow::anyhow!(
                "SosShmem open '{}' MapViewOfFile failed: win32 error {}",
                name,
                err.0
            ));
        }

        // 查询映射区域的实际大小
        let mut info = MEMORY_BASIC_INFORMATION::default();
        let query_size = unsafe {
            VirtualQuery(
                Some(view.Value),
                &mut info,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        let region_size = if query_size > 0 {
            info.RegionSize
        } else {
            0
        };

        log::info!(
            "SosShmem opened: name={} mapping=0x{:x} ptr=0x{:x} len={}",
            name,
            mapping.0 as usize,
            view.Value as usize,
            region_size
        );
        Ok(SosShmem {
            mapping,
            view,
            len: region_size,
        })
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.view.Value as *const u8
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn write(&self, addr: usize, data: &[u8]) {
        unsafe {
            debug_assert!(addr + data.len() <= self.len);
            let dst = (self.view.Value as *mut u8).add(addr);
            std::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len());
        }
    }
}

// ── 自定义捕获器工厂 ──

/// 存放 SOS SHMEM 及尺寸信息（持有所有权，防止悬空指针）
static SHMEM_STATE: std::sync::Mutex<Option<(SosShmem, usize, usize)>> =
    std::sync::Mutex::new(None);
// (shmem, width, height)

/// 标记 factory 是否有效：清除时设为 false，capturer 检测到此标志会返回错误触发 video_service 重启
static SHMEM_FACTORY_ACTIVE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// 注入 SHMEM 状态并注册自定义捕获器工厂到 video_service。
/// 首次调用时存储 `SosShmem`（持有所有权），后续调用复用已有映射。
pub fn register_shmem_and_factory(shmem: SosShmem, width: usize, height: usize) {
    let ptr = shmem.as_ptr() as usize;
    let len = shmem.len();
    log::info!(
        "[register_shmem_and_factory] ptr=0x{:x} len={} w={} h={}",
        ptr,
        len,
        width,
        height
    );

    let mut state = SHMEM_STATE.lock().unwrap();
    if state.is_none() {
        *state = Some((shmem, width, height));
    }
    // 已存在 SHMEM 时 drop 新打开的（旧映射仍有效，避免替换时旧 capturer 悬空）
    drop(state);

    // 先清除再设置（确保动态切换生效）
    librustdesk::video_service::clear_custom_capturer_factory();
    SHMEM_FACTORY_ACTIVE.store(true, std::sync::atomic::Ordering::SeqCst);
    librustdesk::video_service::set_custom_capturer_factory(Box::new(
        |_current, _display, _running| {
            let state = SHMEM_STATE.lock().unwrap();
            let (ref shmem, w, h) = state.as_ref().expect("SHMEM_STATE not set");
            Ok(Box::new(SosShmemCapturer::new(
                shmem.as_ptr(),
                shmem.len(),
                *w,
                *h,
            )))
        },
    ));
}

/// 清除工厂并标记 SHMEM 无效（UAC 退出时调用）
/// capturer 检测到此标志会返回错误，触发 video_service 重启回 DXGI
pub fn clear_shmem_factory() {
    SHMEM_FACTORY_ACTIVE.store(false, std::sync::atomic::Ordering::SeqCst);
    librustdesk::video_service::clear_custom_capturer_factory();
    log::info!("SHMEM factory cleared, capturers will restart");
}

/// 创建 SOS 自有 SHMEM，返回内存对象。
pub fn create_shmem() -> hbb_common::ResultType<SosShmem> {
    use hbb_common::bail;

    let displays = scrap::Display::all()?;
    if displays.is_empty() {
        bail!("no display available");
    }

    const ALIGN: usize = 64;
    const ADDR_FRAME: usize = 192;
    let mut max_pixel = 0;
    for d in &displays {
        let w = d.width() as usize;
        let h = d.height() as usize;
        let pixel = ((w + ALIGN - 1) / ALIGN * ALIGN) * ((h + ALIGN - 1) / ALIGN * ALIGN);
        if pixel > max_pixel {
            max_pixel = pixel;
        }
    }
    let shmem_size = (ADDR_FRAME + max_pixel * 4 + ALIGN - 1) / ALIGN * ALIGN;

    let shmem = SosShmem::create(SHMEM_NAME, shmem_size)?;
    log::info!("SOS SHMEM created: size={}", shmem_size);
    Ok(shmem)
}

// ── SOS SHMEM 读取器 ──

/// SOS 自有的共享内存捕获器，实现 `scrap::TraitCapturer`。
///
/// 直接按固定偏移量从 SHMEM 中读取 FrameInfo 和帧数据，
/// 返回 `Frame::PixelBuffer(BGRA)`。
pub struct SosShmemCapturer {
    shmem_ptr: *const u8,
    shmem_len: usize,
    _width: usize,
    _height: usize,
}

unsafe impl Send for SosShmemCapturer {}
unsafe impl Sync for SosShmemCapturer {}

impl SosShmemCapturer {
    pub fn new(ptr: *const u8, len: usize, width: usize, height: usize) -> Self {
        Self {
            shmem_ptr: ptr,
            shmem_len: len,
            _width: width,
            _height: height,
        }
    }

    fn read_counter(&self) -> i32 {
        unsafe {
            let ptr = self.shmem_ptr.add(SHMEM_ADDR_CAPTURE_FRAME_COUNTER);
            *(ptr as *const i32)
        }
    }

    fn read_counter_echo(&self) -> i32 {
        unsafe {
            let ptr = self.shmem_ptr.add(SHMEM_ADDR_CAPTURE_FRAME_COUNTER + 4);
            *(ptr as *const i32)
        }
    }

    fn update_counter_echo(&self) {
        unsafe {
            let wptr = self.shmem_ptr.add(SHMEM_ADDR_CAPTURE_FRAME_COUNTER);
            let rptr = wptr.add(4);
            std::ptr::copy_nonoverlapping(wptr, rptr as *mut _, 4);
        }
    }

    fn is_wouldblock(&self) -> bool {
        unsafe {
            let ptr = self.shmem_ptr.add(SHMEM_ADDR_CAPTURE_WOULDBLOCK);
            *(ptr as *const i32) == 1
        }
    }

    fn read_frame_info(&self) -> (usize, usize, usize) {
        unsafe {
            let ptr = self.shmem_ptr.add(SHMEM_ADDR_CAPTURE_FRAME_INFO);
            let fi = ptr as *const (usize, usize, usize);
            *fi
        }
    }

    fn read_frame_data(&self, len: usize) -> &[u8] {
        unsafe {
            let ptr = self.shmem_ptr.add(SHMEM_ADDR_CAPTURE_FRAME);
            std::slice::from_raw_parts(ptr, len)
        }
    }
}

impl scrap::TraitCapturer for SosShmemCapturer {
    fn frame<'a>(&'a mut self, _timeout: std::time::Duration) -> std::io::Result<scrap::Frame<'a>> {
        use scrap::Frame;

        // 检查 factory 是否已被清除（UAC 退出），是则返回错误触发 video_service 重启
        if !SHMEM_FACTORY_ACTIVE.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "shmem factory cleared",
            ));
        }

        let wcnt = self.read_counter();
        let ecnt = self.read_counter_echo();
        let has_new = wcnt != ecnt;
        let wb = self.is_wouldblock();

        if has_new {
            let (len, w, h) = self.read_frame_info();
            log::debug!(
                "[SosShmemCapturer::frame] NEW wcnt={} ecnt={} len={} w={} h={}",
                wcnt,
                ecnt,
                len,
                w,
                h
            );
            if len > 0 && len <= self.shmem_len.saturating_sub(SHMEM_ADDR_CAPTURE_FRAME) {
                self.update_counter_echo();
                let data = self.read_frame_data(len);
                let pb = scrap::PixelBuffer::with_BGRA(data, w, h);
                return Ok(Frame::PixelBuffer(pb));
            }
        }

        static ERR_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = ERR_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if n % 200 == 0 {
            log::debug!(
                "[SosShmemCapturer::frame] NOFRAME n={} wcnt={} ecnt={} wb={} has_new={}",
                n,
                wcnt,
                ecnt,
                wb,
                has_new
            );
        }

        // 没有新帧时统一返回 WouldBlock，让上游主循环重试而非重启服务
        Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "shmem wouldblock",
        ))
    }

    fn is_gdi(&self) -> bool {
        true
    }
    fn set_gdi(&mut self) -> bool {
        true
    }
}
