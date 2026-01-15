use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::types::{EventDetails, EventType, SystemEvent};

#[cfg(windows)]
mod win {
    use super::*;
    use std::ffi::OsStr;
    use std::mem;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;
    use std::sync::OnceLock;

    use winapi::shared::minwindef::{DWORD, FALSE, LPVOID};
    use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING, QueryDosDeviceW};
    use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
    use winapi::um::ioapiset::DeviceIoControl;
    use winapi::um::winnt::{
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, GENERIC_WRITE,
        HANDLE,
    };

    const DEVICE_PATH: &str = "\\\\.\\AegisFusion";
    const IOCTL_AEGIS_START: DWORD = 0x222004;
    const IOCTL_AEGIS_STOP: DWORD = 0x222008;
    const IOCTL_AEGIS_GET_EVENT: DWORD = 0x22200C;

    const ERROR_NO_MORE_ITEMS: i32 = 259;
    const ERROR_NO_MORE_FILES: i32 = 18;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct RawEvent {
        timestamp: i64,
        event_type: u32,
        process_id: u32,
        parent_process_id: u32,
        thread_id: u32,
        process_name: [u16; 64],
        path: [u16; 260],
        data_length: u32,
        data: [u8; 256],
    }

    struct HandleGuard {
        handle: HANDLE,
    }

    impl HandleGuard {
        fn new() -> std::io::Result<Self> {
            let device_name: Vec<u16> = OsStr::new(DEVICE_PATH)
                .encode_wide()
                .chain(Some(0))
                .collect();

            unsafe {
                let handle = CreateFileW(
                    device_name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    ptr::null_mut(),
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    ptr::null_mut(),
                );

                if handle == INVALID_HANDLE_VALUE {
                    return Err(std::io::Error::last_os_error());
                }

                Ok(Self { handle })
            }
        }

        fn send_ioctl(&self, code: DWORD) -> std::io::Result<()> {
            unsafe {
                let mut bytes_returned: DWORD = 0;
                let result = DeviceIoControl(
                    self.handle,
                    code,
                    ptr::null_mut(),
                    0,
                    ptr::null_mut(),
                    0,
                    &mut bytes_returned,
                    ptr::null_mut(),
                );

                if result == FALSE {
                    return Err(std::io::Error::last_os_error());
                }

                Ok(())
            }
        }

        fn get_event(&self) -> std::io::Result<Option<RawEvent>> {
            unsafe {
                let mut event: RawEvent = mem::zeroed();
                let mut bytes_returned: DWORD = 0;

                let result = DeviceIoControl(
                    self.handle,
                    IOCTL_AEGIS_GET_EVENT,
                    ptr::null_mut(),
                    0,
                    &mut event as *mut _ as LPVOID,
                    mem::size_of::<RawEvent>() as DWORD,
                    &mut bytes_returned,
                    ptr::null_mut(),
                );

                if result == FALSE {
                    let error = std::io::Error::last_os_error();
                    match error.raw_os_error() {
                        Some(ERROR_NO_MORE_ITEMS) | Some(ERROR_NO_MORE_FILES) => return Ok(None),
                        _ => return Err(error),
                    }
                }

                Ok(Some(event))
            }
        }
    }

    impl Drop for HandleGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = self.send_ioctl(IOCTL_AEGIS_STOP);
                CloseHandle(self.handle);
            }
        }
    }

    unsafe impl Send for HandleGuard {}

    unsafe impl Send for KernelState {}
    unsafe impl Sync for KernelState {}

    pub struct KernelState {
        handle: Option<HandleGuard>,
        monitoring: bool,
        last_error: Option<String>,
        last_error_log: Instant,
    }

    impl KernelState {
        pub fn new() -> Self {
            Self {
                handle: None,
                monitoring: false,
                last_error: None,
                last_error_log: Instant::now() - Duration::from_secs(60),
            }
        }

        pub fn poll(&mut self, counter: &AtomicU64) -> Vec<SystemEvent> {
            if self.handle.is_none() {
                match HandleGuard::new() {
                    Ok(handle) => {
                        self.handle = Some(handle);
                        self.monitoring = false;
                        self.last_error = None;
                    }
                    Err(error) => {
                        self.last_error = Some(error.to_string());
                        if self.last_error_log.elapsed() > Duration::from_secs(30) {
                            self.last_error_log = Instant::now();
                            eprintln!("[KERNEL] Driver not available: {}", error);
                        }
                        return Vec::new();
                    }
                }
            }

            if let Some(handle) = &self.handle {
                if !self.monitoring {
                    if let Err(error) = handle.send_ioctl(IOCTL_AEGIS_START) {
                        self.last_error = Some(error.to_string());
                        if self.last_error_log.elapsed() > Duration::from_secs(30) {
                            self.last_error_log = Instant::now();
                            eprintln!("[KERNEL] Failed to start monitoring: {}", error);
                        }
                        self.handle = None;
                        return Vec::new();
                    }
                    self.monitoring = true;
                }

                let mut events = Vec::new();
                loop {
                    match handle.get_event() {
                        Ok(Some(raw)) => {
                            if let Some(event) = map_event(raw, counter) {
                                events.push(event);
                            }
                        }
                        Ok(None) => break,
                        Err(error) => {
                            self.last_error = Some(error.to_string());
                            if self.last_error_log.elapsed() > Duration::from_secs(30) {
                                self.last_error_log = Instant::now();
                                eprintln!("[KERNEL] Failed to read event: {}", error);
                            }
                            break;
                        }
                    }
                }
                return events;
            }

            Vec::new()
        }
    }

    fn map_event(raw: RawEvent, counter: &AtomicU64) -> Option<SystemEvent> {
        let event_type = match raw.event_type {
            1 => EventType::FileCreated,
            2 => EventType::FileModified,
            3 => EventType::FileDeleted,
            10 => EventType::ProcessStarted,
            11 => EventType::ProcessTerminated,
            20 | 21 => EventType::RegistryModified,
            _ => return None,
        };

        let process_name = wide_to_string(&raw.process_name);
        let path_raw = wide_to_string(&raw.path);
        let path = normalize_path(&path_raw);

        let details = match event_type {
            EventType::FileCreated | EventType::FileModified | EventType::FileDeleted => {
                EventDetails::FileOp {
                    path,
                    hash: None,
                }
            }
            EventType::ProcessStarted | EventType::ProcessTerminated => EventDetails::ProcessOp {
                parent_pid: raw.parent_process_id,
                command_line: decode_command_line(&raw),
            },
            EventType::RegistryModified => EventDetails::RegistryOp {
                key: path,
                value: String::new(),
            },
            _ => return None,
        };

        Some(SystemEvent {
            id: counter.fetch_add(1, Ordering::Relaxed),
            timestamp: filetime_to_systemtime(raw.timestamp),
            event_type,
            process_id: raw.process_id,
            process_name: if process_name.is_empty() {
                "unknown".to_string()
            } else {
                process_name
            },
            details,
            threat_score: 0.0,
        })
    }

    fn wide_to_string(input: &[u16]) -> String {
        let end = input.iter().position(|&c| c == 0).unwrap_or(input.len());
        String::from_utf16_lossy(&input[..end])
    }

    fn decode_command_line(raw: &RawEvent) -> String {
        let mut len = raw.data_length as usize;
        if len == 0 {
            return String::new();
        }

        if len > raw.data.len() {
            len = raw.data.len();
        }

        len &= !1;
        if len == 0 {
            return String::new();
        }

        let mut utf16 = Vec::with_capacity(len / 2);
        for chunk in raw.data[..len].chunks_exact(2) {
            let value = u16::from_le_bytes([chunk[0], chunk[1]]);
            if value == 0 {
                break;
            }
            utf16.push(value);
        }

        if utf16.is_empty() {
            String::new()
        } else {
            String::from_utf16_lossy(&utf16)
        }
    }

    fn normalize_path(path: &str) -> String {
        if path.starts_with("\\\\?\\") {
            return path.trim_start_matches("\\\\?\\").to_string();
        }

        if path.starts_with("\\??\\") {
            return path.trim_start_matches("\\??\\").to_string();
        }

        if !path.starts_with("\\Device\\") {
            return path.to_string();
        }

        for (device, drive) in device_map().iter() {
            if path.starts_with(device) {
                return format!("{}{}", drive, &path[device.len()..]);
            }
        }

        path.to_string()
    }

    fn device_map() -> &'static Vec<(String, String)> {
        static MAP: OnceLock<Vec<(String, String)>> = OnceLock::new();

        MAP.get_or_init(|| {
            let mut mappings = Vec::new();
            for letter in b'A'..=b'Z' {
                let drive = format!("{}:", letter as char);
                let wide: Vec<u16> = OsStr::new(&drive)
                    .encode_wide()
                    .chain(Some(0))
                    .collect();
                let mut target = vec![0u16; 512];

                let len = unsafe {
                    QueryDosDeviceW(wide.as_ptr(), target.as_mut_ptr(), target.len() as DWORD)
                };

                if len == 0 {
                    continue;
                }

                let end = target.iter().position(|&c| c == 0).unwrap_or(len as usize);
                let device = String::from_utf16_lossy(&target[..end]);
                if !device.is_empty() {
                    mappings.push((device, drive));
                }
            }
            mappings
        })
    }

    fn filetime_to_systemtime(filetime: i64) -> SystemTime {
        let ticks = if filetime < 0 { 0 } else { filetime as u64 };
        let unix_offset = 11644473600u64;
        let seconds = ticks / 10_000_000;
        let nanos = (ticks % 10_000_000) * 100;

        if seconds > unix_offset {
            UNIX_EPOCH + Duration::new(seconds - unix_offset, nanos as u32)
        } else {
            UNIX_EPOCH
        }
    }
}

#[cfg(not(windows))]
mod win {
    use super::*;

    pub struct KernelState;

    impl KernelState {
        pub fn new() -> Self {
            Self
        }

        pub fn poll(&mut self, _counter: &AtomicU64) -> Vec<SystemEvent> {
            Vec::new()
        }
    }
}

pub struct KernelComm {
    state: Arc<Mutex<win::KernelState>>,
    counter: Arc<AtomicU64>,
}

impl KernelComm {
    pub fn new() -> Self {
        KernelComm {
            state: Arc::new(Mutex::new(win::KernelState::new())),
            counter: Arc::new(AtomicU64::new(1)),
        }
    }

    pub async fn poll_events(&self) -> Vec<SystemEvent> {
        let state = Arc::clone(&self.state);
        let counter = Arc::clone(&self.counter);

        tokio::task::spawn_blocking(move || {
            let mut state = state.lock().unwrap();
            state.poll(&counter)
        })
        .await
        .unwrap_or_default()
    }
}
