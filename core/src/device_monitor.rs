use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

use sysinfo::Disks;
use tokio::sync::RwLock;

use crate::config::{matches_exclusion, CoreConfig};
use crate::scan::{ScanManager, ScanMode, ScanRuntimeConfig};

pub async fn run_device_monitor(
    config: Arc<RwLock<CoreConfig>>,
    scan_manager: Arc<ScanManager>,
) {
    let mut disks = Disks::new_with_refreshed_list();
    let mut known_devices: HashSet<String> = {
        let config = config.read().await;
        let current = collect_device_mounts(&mut disks, config.device_scan_removable_only);
        current.keys().cloned().collect()
    };

    loop {
        let (enabled, interval_ms, removable_only, mode_string, scan_config) = {
            let config = config.read().await;
            let scan_config = ScanRuntimeConfig::from_config(&config);
            (
                config.device_scan_enabled,
                config.device_scan_interval_ms,
                config.device_scan_removable_only,
                config.device_scan_mode.clone(),
                scan_config,
            )
        };

        tokio::time::sleep(Duration::from_millis(interval_ms)).await;

        let current = collect_device_mounts(&mut disks, removable_only);
        known_devices.retain(|key| current.contains_key(key));
        if !enabled {
            known_devices = current.keys().cloned().collect();
            continue;
        }

        for (key, mount) in current.iter() {
            if known_devices.contains(key) {
                continue;
            }

            if matches_exclusion(&scan_config.exclude_programs, "", Some(mount)) {
                known_devices.insert(key.clone());
                continue;
            }

            let scan_config = scan_config.clone();
            let mode = if mode_string == "full" {
                ScanMode::Full
            } else {
                ScanMode::Quick
            };

            println!("[DEVICE] Nuevo dispositivo detectado: {}", key);
            match scan_manager
                .start_scan_with_roots(mode, scan_config, vec![mount.clone()])
                .await
            {
                Ok(_) => {
                    known_devices.insert(key.clone());
                }
                Err(error) => {
                    if error != "Scan already running" {
                        known_devices.insert(key.clone());
                    }
                    eprintln!("[DEVICE] No se pudo iniciar el escaneo: {}", error);
                }
            }
        }
    }
}

fn collect_device_mounts(
    disks: &mut Disks,
    removable_only: bool,
) -> HashMap<String, PathBuf> {
    disks.refresh_list();
    let mut mounts = HashMap::new();

    for disk in disks.list() {
        let mount = disk.mount_point();
        if !mount.exists() {
            continue;
        }
        if removable_only && !is_removable_mount(disk, mount) {
            continue;
        }

        let key = mount.to_string_lossy().to_string();
        mounts.insert(key, mount.to_path_buf());
    }

    mounts
}

fn is_removable_mount(disk: &sysinfo::Disk, mount: &Path) -> bool {
    if disk.is_removable() {
        return true;
    }

    #[cfg(windows)]
    {
        if let Some(removable) = windows_drive_is_removable(mount) {
            return removable;
        }
    }

    false
}

#[cfg(windows)]
fn windows_drive_is_removable(mount: &Path) -> Option<bool> {
    use winapi::um::fileapi::GetDriveTypeW;
    use winapi::um::winbase::{
        DRIVE_CDROM, DRIVE_NO_ROOT_DIR, DRIVE_REMOVABLE, DRIVE_UNKNOWN,
    };

    let mut wide: Vec<u16> = mount.as_os_str().encode_wide().collect();
    if !wide.is_empty() && !wide.ends_with(&['\\' as u16]) {
        wide.push('\\' as u16);
    }
    wide.push(0);

    let drive_type = unsafe { GetDriveTypeW(wide.as_ptr()) };
    match drive_type {
        DRIVE_REMOVABLE | DRIVE_CDROM => Some(true),
        DRIVE_UNKNOWN | DRIVE_NO_ROOT_DIR => None,
        _ => Some(false),
    }
}
