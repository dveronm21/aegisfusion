#[cfg(windows)]
mod windows_service_impl {
    use std::ffi::OsString;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use tokio::sync::oneshot;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{
        self, ServiceControlHandlerResult,
    };
    use windows_service::service_dispatcher;
    use windows_service::define_windows_service;

    const SERVICE_NAME: &str = "AegisFusionCore";

    define_windows_service!(ffi_service_main, service_main);

    pub fn run_service() -> Result<(), Box<dyn std::error::Error>> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
        Ok(())
    }

    fn service_main(_args: Vec<OsString>) {
        if let Err(error) = run_service_inner() {
            eprintln!("[SERVICE] Failed to start: {}", error);
        }
    }

    fn run_service_inner() -> Result<(), Box<dyn std::error::Error>> {
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let shutdown_tx = Arc::new(Mutex::new(Some(shutdown_tx)));

        let shutdown_handle = Arc::clone(&shutdown_tx);
        let status_handle = service_control_handler::register(
            SERVICE_NAME,
            move |control_event| match control_event {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    if let Some(sender) = shutdown_handle.lock().unwrap().take() {
                        let _ = sender.send(());
                    }
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            },
        )?;

        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(10),
            process_id: None,
        })?;

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;

        let stats = runtime.block_on(async move { crate::run_until_shutdown(shutdown_rx).await });

        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(0),
            process_id: None,
        })?;

        println!(
            "[SERVICE] Stats: total={}, ok={}, failed={}",
            stats.total_responses, stats.successful, stats.failed
        );

        Ok(())
    }
}

#[cfg(windows)]
pub use windows_service_impl::run_service;

#[cfg(not(windows))]
pub fn run_service() -> Result<(), Box<dyn std::error::Error>> {
    Err("Windows service mode is only supported on Windows".into())
}
