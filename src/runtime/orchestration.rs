use crate::cli::{Cli, Commands};
use crate::replay::ReplayOptions;
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
use crate::runtime::capture::CaptureOptions;
#[cfg(target_os = "linux")]
use crate::runtime::linux as platform_runtime;
#[cfg(target_os = "macos")]
use crate::runtime::macos as platform_runtime;

/// Commands that need neither sensors nor a platform runtime, handled before
/// any platform dispatch so they behave identically everywhere.
fn run_portable_command(cli: &Cli) -> Option<anyhow::Result<()>> {
    match &cli.command {
        Some(Commands::Replay { recording, output }) => {
            Some(crate::replay::run_cli(ReplayOptions {
                recording: recording.clone(),
                output: output.clone(),
                log_level: cli.log_level.clone(),
                config_path: cli.config.clone(),
            }))
        }
        // Response operations run in this process, not the service, and reach
        // the same kernel and on-disk state the service does. They are handled
        // here so they work on every platform and in both install modes.
        Some(Commands::Response { action }) => Some(run_response_command(action.clone(), cli)),
        _ => None,
    }
}

/// Load the configuration a response command needs, then run it.
fn run_response_command(
    action: crate::response::cli::ResponseAction,
    cli: &Cli,
) -> anyhow::Result<()> {
    let config = crate::config::AppConfig::from_config_path(cli.config.clone())
        .map_err(|err| anyhow::anyhow!("{err}"))?;
    let code = crate::response::cli::run_cli(action, &config)?;
    std::process::exit(code);
}

#[cfg(windows)]
pub fn run() -> anyhow::Result<()> {
    let cli = Cli::parse_args();

    if let Some(result) = run_portable_command(&cli) {
        return result;
    }

    if let Some(Commands::Doctor { json }) = &cli.command {
        let code = crate::doctor::run_cli(cli.config.clone(), *json)?;
        std::process::exit(code);
    }

    if windows_service::service_dispatcher::start(
        crate::platform::windows::SERVICE_NAME,
        crate::runtime::windows::ffi_service_main,
    )
    .is_ok()
    {
        return Ok(());
    }

    match cli.command {
        Some(Commands::Run { no_console, .. }) => {
            crate::runtime::windows::run_console(!no_console, cli.log_level, cli.config)
        }
        Some(Commands::Capture { output }) => {
            crate::runtime::windows::run_capture(CaptureOptions {
                output,
                log_level: cli.log_level,
                config_path: cli.config,
            })
        }
        None => crate::runtime::windows::run_console(true, cli.log_level, cli.config),
        Some(Commands::Doctor { .. }) => unreachable!("doctor is handled before service dispatch"),
        Some(Commands::Response { .. }) => {
            unreachable!("response is handled before service dispatch")
        }
        Some(Commands::Replay { .. }) => {
            unreachable!("replay is handled before service dispatch")
        }
        Some(Commands::Service { action }) => crate::platform::handle_service_command(action),
        Some(Commands::Rules { action }) => crate::rules::run_cli(action, cli.config),
        Some(Commands::Setup {
            pack,
            yes,
            no_start,
            force,
            catalog_url,
        }) => crate::setup::run_cli(crate::setup::SetupOptions {
            pack,
            yes,
            no_start,
            force,
            catalog_url,
        }),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn run() -> anyhow::Result<()> {
    let cli = Cli::parse_args();

    if let Some(result) = run_portable_command(&cli) {
        return result;
    }

    match cli.command {
        Some(Commands::Replay { .. }) => unreachable!("replay is handled before platform dispatch"),
        Some(Commands::Response { .. }) => {
            unreachable!("response is handled before platform dispatch")
        }
        Some(Commands::Service { action }) => crate::platform::handle_service_command(action),
        Some(Commands::Doctor { json }) => {
            let code = crate::doctor::run_cli(cli.config, json)?;
            std::process::exit(code);
        }
        Some(Commands::Rules { action }) => crate::rules::run_cli(action, cli.config),
        Some(Commands::Setup {
            pack,
            yes,
            no_start,
            force,
            catalog_url,
        }) => crate::setup::run_cli(crate::setup::SetupOptions {
            pack,
            yes,
            no_start,
            force,
            catalog_url,
        }),
        Some(Commands::Run { no_console, .. }) => {
            platform_runtime::run(!no_console, cli.log_level, cli.config)
        }
        Some(Commands::Capture { output }) => platform_runtime::run_capture(CaptureOptions {
            output,
            log_level: cli.log_level,
            config_path: cli.config,
        }),
        None => platform_runtime::run(true, cli.log_level, cli.config),
    }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub fn run() -> anyhow::Result<()> {
    // Replay still works here: it reads a recording rather than an endpoint.
    if let Some(result) = run_portable_command(&Cli::parse_args()) {
        return result;
    }

    Err(anyhow::anyhow!(
        "This platform is not supported. Rustinel runs on Windows (ETW), Linux (eBPF), and macOS (ESF)."
    ))
}
