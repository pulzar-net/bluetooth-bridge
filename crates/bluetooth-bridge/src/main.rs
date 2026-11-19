//! `bluetooth-bridge`: a Bluetooth LE to MQTT bridge.

use std::path::PathBuf;
use std::time::Duration;

use bluetooth_bridge::Config;

const USAGE: &str = "\
Usage: bluetooth-bridge [--config FILE]
       bluetooth-bridge probe TRANSPORT
       bluetooth-bridge --version

  --config FILE   configuration (default /etc/bluetooth-bridge/config.toml)
  probe           name the controller at TRANSPORT (hci0, serial:PATH:BAUD,
                  tcp:HOST:PORT) as JSON, and exit

Logging follows RUST_LOG (default info).";

fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();
    match args() {
        Ok(cmd) => {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("runtime: {e}");
                    return std::process::ExitCode::FAILURE;
                }
            };
            match rt.block_on(run(cmd)) {
                Ok(()) => std::process::ExitCode::SUCCESS,
                Err(e) => {
                    tracing::error!("{e}");
                    std::process::ExitCode::FAILURE
                }
            }
        }
        Err(e) => {
            eprintln!("{e}\n\n{USAGE}");
            std::process::ExitCode::from(2)
        }
    }
}

enum Command {
    Run(PathBuf),
    Probe(String),
    Exit,
}

fn args() -> Result<Command, String> {
    use lexopt::prelude::*;
    let mut parser = lexopt::Parser::from_env();
    let mut config = PathBuf::from("/etc/bluetooth-bridge/config.toml");
    while let Some(arg) = parser.next().map_err(|e| e.to_string())? {
        match arg {
            Long("config") | Short('c') => {
                config = parser.value().map_err(|e| e.to_string())?.into()
            }
            Long("version") | Short('V') => {
                println!("bluetooth-bridge {}", env!("CARGO_PKG_VERSION"));
                return Ok(Command::Exit);
            }
            Long("help") | Short('h') => {
                println!("{USAGE}");
                return Ok(Command::Exit);
            }
            Value(v) if v == "probe" => {
                let t = parser
                    .value()
                    .map_err(|_| "probe needs a transport".to_string())?;
                return Ok(Command::Probe(
                    t.string().map_err(|_| "transport is not UTF-8")?,
                ));
            }
            other => return Err(other.unexpected().to_string()),
        }
    }
    Ok(Command::Run(config))
}

async fn run(cmd: Command) -> Result<(), String> {
    match cmd {
        Command::Exit => Ok(()),
        Command::Probe(t) => {
            let spec = t.parse()?;
            let r = bluetooth_host::probe::probe(&spec, Duration::from_secs(5))
                .await
                .map_err(|e| e.to_string())?;
            println!("{}", serde_json::to_string_pretty(&r).unwrap_or_default());
            Ok(())
        }
        Command::Run(path) => {
            let config = Config::load(&path).map_err(|e| e.to_string())?;
            bluetooth_bridge::run(config).await
        }
    }
}
