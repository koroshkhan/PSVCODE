#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use ps5_file_dump::gui::launch_gui;
use ps5_file_dump::library::scan_library_folder;
use ps5_file_dump::orchestrator::{execute_cli_command, CliCommand};
use ps5_file_dump::queue_engine::JobPriority;
use std::io;
use std::path::PathBuf;

fn main() -> io::Result<()> {
    let mut args = std::env::args().skip(1);
    let Some(cmd) = args.next() else {
        launch_gui().map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        return Ok(());
    };

    match cmd.as_str() {
        "inspect" => {
            let target = PathBuf::from(args.next().unwrap_or_else(|| ".".into()));
            let console_fw = args.next();
            execute_cli_command(CliCommand::Inspect { target, console_fw })
        }
        "library" => {
            let root = PathBuf::from(args.next().unwrap_or_else(|| ".".into()));
            let console_fw = args.next();
            let summary = scan_library_folder(&root, console_fw.as_deref())?;
            println!(
                "ps5_file_dump Library: {} items | Ready: {} | Warning: {} | Blocked: {} | Bytes: {}",
                summary.items.len(),
                summary.ready_count,
                summary.warning_count,
                summary.blocked_count,
                summary.total_bytes
            );
            Ok(())
        }
        "stream" => {
            let source = PathBuf::from(args.next().expect("Source path required"));
            let output = PathBuf::from(args.next().expect("Output path required"));
            let force = args.any(|a| a == "--force");
            execute_cli_command(CliCommand::Stream {
                source,
                output,
                priority: JobPriority::Normal,
                console_fw: None,
                force,
            })
        }
        "send-elf" => {
            let elf_path = PathBuf::from(args.next().expect("ELF path required"));
            let ps5_ip = args.next().expect("PS5 IP required");
            let port: u16 = args
                .next()
                .and_then(|p| p.parse().ok())
                .unwrap_or(9021);
            execute_cli_command(CliCommand::SendElf {
                elf_path,
                ps5_ip,
                port,
            })
        }
        _ => {
            launch_gui().map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            Ok(())
        }
    }
}
