use crate::analyzer::{run_preflight_analysis, PreFlightReport, ReadinessStatus};
use crate::net::send_elf_payload;
use crate::queue_engine::{JobPriority, StreamQueueEngine, TransferJob};
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct OrchestratorOptions {
    pub console_fw: Option<String>,
    pub dest_free_bytes: Option<u64>,
    pub allow_warnings: bool,
    pub force_on_blocked: bool,
    pub concurrency: usize,
    pub buffer_bytes: usize,
}

impl Default for OrchestratorOptions {
    fn default() -> Self {
        Self {
            console_fw: None,
            dest_free_bytes: None,
            allow_warnings: true,
            force_on_blocked: false,
            concurrency: 2,
            buffer_bytes: 2 * 1024 * 1024,
        }
    }
}

pub fn guarded_enqueue_stream(
    engine: &StreamQueueEngine,
    job_id: u64,
    priority: JobPriority,
    source: &Path,
    final_output: &Path,
    opts: &OrchestratorOptions,
) -> io::Result<PreFlightReport> {
    let report = run_preflight_analysis(
        source,
        opts.console_fw.as_deref(),
        opts.dest_free_bytes,
    )?;

    match report.status {
        ReadinessStatus::Blocked if !opts.force_on_blocked => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Blocked by pre-flight analysis.",
            ));
        }
        ReadinessStatus::Warning if !opts.allow_warnings => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Stopped due to warnings.",
            ));
        }
        _ => {}
    }

    engine.enqueue(TransferJob {
        id: job_id,
        priority,
        source: source.to_path_buf(),
        final_output: final_output.to_path_buf(),
        max_retries: 3,
        buffer_bytes: opts.buffer_bytes,
        verify_size: true,
    });

    Ok(report)
}

#[derive(Debug, Clone)]
pub enum CliCommand {
    Inspect {
        target: PathBuf,
        console_fw: Option<String>,
    },
    Stream {
        source: PathBuf,
        output: PathBuf,
        priority: JobPriority,
        console_fw: Option<String>,
        force: bool,
    },
    SendElf {
        elf_path: PathBuf,
        ps5_ip: String,
        port: u16,
    },
}

pub fn execute_cli_command(cmd: CliCommand) -> io::Result<()> {
    match cmd {
        CliCommand::Inspect { target, console_fw } => {
            let report = run_preflight_analysis(&target, console_fw.as_deref(), None)?;
            println!("Format: {} | Status: {:?}", report.detected_label, report.status);
            Ok(())
        }
        CliCommand::Stream {
            source,
            output,
            priority,
            console_fw,
            force,
        } => {
            let opts = OrchestratorOptions {
                console_fw,
                force_on_blocked: force,
                ..OrchestratorOptions::default()
            };
            let engine = StreamQueueEngine::new(opts.concurrency);
            let _ = guarded_enqueue_stream(&engine, 1, priority, &source, &output, &opts)?;
            engine.run_all();
            Ok(())
        }
        CliCommand::SendElf {
            elf_path,
            ps5_ip,
            port,
        } => send_elf_payload(&elf_path, &ps5_ip, port),
    }
}
