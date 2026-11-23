use crate::analyzer::{run_preflight_analysis, PreFlightReport, ReadinessStatus};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct LibraryItem {
    pub path: PathBuf,
    pub report: PreFlightReport,
}

#[derive(Debug, Clone, Default)]
pub struct LibrarySummary {
    pub items: Vec<LibraryItem>,
    pub ready_count: usize,
    pub warning_count: usize,
    pub blocked_count: usize,
    pub total_bytes: u64,
}

pub fn scan_library_folder(root: &Path, console_fw: Option<&str>) -> io::Result<LibrarySummary> {
    if !root.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Library path does not exist or is not a directory.",
        ));
    }

    let mut summary = LibrarySummary::default();
    let mut entries: Vec<PathBuf> = fs::read_dir(root)?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            let name = p
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default();
            !name.starts_with('.') && !name.ends_with(".part")
        })
        .collect();

    entries.sort();

    for entry in entries {
        let report = run_preflight_analysis(&entry, console_fw, None)?;
        match report.status {
            ReadinessStatus::Ready => summary.ready_count += 1,
            ReadinessStatus::Warning => summary.warning_count += 1,
            ReadinessStatus::Blocked => summary.blocked_count += 1,
        }
        summary.total_bytes = summary
            .total_bytes
            .saturating_add(report.metadata.total_bytes);

        summary.items.push(LibraryItem {
            path: entry,
            report,
        });
    }

    Ok(summary)
}
