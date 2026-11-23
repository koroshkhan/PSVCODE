use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use zip::ZipArchive;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadinessStatus {
    Ready,
    Warning,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageKind {
    BaseGame,
    UpdateOrDlc,
    ContainerOrArchive,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueCategory {
    FormatAndExtension,
    DumpStructure,
    FirmwareAndBackport,
    AssetIntegrity,
    TargetEnvironment,
}

#[derive(Debug, Clone)]
pub struct DiagnosticFinding {
    pub code: &'static str,
    pub category: IssueCategory,
    pub severity: ReadinessStatus,
    pub message: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Default)]
pub struct GameMetadata {
    pub title: Option<String>,
    pub title_id: Option<String>,
    pub content_id: Option<String>,
    pub required_fw: Option<String>,
    pub eboot_valid_elf64: bool,
    pub has_fakelib: bool,
    pub has_ampr_runtime: bool,
    pub packed_asset_count: usize,
    pub zero_byte_files: usize,
    pub total_files: usize,
    pub total_bytes: u64,
    pub sha256_hex: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PreFlightReport {
    pub target_path: PathBuf,
    pub detected_label: String,
    pub package_kind: PackageKind,
    pub status: ReadinessStatus,
    pub metadata: GameMetadata,
    pub findings: Vec<DiagnosticFinding>,
}

#[derive(Deserialize)]
struct ParamJson {
    title: Option<String>,
    #[serde(rename = "titleId")]
    title_id: Option<String>,
    #[serde(rename = "contentId")]
    content_id: Option<String>,
    #[serde(rename = "requiredSystemSoftwareVersion")]
    required_fw: Option<String>,
    #[serde(rename = "localizedParameters")]
    localized: Option<serde_json::Value>,
}

impl ParamJson {
    fn resolved_title(&self) -> Option<String> {
        if let Some(t) = &self.title {
            if !t.trim().is_empty() {
                return Some(t.clone());
            }
        }
        if let Some(loc) = &self.localized {
            if let Some(en) = loc.get("en-US").and_then(|v| v.get("titleName")).and_then(|v| v.as_str()) {
                return Some(en.to_string());
            }
            if let Some(obj) = loc.as_object() {
                for val in obj.values() {
                    if let Some(name) = val.get("titleName").and_then(|v| v.as_str()) {
                        return Some(name.to_string());
                    }
                }
            }
        }
        None
    }
}

pub fn validate_elf64_bytes(header: &[u8]) -> bool {
    header.len() >= 16
        && &header[0..4] == b"\x7FELF"
        && header[4] == 2
        && header[5] == 1
}

pub fn compute_file_sha256(path: &Path) -> io::Result<String> {
    let mut f = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 1024 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

pub fn sniff_magic_label(path: &Path) -> io::Result<String> {
    if path.is_dir() {
        return Ok("Game Folder / Directory".into());
    }
    let mut f = File::open(path)?;
    let mut buf = [0u8; 16];
    let n = f.read(&mut buf)?;
    let s = &buf[..n];

    let label = if s.starts_with(b"PK\x03\x04") || s.starts_with(b"PK\x05\x06") {
        "ZIP Archive"
    } else if s.starts_with(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
        "7Z Archive"
    } else if s.starts_with(b"Rar!\x1A\x07") {
        "RAR Archive"
    } else if s.starts_with(b"CNT\x00") || s.starts_with(b"FPKG") {
        "PS5 FPKG (.pkg)"
    } else if s.starts_with(b"FFPKG") {
        "FFPKG Image"
    } else if s.starts_with(b"FFPFS") && n >= 6 && s[5] == b'C' {
        "FFPFSC Compressed Image"
    } else if s.starts_with(b"FFPFS") {
        "FFPFS Image"
    } else if n >= 11 && &s[3..11] == b"EXFAT   " {
        "exFAT Dump Image"
    } else if n >= 2 && s[0] == 0x1F && s[1] == 0x8B {
        "GZIP Compressed Stream"
    } else {
        "Raw / Custom Extension Binary"
    };

    Ok(label.into())
}

fn inspect_zip_contents(
    zip_path: &Path,
    console_fw: Option<&str>,
    meta: &mut GameMetadata,
    findings: &mut Vec<DiagnosticFinding>,
) -> io::Result<PackageKind> {
    let f = File::open(zip_path)?;
    let mut archive = ZipArchive::new(f)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Corrupt ZIP archive: {e}")))?;

    let mut found_param_raw: Option<String> = None;
    let mut found_eboot_header: Option<Vec<u8>> = None;
    let mut has_eboot = false;
    let mut seen_paths = HashSet::new();

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        if entry.is_dir() {
            continue;
        }
        meta.total_files += 1;
        let sz = entry.size();
        meta.total_bytes += sz;
        if sz == 0 {
            meta.zero_byte_files += 1;
        }

        let norm = entry.name().replace('\\', "/");
        if !seen_paths.insert(norm.to_ascii_lowercase()) {
            findings.push(DiagnosticFinding {
                code: "ZIP_CASE_COLLISION",
                category: IssueCategory::TargetEnvironment,
                severity: ReadinessStatus::Warning,
                message: format!("Case-collision inside ZIP: {norm}"),
                remediation: "Extract on a case-sensitive filesystem or rename duplicate entries.".into(),
            });
        }

        let lower = norm.to_ascii_lowercase();
        if lower.contains("/fakelib/") || lower.starts_with("fakelib/") {
            meta.has_fakelib = true;
        }
        if lower.ends_with("fakelib/libsceampr.sprx") {
            meta.has_ampr_runtime = true;
        }
        if lower.ends_with(".zstd") || lower.ends_with(".lz4") || lower.ends_with(".fpack") {
            meta.packed_asset_count += 1;
        }

        if lower == "param.json" || lower.ends_with("/param.json") {
            let mut s = String::new();
            if entry.read_to_string(&mut s).is_ok() {
                found_param_raw = Some(s);
            }
        } else if lower == "eboot.bin" || lower.ends_with("/eboot.bin") {
            has_eboot = true;
            let mut hdr = vec![0u8; 32];
            let n = entry.read(&mut hdr).unwrap_or(0);
            hdr.truncate(n);
            found_eboot_header = Some(hdr);
        }
    }

    if let Some(raw) = found_param_raw {
        if let Ok(parsed) = serde_json::from_str::<ParamJson>(&raw) {
            meta.title = parsed.resolved_title();
            meta.title_id = parsed.title_id;
            meta.content_id = parsed.content_id;
            meta.required_fw = parsed.required_fw;
        } else {
            findings.push(DiagnosticFinding {
                code: "INVALID_PARAM_JSON",
                category: IssueCategory::DumpStructure,
                severity: ReadinessStatus::Blocked,
                message: "param.json inside ZIP is malformed JSON.".into(),
                remediation: "Replace param.json with a valid PS5 JSON file.".into(),
            });
        }
    } else {
        findings.push(DiagnosticFinding {
            code: "MISSING_PARAM_JSON",
            category: IssueCategory::DumpStructure,
            severity: ReadinessStatus::Blocked,
            message: "No param.json found inside the ZIP archive.".into(),
            remediation: "Verify this ZIP contains an extracted PS5 game dump.".into(),
        });
    }

    let kind = if has_eboot {
        if let Some(hdr) = found_eboot_header {
            meta.eboot_valid_elf64 = validate_elf64_bytes(&hdr);
            if !meta.eboot_valid_elf64 {
                findings.push(DiagnosticFinding {
                    code: "CORRUPT_EBOOT_BIN",
                    category: IssueCategory::AssetIntegrity,
                    severity: ReadinessStatus::Blocked,
                    message: "eboot.bin inside ZIP is NOT a valid 64-bit ELF executable.".into(),
                    remediation: "Re-dump the game; eboot.bin is truncated, encrypted, or corrupted.".into(),
                });
            }
        }
        PackageKind::BaseGame
    } else {
        findings.push(DiagnosticFinding {
            code: "NO_EBOOT_BIN",
            category: IssueCategory::DumpStructure,
            severity: ReadinessStatus::Warning,
            message: "eboot.bin not found in ZIP (Update/DLC package or incomplete dump).".into(),
            remediation: "Install Base Game first if this archive is Update/DLC.".into(),
        });
        PackageKind::UpdateOrDlc
    };

    evaluate_common_rules(meta, console_fw, findings);
    Ok(kind)
}

fn evaluate_common_rules(
    meta: &GameMetadata,
    console_fw: Option<&str>,
    findings: &mut Vec<DiagnosticFinding>,
) {
    if meta.zero_byte_files > 0 {
        findings.push(DiagnosticFinding {
            code: "ZERO_BYTE_ASSETS",
            category: IssueCategory::AssetIntegrity,
            severity: ReadinessStatus::Warning,
            message: format!("Found {} zero-byte file(s).", meta.zero_byte_files),
            remediation: "Check whether zero-byte files are intentional or failed downloads.".into(),
        });
    }

    if meta.packed_asset_count > 0 && !meta.has_ampr_runtime {
        findings.push(DiagnosticFinding {
            code: "MISSING_AMPR_SPRX",
            category: IssueCategory::FirmwareAndBackport,
            severity: ReadinessStatus::Blocked,
            message: "Packed assets (.zstd/.lz4) found, but fakelib/libSceAmpr.sprx is missing.".into(),
            remediation: "Add libSceAmpr.sprx inside fakelib/ before running on PS5.".into(),
        });
    }

    if meta.has_fakelib {
        findings.push(DiagnosticFinding {
            code: "BACKPORT_FAKELIB_ACTIVE",
            category: IssueCategory::FirmwareAndBackport,
            severity: ReadinessStatus::Warning,
            message: "fakelib/ directory detected; ensure PRX modules match your PS5 firmware.".into(),
            remediation: "Verify backport compatibility with your console firmware.".into(),
        });
    }

    if let (Some(req), Some(cur)) = (&meta.required_fw, console_fw) {
        if req.as_str() > cur && !meta.has_fakelib {
            findings.push(DiagnosticFinding {
                code: "FW_HIGHER_NO_BACKPORT",
                category: IssueCategory::FirmwareAndBackport,
                severity: ReadinessStatus::Blocked,
                message: format!("Required FW ({req}) > Console FW ({cur}) without fakelib backport."),
                remediation: "Use a backported dump or update console firmware.".into(),
            });
        }
    }
}

fn scan_directory_tree(root: &Path, meta: &mut GameMetadata, findings: &mut Vec<DiagnosticFinding>) {
    let mut stack = vec![root.to_path_buf()];
    let mut seen_rel_paths = HashSet::new();

    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            findings.push(DiagnosticFinding {
                code: "DIR_READ_FAILED",
                category: IssueCategory::DumpStructure,
                severity: ReadinessStatus::Warning,
                message: format!("Unable to read directory: {}", dir.display()),
                remediation: "Check folder read permissions.".into(),
            });
            continue;
        };

        for entry in entries.flatten() {
            let p = entry.path();
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                stack.push(p);
            } else if ft.is_file() {
                meta.total_files += 1;
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                meta.total_bytes += size;

                if size == 0 {
                    meta.zero_byte_files += 1;
                }

                if let Ok(rel) = p.strip_prefix(root) {
                    let rel_str = rel.to_string_lossy().replace('\\', "/");
                    if !seen_rel_paths.insert(rel_str.to_ascii_lowercase()) {
                        findings.push(DiagnosticFinding {
                            code: "CASE_COLLISION",
                            category: IssueCategory::TargetEnvironment,
                            severity: ReadinessStatus::Warning,
                            message: format!("Case-insensitive path collision: {rel_str}"),
                            remediation: "Rename colliding files before transferring to Windows/exFAT.".into(),
                        });
                    }
                    if rel_str.to_ascii_lowercase() == "fakelib/libsceampr.sprx" {
                        meta.has_ampr_runtime = true;
                    }
                }

                let ext = p
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|e| e.to_ascii_lowercase());
                if matches!(ext.as_deref(), Some("zstd") | Some("lz4") | Some("fpack")) {
                    meta.packed_asset_count += 1;
                }
            }
        }
    }
}

pub fn run_preflight_analysis(
    target: &Path,
    console_fw: Option<&str>,
    dest_free_bytes: Option<u64>,
) -> io::Result<PreFlightReport> {
    let mut findings = Vec::new();
    let mut metadata = GameMetadata::default();

    if !target.exists() {
        findings.push(DiagnosticFinding {
            code: "MISSING_SOURCE",
            category: IssueCategory::TargetEnvironment,
            severity: ReadinessStatus::Blocked,
            message: "Source file or folder does not exist.".into(),
            remediation: "Verify the path or reconnect storage.".into(),
        });
        return Ok(PreFlightReport {
            target_path: target.to_path_buf(),
            detected_label: "Not Found".into(),
            package_kind: PackageKind::Unknown,
            status: ReadinessStatus::Blocked,
            metadata,
            findings,
        });
    }

    let detected_label = sniff_magic_label(target)?;
    let ext = target
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase());

    if !target.is_dir() && ext.is_none() {
        findings.push(DiagnosticFinding {
            code: "NO_FILE_EXTENSION",
            category: IssueCategory::FormatAndExtension,
            severity: ReadinessStatus::Warning,
            message: format!("File has no extension; detected by magic bytes as: {detected_label}"),
            remediation: "PS5FileDump processes it directly by real header without renaming.".into(),
        });
    }

    let mut package_kind = if target.is_dir() {
        scan_directory_tree(target, &mut metadata, &mut findings);

        let param_path = target.join("param.json");
        let eboot_path = target.join("eboot.bin");
        metadata.has_fakelib = target.join("fakelib").is_dir();

        if param_path.is_file() {
            if let Ok(raw) = fs::read_to_string(&param_path) {
                if let Ok(parsed) = serde_json::from_str::<ParamJson>(&raw) {
                    metadata.title = parsed.resolved_title();
                    metadata.title_id = parsed.title_id;
                    metadata.content_id = parsed.content_id;
                    metadata.required_fw = parsed.required_fw;
                } else {
                    findings.push(DiagnosticFinding {
                        code: "INVALID_PARAM_JSON",
                        category: IssueCategory::DumpStructure,
                        severity: ReadinessStatus::Blocked,
                        message: "param.json contains invalid JSON syntax.".into(),
                        remediation: "Restore or fix param.json from a clean dump.".into(),
                    });
                }
            }
        } else {
            findings.push(DiagnosticFinding {
                code: "MISSING_PARAM_JSON",
                category: IssueCategory::DumpStructure,
                severity: ReadinessStatus::Blocked,
                message: "param.json is missing from the dump root.".into(),
                remediation: "A valid param.json is required for PS5 launch.".into(),
            });
        }

        let kind = if eboot_path.is_file() {
            if let Ok(mut ef) = File::open(&eboot_path) {
                let mut hdr = [0u8; 32];
                let n = ef.read(&mut hdr).unwrap_or(0);
                metadata.eboot_valid_elf64 = validate_elf64_bytes(&hdr[..n]);
                if !metadata.eboot_valid_elf64 {
                    findings.push(DiagnosticFinding {
                        code: "CORRUPT_EBOOT_BIN",
                        category: IssueCategory::AssetIntegrity,
                        severity: ReadinessStatus::Blocked,
                        message: "eboot.bin header is NOT a valid 64-bit little-endian ELF executable.".into(),
                        remediation: "Re-dump the game; eboot.bin is invalid or still encrypted.".into(),
                    });
                }
            }
            PackageKind::BaseGame
        } else {
            findings.push(DiagnosticFinding {
                code: "NO_EBOOT_BIN",
                category: IssueCategory::DumpStructure,
                severity: ReadinessStatus::Warning,
                message: "eboot.bin not found (likely Update/DLC package, or incomplete base dump).".into(),
                remediation: "If this is Update/DLC, ensure the matching Base Game is installed first.".into(),
            });
            PackageKind::UpdateOrDlc
        };

        evaluate_common_rules(&metadata, console_fw, &mut findings);
        kind
    } else if detected_label == "ZIP Archive" {
        inspect_zip_contents(target, console_fw, &mut metadata, &mut findings)?
    } else {
        metadata.total_files = 1;
        metadata.total_bytes = target.metadata().map(|m| m.len()).unwrap_or(0);
        if metadata.total_bytes == 0 {
            findings.push(DiagnosticFinding {
                code: "EMPTY_FILE",
                category: IssueCategory::AssetIntegrity,
                severity: ReadinessStatus::Blocked,
                message: "Input file is empty (0 bytes).".into(),
                remediation: "Provide a non-empty game dump or archive.".into(),
            });
        } else if metadata.total_bytes <= 256 * 1024 * 1024 {
            if let Ok(hex) = compute_file_sha256(target) {
                metadata.sha256_hex = Some(hex);
            }
        }
        PackageKind::ContainerOrArchive
    };

    if let Some(free) = dest_free_bytes {
        let required_with_margin = metadata.total_bytes.saturating_add(metadata.total_bytes / 10);
        if free < required_with_margin {
            findings.push(DiagnosticFinding {
                code: "INSUFFICIENT_DEST_SPACE",
                category: IssueCategory::TargetEnvironment,
                severity: ReadinessStatus::Blocked,
                message: "Not enough free space at destination for safe conversion and verification.".into(),
                remediation: "Free up disk space on the target drive.".into(),
            });
            if package_kind == PackageKind::Unknown {
                package_kind = PackageKind::ContainerOrArchive;
            }
        }
    }

    let status = if findings.iter().any(|f| f.severity == ReadinessStatus::Blocked) {
        ReadinessStatus::Blocked
    } else if findings.iter().any(|f| f.severity == ReadinessStatus::Warning) {
        ReadinessStatus::Warning
    } else {
        ReadinessStatus::Ready
    };

    Ok(PreFlightReport {
        target_path: target.to_path_buf(),
        detected_label,
        package_kind,
        status,
        metadata,
        findings,
    })
}
