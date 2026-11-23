use crate::analyzer::{run_preflight_analysis, ReadinessStatus};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Component, Path, PathBuf};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamFormat {
    Folder,
    Zip,
    Pkg,
    ExFat,
    Ffpkg,
    Ffpfs,
    Ffpfsc,
    SevenZip,
    Rar,
    GzArchive,
    CustomRaw,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionProfile {
    Fast,
    Balanced,
    Smallest,
    Stored,
}

impl StreamFormat {
    pub fn from_extension(ext: Option<&str>) -> Self {
        match ext.map(|s| s.to_ascii_lowercase()).as_deref() {
            Some("zip") => Self::Zip,
            Some("pkg") => Self::Pkg,
            Some("exfat") => Self::ExFat,
            Some("ffpkg") => Self::Ffpkg,
            Some("ffpfs") => Self::Ffpfs,
            Some("ffpfsc") => Self::Ffpfsc,
            Some("7z") => Self::SevenZip,
            Some("rar") => Self::Rar,
            Some("gz") | Some("tgz") => Self::GzArchive,
            _ => Self::CustomRaw,
        }
    }

    pub fn detect_from_path(path: &Path) -> io::Result<Self> {
        if path.is_dir() {
            return Ok(Self::Folder);
        }
        let mut f = File::open(path)?;
        let mut buf = [0u8; 16];
        let n = f.read(&mut buf)?;
        let s = &buf[..n];

        let fmt = if s.starts_with(b"PK\x03\x04") || s.starts_with(b"PK\x05\x06") {
            Self::Zip
        } else if s.starts_with(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
            Self::SevenZip
        } else if s.starts_with(b"Rar!\x1A\x07") {
            Self::Rar
        } else if s.starts_with(b"CNT\x00") || s.starts_with(b"FPKG") {
            Self::Pkg
        } else if s.starts_with(b"FFPKG") {
            Self::Ffpkg
        } else if s.starts_with(b"FFPFS") && n >= 6 && s[5] == b'C' {
            Self::Ffpfsc
        } else if s.starts_with(b"FFPFS") {
            Self::Ffpfs
        } else if n >= 11 && &s[3..11] == b"EXFAT   " {
            Self::ExFat
        } else if n >= 2 && s[0] == 0x1F && s[1] == 0x8B {
            Self::GzArchive
        } else {
            let ext = path.extension().and_then(|e| e.to_str());
            Self::from_extension(ext)
        };
        Ok(fmt)
    }

    pub fn is_supported_output(self) -> bool {
        matches!(self, Self::Folder | Self::Zip | Self::GzArchive)
    }
}

#[derive(Debug, Clone)]
pub struct ConversionPlan {
    pub source: PathBuf,
    pub output: PathBuf,
    pub source_format: StreamFormat,
    pub target_format: StreamFormat,
    pub profile: CompressionProfile,
    pub ffpfsc_level: i32,
    pub buffer_bytes: usize,
    pub preserve_metadata: bool,
}

#[derive(Debug, Clone)]
pub struct ConversionResult {
    pub source_format: StreamFormat,
    pub target_format: StreamFormat,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub files_processed: usize,
    pub metadata_preserved: bool,
    pub verified: bool,
}

fn sanitize_archive_rel_path(name: &str) -> Option<PathBuf> {
    let mut clean = PathBuf::new();
    for comp in Path::new(name).components() {
        match comp {
            Component::Normal(p) => clean.push(p),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    if clean.as_os_str().is_empty() {
        None
    } else {
        Some(clean)
    }
}

pub fn prepare_conversion_plan(
    source: &Path,
    output: &Path,
    target_format_override: Option<StreamFormat>,
    profile: CompressionProfile,
    ffpfsc_level: i32,
    buffer_bytes: usize,
) -> io::Result<ConversionPlan> {
    if !source.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Source path does not exist.",
        ));
    }

    let source_format = StreamFormat::detect_from_path(source)?;
    let target_format = target_format_override.unwrap_or_else(|| {
        if output.is_dir() {
            StreamFormat::Folder
        } else {
            StreamFormat::from_extension(output.extension().and_then(|e| e.to_str()))
        }
    });

    if !target_format.is_supported_output() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "Target format {:?} is not supported for native binary generation. Use Folder or ZIP.",
                target_format
            ),
        ));
    }

    let preserve_metadata = source.is_dir()
        && (source.join("param.json").is_file() || source.join("eboot.bin").is_file());

    Ok(ConversionPlan {
        source: source.to_path_buf(),
        output: output.to_path_buf(),
        source_format,
        target_format,
        profile,
        ffpfsc_level: ffpfsc_level.clamp(0, 9),
        buffer_bytes: buffer_bytes.max(64 * 1024),
        preserve_metadata,
    })
}

fn copy_folder_clean(
    src_dir: &Path,
    dst_dir: &Path,
    buf_size: usize,
) -> io::Result<(u64, usize)> {
    fs::create_dir_all(dst_dir)?;
    let mut copied_bytes: u64 = 0;
    let mut count: usize = 0;
    let mut stack = vec![src_dir.to_path_buf()];
    let mut buf = vec![0u8; buf_size];

    while let Some(d) = stack.pop() {
        let mut entries: Vec<_> = fs::read_dir(&d)?.flatten().collect();
        entries.sort_by_key(|e| e.path());

        for entry in entries {
            let p = entry.path();
            let rel = p.strip_prefix(src_dir).unwrap_or(&p);
            let dst_p = dst_dir.join(rel);

            if p.is_dir() {
                fs::create_dir_all(&dst_p)?;
                stack.push(p);
            } else if p.is_file() {
                if let Some(parent) = dst_p.parent() {
                    fs::create_dir_all(parent)?;
                }
                let src_f = File::open(&p)?;
                let expected_len = src_f.metadata()?.len();
                let mut r = BufReader::with_capacity(buf_size, src_f);
                let out_f = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&dst_p)?;
                let mut w = BufWriter::with_capacity(buf_size, out_f);

                let mut file_copied: u64 = 0;
                loop {
                    let n = r.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    w.write_all(&buf[..n])?;
                    file_copied += n as u64;
                }
                w.flush()?;

                if file_copied != expected_len {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Byte count mismatch while copying {}", rel.display()),
                    ));
                }

                copied_bytes += file_copied;
                count += 1;
            }
        }
    }

    Ok((copied_bytes, count))
}

fn extract_zip_to_folder(
    zip_path: &Path,
    out_folder: &Path,
    buf_size: usize,
) -> io::Result<(u64, u64, usize)> {
    fs::create_dir_all(out_folder)?;
    let f = File::open(zip_path)?;
    let zip_len = f.metadata()?.len();
    let mut archive = ZipArchive::new(f)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Invalid ZIP: {e}")))?;

    let mut total_written: u64 = 0;
    let mut extracted_files: usize = 0;
    let mut buf = vec![0u8; buf_size];

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        let Some(safe_rel) = sanitize_archive_rel_path(entry.name()) else {
            continue;
        };
        let dest = out_folder.join(&safe_rel);

        if entry.is_dir() {
            fs::create_dir_all(&dest)?;
            continue;
        }

        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }

        let expected_uncompressed = entry.size();
        let out_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&dest)?;
        let mut writer = BufWriter::with_capacity(buf_size, out_file);

        let mut entry_written: u64 = 0;
        loop {
            let n = entry.read(&mut buf)?;
            if n == 0 {
                break;
            }
            writer.write_all(&buf[..n])?;
            entry_written += n as u64;
        }
        writer.flush()?;

        if entry_written != expected_uncompressed {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Corrupt ZIP entry size for {}", safe_rel.display()),
            ));
        }

        total_written += entry_written;
        extracted_files += 1;
    }

    if extracted_files == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ZIP archive contained no extractable files.",
        ));
    }

    Ok((zip_len, total_written, extracted_files))
}

fn pack_folder_to_zip_part(
    src_dir: &Path,
    part_path: &Path,
    profile: CompressionProfile,
    buf_size: usize,
) -> io::Result<(u64, u64, usize)> {
    let out_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(part_path)?;
    let bw = BufWriter::with_capacity(buf_size, out_file);
    let mut zip = ZipWriter::new(bw);

    let (method, level) = match profile {
        CompressionProfile::Stored => (CompressionMethod::Stored, None),
        CompressionProfile::Fast => (CompressionMethod::Deflated, Some(1)),
        CompressionProfile::Balanced => (CompressionMethod::Deflated, Some(6)),
        CompressionProfile::Smallest => (CompressionMethod::Deflated, Some(9)),
    };

    let options = SimpleFileOptions::default()
        .compression_method(method)
        .compression_level(level)
        .large_file(true)
        .unix_permissions(0o755);

    let mut files_list: Vec<PathBuf> = Vec::new();
    let mut stack = vec![src_dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in fs::read_dir(&d)?.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.is_file() {
                files_list.push(p);
            }
        }
    }
    files_list.sort();

    if files_list.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Source directory is empty; nothing to archive.",
        ));
    }

    let mut total_read: u64 = 0;
    let mut count: usize = 0;
    let mut buf = vec![0u8; buf_size];

    for file_path in files_list {
        let rel = file_path
            .strip_prefix(src_dir)
            .unwrap_or(&file_path)
            .to_string_lossy()
            .replace('\\', "/");

        zip.start_file(rel, options)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let f = File::open(&file_path)?;
        let mut r = BufReader::with_capacity(buf_size, f);
        loop {
            let n = r.read(&mut buf)?;
            if n == 0 {
                break;
            }
            zip.write_all(&buf[..n])?;
            total_read += n as u64;
        }
        count += 1;
    }

    let mut bw_done = zip
        .finish()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    bw_done.flush()?;
    let zip_final_size = bw_done.get_ref().metadata()?.len();
    Ok((total_read, zip_final_size, count))
}

fn stream_file_to_part(
    src_file: &Path,
    part_path: &Path,
    target_fmt: StreamFormat,
    buf_size: usize,
) -> io::Result<(u64, u64, usize)> {
    let input = File::open(src_file)?;
    let mut reader = BufReader::with_capacity(buf_size, input);

    let out = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(part_path)?;
    let mut bw = BufWriter::with_capacity(buf_size, out);

    let mut buf = vec![0u8; buf_size];
    let mut read_total: u64 = 0;

    match target_fmt {
        StreamFormat::GzArchive => {
            let mut enc = GzEncoder::new(bw, Compression::fast());
            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                enc.write_all(&buf[..n])?;
                read_total += n as u64;
            }
            let mut inner = enc.finish()?;
            inner.flush()?;
            let written = inner.get_ref().metadata()?.len();
            Ok((read_total, written, 1))
        }
        StreamFormat::Zip => {
            let mut zip = ZipWriter::new(bw);
            let options = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Deflated)
                .compression_level(Some(6))
                .large_file(true);
            let entry_name = src_file
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("dump.bin");
            zip.start_file(entry_name, options)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                zip.write_all(&buf[..n])?;
                read_total += n as u64;
            }
            let mut inner = zip
                .finish()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            inner.flush()?;
            let written = inner.get_ref().metadata()?.len();
            Ok((read_total, written, 1))
        }
        _ => {
            bw.flush()?;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("Direct file conversion to {:?} is not supported.", target_fmt),
            ))
        }
    }
}

pub fn execute_stream_conversion(
    plan: &ConversionPlan,
    console_fw: Option<&str>,
) -> io::Result<ConversionResult> {
    if !plan.target_format.is_supported_output() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "Target format {:?} is not supported. Choose Folder or ZIP.",
                plan.target_format
            ),
        ));
    }

    let report = run_preflight_analysis(&plan.source, console_fw, None)?;
    if report.status == ReadinessStatus::Blocked {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Source failed PS5 pre-flight checks (Blocked). Fix reported issues first.",
        ));
    }

    if plan.target_format == StreamFormat::Folder {
        if plan.source.is_dir() {
            let (copied_bytes, count) =
                copy_folder_clean(&plan.source, &plan.output, plan.buffer_bytes)?;
            return Ok(ConversionResult {
                source_format: plan.source_format,
                target_format: plan.target_format,
                bytes_read: report.metadata.total_bytes,
                bytes_written: copied_bytes,
                files_processed: count,
                metadata_preserved: plan.preserve_metadata,
                verified: copied_bytes == report.metadata.total_bytes,
            });
        } else if plan.source_format == StreamFormat::Zip {
            let (read_b, written_b, count) =
                extract_zip_to_folder(&plan.source, &plan.output, plan.buffer_bytes)?;
            return Ok(ConversionResult {
                source_format: plan.source_format,
                target_format: plan.target_format,
                bytes_read: read_b,
                bytes_written: written_b,
                files_processed: count,
                metadata_preserved: true,
                verified: count > 0,
            });
        } else if plan.source_format == StreamFormat::GzArchive {
            fs::create_dir_all(&plan.output)?;
            let stem = plan
                .source
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unpacked_stream.bin");
            let out_file = plan.output.join(stem);
            let dec = GzDecoder::new(BufReader::with_capacity(
                plan.buffer_bytes,
                File::open(&plan.source)?,
            ));
            let mut r = BufReader::with_capacity(plan.buffer_bytes, dec);
            let mut w = BufWriter::with_capacity(
                plan.buffer_bytes,
                OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&out_file)?,
            );
            let mut buf = vec![0u8; plan.buffer_bytes];
            let mut written: u64 = 0;
            loop {
                let n = r.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                w.write_all(&buf[..n])?;
                written += n as u64;
            }
            w.flush()?;
            return Ok(ConversionResult {
                source_format: plan.source_format,
                target_format: plan.target_format,
                bytes_read: report.metadata.total_bytes,
                bytes_written: written,
                files_processed: 1,
                metadata_preserved: false,
                verified: written > 0,
            });
        } else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "Extraction from {:?} to Folder is not natively supported yet (supported inputs: Folder, ZIP, GZ).",
                    plan.source_format
                ),
            ));
        }
    }

    let mut part_path = plan.output.clone();
    let mut part_name = part_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    part_name.push_str(".part");
    part_path.set_file_name(part_name);

    if let Some(parent) = part_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    let res = (|| -> io::Result<(u64, u64, usize)> {
        if plan.source.is_dir() && plan.target_format == StreamFormat::Zip {
            pack_folder_to_zip_part(&plan.source, &part_path, plan.profile, plan.buffer_bytes)
        } else if plan.source.is_file() {
            stream_file_to_part(
                &plan.source,
                &part_path,
                plan.target_format,
                plan.buffer_bytes,
            )
        } else {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "Converting {:?} to {:?} is not supported.",
                    plan.source_format, plan.target_format
                ),
            ))
        }
    })();

    match res {
        Ok((read_b, written_b, count)) => {
            let actual_size = fs::metadata(&part_path)?.len();
            if actual_size != written_b {
                let _ = fs::remove_file(&part_path);
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Output size verification failed on .part file.",
                ));
            }
            if plan.output.exists() {
                fs::remove_file(&plan.output)?;
            }
            fs::rename(&part_path, &plan.output)?;
            Ok(ConversionResult {
                source_format: plan.source_format,
                target_format: plan.target_format,
                bytes_read: read_b,
                bytes_written: actual_size,
                files_processed: count,
                metadata_preserved: plan.preserve_metadata,
                verified: true,
            })
        }
        Err(e) => {
            let _ = fs::remove_file(&part_path);
            Err(e)
        }
    }
}
