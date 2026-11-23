use crate::analyzer::{run_preflight_analysis, ReadinessStatus};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
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

    pub fn magic_header(self) -> Option<&'static [u8]> {
        match self {
            Self::Pkg => Some(b"FPKG\x00\x01\x00\x00"),
            Self::ExFat => Some(b"\xEB\x52\x90EXFAT   \x00"),
            Self::Ffpkg => Some(b"FFPKG\x00\x01\x00"),
            Self::Ffpfs => Some(b"FFPFS\x00\x01\x00"),
            Self::Ffpfsc => Some(b"FFPFSC\x01\x00"),
            _ => None,
        }
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
            "Source path does not exist for streaming conversion.",
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

        let out_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&dest)?;
        let mut writer = BufWriter::with_capacity(buf_size, out_file);

        loop {
            let n = entry.read(&mut buf)?;
            if n == 0 {
                break;
            }
            writer.write_all(&buf[..n])?;
            total_written += n as u64;
        }
        writer.flush()?;
        extracted_files += 1;
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

fn write_manifest_header<W: Write>(
    writer: &mut W,
    source: &Path,
    target_fmt: StreamFormat,
    payload_len: u64,
    metadata_preserved: bool,
) -> io::Result<u64> {
    let mut header_written: u64 = 0;
    if let Some(magic) = target_fmt.magic_header() {
        writer.write_all(magic)?;
        header_written += magic.len() as u64;
    }

    let has_param = source.join("param.json").is_file();
    let manifest = serde_json::json!({
        "engine": "PS5FileDump-StreamConverter",
        "source_name": source.file_name().and_then(|s| s.to_str()).unwrap_or("dump"),
        "target_format": format!("{:?}", target_fmt),
        "payload_bytes": payload_len,
        "metadata_preserved": metadata_preserved,
        "has_param_json": has_param,
    });
    let mut line = serde_json::to_vec(&manifest)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    line.push(b'\n');

    let len_bytes = (line.len() as u32).to_le_bytes();
    writer.write_all(&len_bytes)?;
    writer.write_all(&line)?;
    header_written += (len_bytes.len() + line.len()) as u64;
    Ok(header_written)
}

fn stream_file_to_part(
    src_file: &Path,
    part_path: &Path,
    target_fmt: StreamFormat,
    buf_size: usize,
) -> io::Result<(u64, u64, usize)> {
    let input = File::open(src_file)?;
    let src_len = input.metadata()?.len();
    let mut reader = BufReader::with_capacity(buf_size, input);

    let out = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(part_path)?;
    let mut bw = BufWriter::with_capacity(buf_size, out);

    let mut written: u64 = 0;
    if matches!(
        target_fmt,
        StreamFormat::Pkg
            | StreamFormat::ExFat
            | StreamFormat::Ffpkg
            | StreamFormat::Ffpfs
            | StreamFormat::Ffpfsc
    ) {
        written += write_manifest_header(&mut bw, src_file, target_fmt, src_len, false)?;
    }

    let mut buf = vec![0u8; buf_size];
    let mut read_total: u64 = 0;

    if target_fmt == StreamFormat::GzArchive {
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
        written = inner.get_ref().metadata()?.len();
    } else {
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            bw.write_all(&buf[..n])?;
            read_total += n as u64;
            written += n as u64;
        }
        bw.flush()?;
        bw.get_ref().sync_all()?;
    }

    Ok((read_total, written, 1))
}

fn stream_folder_to_container_part(
    src_dir: &Path,
    part_path: &Path,
    target_fmt: StreamFormat,
    buf_size: usize,
) -> io::Result<(u64, u64, usize)> {
    let mut files_list: Vec<PathBuf> = Vec::new();
    let mut stack = vec![src_dir.to_path_buf()];
    let mut total_src_bytes: u64 = 0;

    while let Some(d) = stack.pop() {
        for entry in fs::read_dir(&d)?.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.is_file() {
                total_src_bytes += p.metadata().map(|m| m.len()).unwrap_or(0);
                files_list.push(p);
            }
        }
    }
    files_list.sort();

    let out = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(part_path)?;
    let mut bw = BufWriter::with_capacity(buf_size, out);
    let mut written: u64 = 0;

    written += write_manifest_header(&mut bw, src_dir, target_fmt, total_src_bytes, true)?;

    let mut buf = vec![0u8; buf_size];
    let file_count = files_list.len();

    for file_path in files_list {
        let rel = file_path
            .strip_prefix(src_dir)
            .unwrap_or(&file_path)
            .to_string_lossy()
            .replace('\\', "/");
        let f = File::open(&file_path)?;
        let f_len = f.metadata()?.len();
        let mut r = BufReader::with_capacity(buf_size, f);

        let entry_meta = serde_json::json!({
            "path": rel,
            "size": f_len,
        });
        let mut meta_bytes = serde_json::to_vec(&entry_meta)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        meta_bytes.push(b'\n');
        bw.write_all(&(meta_bytes.len() as u32).to_le_bytes())?;
        bw.write_all(&meta_bytes)?;
        written += (4 + meta_bytes.len()) as u64;

        loop {
            let n = r.read(&mut buf)?;
            if n == 0 {
                break;
            }
            bw.write_all(&buf[..n])?;
            written += n as u64;
        }
    }

    bw.flush()?;
    bw.get_ref().sync_all()?;
    Ok((total_src_bytes, written, file_count))
}

fn unpack_container_to_folder(
    container_file: &Path,
    out_folder: &Path,
    buf_size: usize,
) -> io::Result<(u64, u64, usize)> {
    fs::create_dir_all(out_folder)?;
    let f = File::open(container_file)?;
    let file_len = f.metadata()?.len();
    let mut r = BufReader::with_capacity(buf_size, f);

    let mut magic = [0u8; 8];
    r.read_exact(&mut magic)?;

    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let manifest_len = u32::from_le_bytes(len_buf) as usize;
    let mut manifest_raw = vec![0u8; manifest_len];
    r.read_exact(&mut manifest_raw)?;

    let mut total_written: u64 = 0;
    let mut files_count: usize = 0;
    let mut buf = vec![0u8; buf_size];

    loop {
        let mut entry_len_buf = [0u8; 4];
        match r.read_exact(&mut entry_len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }

        let meta_sz = u32::from_le_bytes(entry_len_buf) as usize;
        if meta_sz == 0 || meta_sz > 64 * 1024 {
            break;
        }
        let mut meta_buf = vec![0u8; meta_sz];
        r.read_exact(&mut meta_buf)?;
        let val: serde_json::Value = serde_json::from_slice(&meta_buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        let rel_path = val["path"].as_str().unwrap_or("extracted.bin");
        let entry_size = val["size"].as_u64().unwrap_or(0);

        let Some(safe_rel) = sanitize_archive_rel_path(rel_path) else {
            continue;
        };
        let target_file = out_folder.join(safe_rel);
        if let Some(parent) = target_file.parent() {
            fs::create_dir_all(parent)?;
        }

        let out_f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&target_file)?;
        let mut w = BufWriter::with_capacity(buf_size, out_f);

        let mut remaining = entry_size;
        while remaining > 0 {
            let to_read = (remaining as usize).min(buf.len());
            let n = r.read(&mut buf[..to_read])?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Unexpected EOF while streaming entry payload.",
                ));
            }
            w.write_all(&buf[..n])?;
            remaining -= n as u64;
            total_written += n as u64;
        }
        w.flush()?;
        files_count += 1;
    }

    if total_written == 0 && file_len > 12 {
        let mut raw_f = File::open(container_file)?;
        raw_f.seek(SeekFrom::Start(0))?;
        let mut raw_r = BufReader::with_capacity(buf_size, raw_f);
        let fallback_out = out_folder.join("extracted_dump.bin");
        let out_f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&fallback_out)?;
        let mut w = BufWriter::with_capacity(buf_size, out_f);
        loop {
            let n = raw_r.read(&mut buf)?;
            if n == 0 {
                break;
            }
            w.write_all(&buf[..n])?;
            total_written += n as u64;
        }
        w.flush()?;
        files_count = 1;
    }

    Ok((file_len, total_written, files_count))
}

pub fn execute_stream_conversion(
    plan: &ConversionPlan,
    console_fw: Option<&str>,
) -> io::Result<ConversionResult> {
    let report = run_preflight_analysis(&plan.source, console_fw, None)?;
    if report.status == ReadinessStatus::Blocked {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Source failed PS5 pre-flight checks (Blocked). Fix reported issues first.",
        ));
    }

    if plan.target_format == StreamFormat::Folder {
        if plan.source.is_dir() {
            fs::create_dir_all(&plan.output)?;
            let mut copied_bytes: u64 = 0;
            let mut count: usize = 0;
            let mut stack = vec![plan.source.clone()];
            let mut buf = vec![0u8; plan.buffer_bytes];

            while let Some(d) = stack.pop() {
                for entry in fs::read_dir(&d)?.flatten() {
                    let p = entry.path();
                    let rel = p.strip_prefix(&plan.source).unwrap_or(&p);
                    let dst_p = plan.output.join(rel);
                    if p.is_dir() {
                        fs::create_dir_all(&dst_p)?;
                        stack.push(p);
                    } else if p.is_file() {
                        if let Some(parent) = dst_p.parent() {
                            fs::create_dir_all(parent)?;
                        }
                        let mut r = BufReader::with_capacity(plan.buffer_bytes, File::open(&p)?);
                        let mut w = BufWriter::with_capacity(
                            plan.buffer_bytes,
                            OpenOptions::new()
                                .create(true)
                                .write(true)
                                .truncate(true)
                                .open(&dst_p)?,
                        );
                        loop {
                            let n = r.read(&mut buf)?;
                            if n == 0 {
                                break;
                            }
                            w.write_all(&buf[..n])?;
                            copied_bytes += n as u64;
                        }
                        w.flush()?;
                        count += 1;
                    }
                }
            }

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
            let out_file = plan.output.join("unpacked_stream.bin");
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
            let (read_b, written_b, count) =
                unpack_container_to_folder(&plan.source, &plan.output, plan.buffer_bytes)?;
            return Ok(ConversionResult {
                source_format: plan.source_format,
                target_format: plan.target_format,
                bytes_read: read_b,
                bytes_written: written_b,
                files_processed: count,
                metadata_preserved: false,
                verified: written_b > 0,
            });
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
        } else if plan.source.is_dir() {
            stream_folder_to_container_part(
                &plan.source,
                &part_path,
                plan.target_format,
                plan.buffer_bytes,
            )
        } else {
            stream_file_to_part(
                &plan.source,
                &part_path,
                plan.target_format,
                plan.buffer_bytes,
            )
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
