use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetCodec {
    Zstd,
    Lz4,
}

#[derive(Debug, Clone)]
pub struct PackStats {
    pub codec: AssetCodec,
    pub files_packed: usize,
    pub original_bytes: u64,
    pub compressed_bytes: u64,
    pub has_ampr_sprx: bool,
}

pub fn pack_game_assets(
    game_dir: &Path,
    output_dir: &Path,
    codec: AssetCodec,
    zstd_level: i32,
) -> io::Result<PackStats> {
    if !game_dir.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Game directory does not exist.",
        ));
    }

    fs::create_dir_all(output_dir)?;

    let mut files: Vec<PathBuf> = Vec::new();
    let mut stack = vec![game_dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in fs::read_dir(&d)?.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.is_file() {
                files.push(p);
            }
        }
    }
    files.sort();

    let mut index_records: Vec<serde_json::Value> = Vec::new();
    let mut files_packed = 0usize;
    let mut original_bytes = 0u64;
    let mut compressed_bytes = 0u64;

    for src_path in files {
        let rel = src_path
            .strip_prefix(game_dir)
            .unwrap_or(&src_path)
            .to_string_lossy()
            .replace('\\', "/");
        let lower = rel.to_ascii_lowercase();

        let keep_raw = lower == "eboot.bin"
            || lower == "param.json"
            || lower.starts_with("sce_sys/")
            || lower.starts_with("fakelib/");

        let dst_path = output_dir.join(&rel);
        if let Some(parent) = dst_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let src_len = src_path.metadata()?.len();
        original_bytes += src_len;

        if keep_raw || src_len < 4096 {
            fs::copy(&src_path, &dst_path)?;
            compressed_bytes += src_len;
        } else {
            let mut raw = Vec::with_capacity(src_len as usize);
            BufReader::new(File::open(&src_path)?).read_to_end(&mut raw)?;

            let (packed_data, ext_suffix) = match codec {
                AssetCodec::Zstd => {
                    let encoded = zstd::stream::encode_all(raw.as_slice(), zstd_level.clamp(1, 19))
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                    (encoded, "zstd")
                }
                AssetCodec::Lz4 => {
                    let encoded = lz4_flex::compress_prepend_size(&raw);
                    (encoded, "lz4")
                }
            };

            let mut packed_file_path = dst_path.clone();
            let new_name = format!(
                "{}.{}",
                dst_path.file_name().and_then(|s| s.to_str()).unwrap_or("asset"),
                ext_suffix
            );
            packed_file_path.set_file_name(new_name);

            let mut w = BufWriter::new(
                OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&packed_file_path)?,
            );
            w.write_all(&packed_data)?;
            w.flush()?;

            let comp_len = packed_data.len() as u64;
            compressed_bytes += comp_len;
            files_packed += 1;

            index_records.push(serde_json::json!({
                "path": rel,
                "codec": ext_suffix,
                "orig_size": src_len,
                "packed_size": comp_len,
                "slot_align": 8
            }));
        }
    }

    let mut index_bytes = serde_json::to_vec_pretty(&serde_json::json!({
        "magic": "AMPR_IDX_V1",
        "slot_alignment": 8,
        "entries": index_records
    }))
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    while index_bytes.len() % 8 != 0 {
        index_bytes.push(b' ');
    }
    fs::write(output_dir.join("ampr_emu.index"), &index_bytes)?;

    let has_ampr_sprx = output_dir.join("fakelib/libSceAmpr.sprx").is_file();
    Ok(PackStats {
        codec,
        files_packed,
        original_bytes,
        compressed_bytes,
        has_ampr_sprx,
    })
}

pub fn unpack_game_assets(packed_dir: &Path, output_dir: &Path) -> io::Result<usize> {
    if !packed_dir.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Packed game directory does not exist.",
        ));
    }
    fs::create_dir_all(output_dir)?;

    let mut unpacked_count = 0usize;
    let mut stack = vec![packed_dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in fs::read_dir(&d)?.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.is_file() {
                let rel = p.strip_prefix(packed_dir).unwrap_or(&p);
                let rel_str = rel.to_string_lossy().replace('\\', "/");
                if rel_str == "ampr_emu.index" {
                    continue;
                }

                let ext = p.extension().and_then(|e| e.to_str()).map(|s| s.to_ascii_lowercase());
                if matches!(ext.as_deref(), Some("zstd") | Some("lz4")) {
                    let mut comp_bytes = Vec::new();
                    BufReader::new(File::open(&p)?).read_to_end(&mut comp_bytes)?;

                    let raw = if ext.as_deref() == Some("zstd") {
                        zstd::stream::decode_all(comp_bytes.as_slice())
                            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
                    } else {
                        lz4_flex::decompress_size_prepended(&comp_bytes)
                            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
                    };

                    let mut out_p = output_dir.join(rel);
                    out_p.set_extension("");
                    if let Some(parent) = out_p.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    fs::write(&out_p, &raw)?;
                    unpacked_count += 1;
                } else {
                    let out_p = output_dir.join(rel);
                    if let Some(parent) = out_p.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    fs::copy(&p, &out_p)?;
                }
            }
        }
    }

    Ok(unpacked_count)
}
