use crate::analyzer::{run_preflight_analysis, ReadinessStatus};
use crate::converter::{
    execute_stream_conversion, prepare_conversion_plan, CompressionProfile, StreamFormat,
};
use crate::editor::{DumpEditorSession, EditOperation};
use crate::library::scan_library_folder;
use crate::net::{
    ensure_endpoint_ready, ConnectManager, EndpointHealth, NetworkEndpoint, RemoteProtocol,
};
use crate::packer::{pack_game_assets, unpack_game_assets, AssetCodec};
use crate::queue_engine::{JobPriority, JobState, StreamQueueEngine, TransferJob};
use std::fs::{self, File};
use std::io::Write;
use std::net::TcpListener;
use std::path::PathBuf;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ps5filedump_win_{prefix}_{nanos}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn valid_elf64_stub() -> Vec<u8> {
    let mut b = vec![0u8; 64];
    b[0..4].copy_from_slice(b"\x7FELF");
    b[4] = 2;
    b[5] = 1;
    b
}

#[test]
fn detects_pkg_header_even_without_extension() {
    let dir = unique_temp_dir("no_ext_pkg");
    let file_path = dir.join("custom_dump_file");
    let mut f = File::create(&file_path).unwrap();
    f.write_all(b"FPKG\x00\x01\x02\x03rest_of_header").unwrap();

    let report = run_preflight_analysis(&file_path, None, None).unwrap();
    assert_eq!(report.detected_label, "PS5 FPKG (.pkg)");
    assert_eq!(report.status, ReadinessStatus::Warning);
    assert!(report.findings.iter().any(|f| f.code == "NO_FILE_EXTENSION"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn packs_folder_to_real_zip_inspects_zip_and_extracts_back() {
    let dir = unique_temp_dir("real_zip_roundtrip");
    let src_folder = dir.join("PPSA07777");
    fs::create_dir_all(src_folder.join("sce_sys")).unwrap();
    fs::write(
        src_folder.join("param.json"),
        r#"{"title":"Real Zip Game","titleId":"PPSA07777","requiredSystemSoftwareVersion":"7.00"}"#,
    )
    .unwrap();
    fs::write(src_folder.join("eboot.bin"), valid_elf64_stub()).unwrap();
    fs::write(src_folder.join("sce_sys/icon0.png"), vec![0x89u8; 512]).unwrap();

    let zip_out = dir.join("game_bundle.zip");
    let plan = prepare_conversion_plan(
        &src_folder,
        &zip_out,
        Some(StreamFormat::Zip),
        CompressionProfile::Balanced,
        6,
        64 * 1024,
    )
    .unwrap();
    let res = execute_stream_conversion(&plan, Some("8.00")).unwrap();
    assert!(res.verified);
    assert_eq!(res.files_processed, 3);

    let zip_report = run_preflight_analysis(&zip_out, Some("8.00"), None).unwrap();
    assert_eq!(zip_report.detected_label, "ZIP Archive");
    assert_eq!(zip_report.status, ReadinessStatus::Ready);
    assert!(zip_report.metadata.eboot_valid_elf64);

    let extracted_dir = dir.join("extracted_game");
    let ext_plan = prepare_conversion_plan(
        &zip_out,
        &extracted_dir,
        Some(StreamFormat::Folder),
        CompressionProfile::Balanced,
        6,
        64 * 1024,
    )
    .unwrap();
    let ext_res = execute_stream_conversion(&ext_plan, Some("8.00")).unwrap();
    assert!(ext_res.verified);
    assert!(extracted_dir.join("eboot.bin").is_file());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn packs_and_unpacks_zstd_and_lz4_assets_with_index() {
    let dir = unique_temp_dir("zstd_lz4_pack");
    let src_folder = dir.join("PPSA09999");
    fs::create_dir_all(src_folder.join("fakelib")).unwrap();
    fs::write(src_folder.join("eboot.bin"), valid_elf64_stub()).unwrap();
    fs::write(src_folder.join("fakelib/libSceAmpr.sprx"), b"SPRX_STUB").unwrap();
    fs::write(src_folder.join("level0.pak"), vec![0x42u8; 16 * 1024]).unwrap();

    let zstd_out = dir.join("packed_zstd");
    let stats = pack_game_assets(&src_folder, &zstd_out, AssetCodec::Zstd, 3).unwrap();
    assert_eq!(stats.files_packed, 1);
    assert!(stats.has_ampr_sprx);
    assert!(zstd_out.join("ampr_emu.index").is_file());
    assert!(zstd_out.join("level0.pak.zstd").is_file());

    let unpacked_out = dir.join("unpacked_zstd");
    let count = unpack_game_assets(&zstd_out, &unpacked_out).unwrap();
    assert_eq!(count, 1);
    assert_eq!(fs::metadata(unpacked_out.join("level0.pak")).unwrap().len(), 16 * 1024);

    let lz4_out = dir.join("packed_lz4");
    let lz4_stats = pack_game_assets(&src_folder, &lz4_out, AssetCodec::Lz4, 1).unwrap();
    assert_eq!(lz4_stats.files_packed, 1);
    assert!(lz4_out.join("level0.pak.lz4").is_file());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn editor_stages_undo_and_applies_dump_changes() {
    let dir = unique_temp_dir("dump_editor");
    let game_dir = dir.join("PPSA03333");
    fs::create_dir_all(&game_dir).unwrap();
    fs::write(game_dir.join("old_name.txt"), b"hello").unwrap();
    fs::write(game_dir.join("delete_me.txt"), b"temp").unwrap();

    let mut editor = DumpEditorSession::default();
    editor.load_folder(&game_dir).unwrap();
    editor.stage_op(EditOperation::Rename {
        from_rel: "old_name.txt".into(),
        to_rel: "new_name.txt".into(),
    });
    editor.stage_op(EditOperation::Delete {
        rel_path: "delete_me.txt".into(),
    });
    assert!(editor.undo_last());
    let applied = editor.apply_changes().unwrap();
    assert_eq!(applied, 1);
    assert!(game_dir.join("new_name.txt").is_file());
    assert!(game_dir.join("delete_me.txt").is_file());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn streams_file_atomically_and_cleans_part_on_missing_source() {
    let dir = unique_temp_dir("stream_atomic");
    let src = dir.join("input.bin");
    let dst = dir.join("output.bin");
    let part = dir.join("output.bin.part");

    fs::write(&src, vec![0xABu8; 256 * 1024]).unwrap();

    let engine = StreamQueueEngine::new(2);
    engine.enqueue(TransferJob {
        id: 1,
        priority: JobPriority::High,
        source: src.clone(),
        final_output: dst.clone(),
        max_retries: 1,
        buffer_bytes: 64 * 1024,
        verify_size: true,
    });
    engine.enqueue(TransferJob {
        id: 2,
        priority: JobPriority::Low,
        source: dir.join("does_not_exist.bin"),
        final_output: dir.join("failed_out.bin"),
        max_retries: 1,
        buffer_bytes: 64 * 1024,
        verify_size: true,
    });

    engine.run_all();

    assert!(dst.is_file());
    assert!(!part.exists());
    assert_eq!(fs::metadata(&dst).unwrap().len(), 256 * 1024);

    let snaps = engine.snapshots();
    assert!(matches!(
        snaps.iter().find(|s| s.id == 1).unwrap().state,
        JobState::Completed
    ));
    assert!(matches!(
        snaps.iter().find(|s| s.id == 2).unwrap().state,
        JobState::Failed { .. }
    ));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn scans_mixed_library_and_skips_part_files() {
    let root = unique_temp_dir("mixed_lib");

    let ready_game = root.join("PPSA01001");
    fs::create_dir_all(&ready_game).unwrap();
    fs::write(
        ready_game.join("param.json"),
        r#"{"title":"Ready Game","titleId":"PPSA01001","requiredSystemSoftwareVersion":"7.00"}"#,
    )
    .unwrap();
    fs::write(ready_game.join("eboot.bin"), valid_elf64_stub()).unwrap();

    let dlc_pack = root.join("PPSA01002_DLC");
    fs::create_dir_all(&dlc_pack).unwrap();
    fs::write(
        dlc_pack.join("param.json"),
        r#"{"title":"DLC Pack","titleId":"PPSA01002"}"#,
    )
    .unwrap();

    let broken_game = root.join("PPSA01003_BROKEN");
    fs::create_dir_all(&broken_game).unwrap();
    fs::write(broken_game.join("eboot.bin"), valid_elf64_stub()).unwrap();

    fs::write(root.join("leftover.pkg.part"), b"partial_bytes").unwrap();

    let summary = scan_library_folder(&root, Some("8.00")).unwrap();
    assert_eq!(summary.items.len(), 3);
    assert_eq!(summary.ready_count, 1);
    assert_eq!(summary.warning_count, 1);
    assert_eq!(summary.blocked_count, 1);
    assert!(summary.total_bytes > 0);

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn probes_live_tcp_endpoint_and_reports_offline_invalid_host() {
    let mut manager = ConnectManager::default();
    manager.add_or_update(NetworkEndpoint::new(
        "bad-host",
        "Invalid-Host-NAS",
        RemoteProtocol::Smb,
        "not-an-ip",
        Some(445),
        "/share",
    ));

    let err = ensure_endpoint_ready(&manager, "bad-host", 200).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotConnected);

    if let Ok(listener) = TcpListener::bind("127.0.0.1:0") {
        let bound_addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            for _ in 0..2 {
                if listener.accept().is_err() {
                    break;
                }
            }
        });

        manager.add_or_update(NetworkEndpoint::new(
            "ps5-mock",
            "PS5-Local-Mock",
            RemoteProtocol::Ps5ElfLoader,
            bound_addr.ip().to_string(),
            Some(bound_addr.port()),
            "elfldr",
        ));

        let ready_ep = ensure_endpoint_ready(&manager, "ps5-mock", 500).unwrap();
        assert_eq!(ready_ep.name, "PS5-Local-Mock");

        let results = manager.check_all(500);
        assert!(matches!(results[0].1, EndpointHealth::Offline { .. }));
        assert!(matches!(results[1].1, EndpointHealth::Online { .. }));

        let _ = handle.join();
    }
}
