use crate::analyzer::{run_preflight_analysis, PreFlightReport, ReadinessStatus};
use crate::converter::{
    execute_stream_conversion, prepare_conversion_plan, CompressionProfile, ConversionResult,
    StreamFormat,
};
use crate::editor::{DumpEditorSession, EditOperation};
use crate::library::{scan_library_folder, LibrarySummary};
use crate::net::{
    send_elf_payload, ConnectManager, EndpointHealth, NetworkEndpoint, RemoteProtocol,
};
use crate::packer::{pack_game_assets, unpack_game_assets, AssetCodec, PackStats};
use crate::queue_engine::{JobPriority, StreamQueueEngine};
use eframe::egui;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveTab {
    Convert,
    Edit,
    Pack,
    Storage,
    Connect,
}

#[derive(Debug, Clone)]
enum ConversionTaskState {
    Idle,
    Running { label: String },
    Finished(ConversionResult),
    Failed(String),
}

pub struct PS5FileDumpApp {
    tab: ActiveTab,
    console_fw: String,
    target_input: String,
    output_input: String,
    target_format: StreamFormat,
    compression_profile: CompressionProfile,
    ffpfsc_level: i32,
    stream_buffer_mb: f32,
    last_report: Option<PreFlightReport>,
    analyzer_error: Option<String>,
    conv_state: Arc<Mutex<ConversionTaskState>>,
    editor: DumpEditorSession,
    editor_dir_input: String,
    editor_rename_from: String,
    editor_rename_to: String,
    editor_status: Option<String>,
    pack_src_input: String,
    pack_out_input: String,
    pack_codec: AssetCodec,
    pack_zstd_level: i32,
    pack_result: Option<PackStats>,
    pack_status: Option<String>,
    library_dir_input: String,
    library_summary: Option<LibrarySummary>,
    library_error: Option<String>,
    library_filter: String,
    stream_priority: JobPriority,
    engine: Arc<StreamQueueEngine>,
    next_job_id: u64,
    connect_mgr: ConnectManager,
    new_ep_name: String,
    new_ep_proto: RemoteProtocol,
    new_ep_host: String,
    new_ep_port: String,
    new_ep_path: String,
    health_results: Vec<(NetworkEndpoint, EndpointHealth)>,
    ps5_ip_input: String,
    ps5_port_input: String,
    elf_file_input: String,
    net_status_msg: Option<String>,
}

impl Default for PS5FileDumpApp {
    fn default() -> Self {
        let mut connect_mgr = ConnectManager::default();
        connect_mgr.add_or_update(NetworkEndpoint::new(
            "ps5-default",
            "PS5 Console (ELF Loader)",
            RemoteProtocol::Ps5ElfLoader,
            "192.168.1.42",
            Some(9021),
            "elfldr",
        ));
        connect_mgr.add_or_update(NetworkEndpoint::new(
            "nas-default",
            "Home NAS (SMB)",
            RemoteProtocol::Smb,
            "192.168.1.10",
            Some(445),
            "/ps5_dumps",
        ));

        Self {
            tab: ActiveTab::Convert,
            console_fw: "8.00".into(),
            target_input: String::new(),
            output_input: String::new(),
            target_format: StreamFormat::Pkg,
            compression_profile: CompressionProfile::Balanced,
            ffpfsc_level: 6,
            stream_buffer_mb: 2.0,
            last_report: None,
            analyzer_error: None,
            conv_state: Arc::new(Mutex::new(ConversionTaskState::Idle)),
            editor: DumpEditorSession::default(),
            editor_dir_input: String::new(),
            editor_rename_from: String::new(),
            editor_rename_to: String::new(),
            editor_status: None,
            pack_src_input: String::new(),
            pack_out_input: String::new(),
            pack_codec: AssetCodec::Zstd,
            pack_zstd_level: 6,
            pack_result: None,
            pack_status: None,
            library_dir_input: String::new(),
            library_summary: None,
            library_error: None,
            library_filter: String::new(),
            stream_priority: JobPriority::High,
            engine: Arc::new(StreamQueueEngine::new(2)),
            next_job_id: 1,
            connect_mgr,
            new_ep_name: String::new(),
            new_ep_proto: RemoteProtocol::Smb,
            new_ep_host: "192.168.1.50".into(),
            new_ep_port: "445".into(),
            new_ep_path: "/games".into(),
            health_results: Vec::new(),
            ps5_ip_input: "192.168.1.42".into(),
            ps5_port_input: "9021".into(),
            elf_file_input: String::new(),
            net_status_msg: None,
        }
    }
}

fn apply_forge_dark_theme(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(10.0, 8.0);
    style.spacing.button_padding = egui::vec2(13.0, 7.0);
    style.spacing.window_margin = egui::Margin::same(14.0);

    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = egui::Color32::from_rgb(14, 14, 21);
    visuals.window_fill = egui::Color32::from_rgb(14, 14, 21);
    visuals.extreme_bg_color = egui::Color32::from_rgb(16, 16, 23);
    visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(23, 23, 31);
    visuals.widgets.noninteractive.rounding = egui::Rounding::same(12.0);
    visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(36, 36, 47);
    visuals.widgets.inactive.rounding = egui::Rounding::same(16.0);
    visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(46, 46, 59);
    visuals.widgets.hovered.rounding = egui::Rounding::same(16.0);
    visuals.widgets.active.bg_fill = egui::Color32::from_rgb(61, 107, 255);
    visuals.widgets.active.rounding = egui::Rounding::same(16.0);
    visuals.selection.bg_fill = egui::Color32::from_rgb(61, 107, 255);

    style.visuals = visuals;
    ctx.set_style(style);
}

fn card_frame(fill: egui::Color32) -> egui::Frame {
    egui::Frame::none()
        .fill(fill)
        .rounding(egui::Rounding::same(14.0))
        .inner_margin(egui::Margin::same(14.0))
}

fn bordered_card_frame(fill: egui::Color32, stroke_color: egui::Color32) -> egui::Frame {
    egui::Frame::none()
        .fill(fill)
        .stroke(egui::Stroke::new(1.2, stroke_color))
        .rounding(egui::Rounding::same(14.0))
        .inner_margin(egui::Margin::same(14.0))
}

fn tile_frame() -> egui::Frame {
    egui::Frame::none()
        .fill(egui::Color32::from_rgb(16, 16, 23))
        .rounding(egui::Rounding::same(10.0))
        .inner_margin(egui::Margin::same(10.0))
}

impl PS5FileDumpApp {
    fn run_analysis(&mut self) {
        self.analyzer_error = None;
        let path = PathBuf::from(self.target_input.trim());
        if path.as_os_str().is_empty() {
            self.analyzer_error =
                Some("Select a source file (any extension) or game folder first.".into());
            return;
        }
        let fw = (!self.console_fw.trim().is_empty()).then_some(self.console_fw.trim());
        match run_preflight_analysis(&path, fw, None) {
            Ok(report) => self.last_report = Some(report),
            Err(e) => self.analyzer_error = Some(e.to_string()),
        }
    }

    fn start_conversion(&mut self) {
        let src = PathBuf::from(self.target_input.trim());
        let dst = PathBuf::from(self.output_input.trim());
        if src.as_os_str().is_empty() || dst.as_os_str().is_empty() {
            self.analyzer_error = Some("Both Source and Output target paths are required.".into());
            return;
        }
        let buf_bytes = ((self.stream_buffer_mb.clamp(0.25, 16.0)) * 1024.0 * 1024.0) as usize;
        let fw = (!self.console_fw.trim().is_empty()).then(|| self.console_fw.trim().to_string());
        let fmt = self.target_format;
        let profile = self.compression_profile;
        let level = self.ffpfsc_level;
        let state_arc = Arc::clone(&self.conv_state);

        *state_arc.lock().unwrap() = ConversionTaskState::Running {
            label: format!("Streaming {} -> {:?} ...", src.display(), fmt),
        };

        thread::spawn(move || {
            let outcome = prepare_conversion_plan(&src, &dst, Some(fmt), profile, level, buf_bytes)
                .and_then(|plan| execute_stream_conversion(&plan, fw.as_deref()));

            let mut guard = state_arc.lock().unwrap();
            match outcome {
                Ok(res) => *guard = ConversionTaskState::Finished(res),
                Err(e) => *guard = ConversionTaskState::Failed(e.to_string()),
            }
        });
    }

    fn run_library_scan(&mut self) {
        self.library_error = None;
        let path = PathBuf::from(self.library_dir_input.trim());
        if path.as_os_str().is_empty() {
            self.library_error = Some("Choose a Storage / Library folder first.".into());
            return;
        }
        let fw = (!self.console_fw.trim().is_empty()).then_some(self.console_fw.trim());
        match scan_library_folder(&path, fw) {
            Ok(summary) => self.library_summary = Some(summary),
            Err(e) => self.library_error = Some(e.to_string()),
        }
    }
}

impl eframe::App for PS5FileDumpApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.request_repaint_after(std::time::Duration::from_millis(200));

        egui::TopBottomPanel::top("forge_topbar").show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.colored_label(
                    egui::Color32::from_rgb(255, 122, 47),
                    egui::RichText::new("◆").strong().size(18.0),
                );
                ui.colored_label(
                    egui::Color32::from_rgb(242, 242, 247),
                    egui::RichText::new("PS5FileDump").strong().size(18.0),
                );
                ui.separator();

                ui.selectable_value(&mut self.tab, ActiveTab::Convert, "Convert & Inspect");
                ui.selectable_value(&mut self.tab, ActiveTab::Edit, "Edit Dump");
                ui.selectable_value(&mut self.tab, ActiveTab::Pack, "Pack (Zstd / LZ4)");
                ui.selectable_value(&mut self.tab, ActiveTab::Storage, "Storage & Library");
                ui.selectable_value(&mut self.tab, ActiveTab::Connect, "Connect & PS5");

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.add(egui::TextEdit::singleline(&mut self.console_fw).desired_width(58.0));
                    ui.weak("PS5 FW:");
                    let online_cnt = self
                        .health_results
                        .iter()
                        .filter(|(_, h)| matches!(h, EndpointHealth::Online { .. }))
                        .count();
                    if online_cnt > 0 {
                        ui.colored_label(
                            egui::Color32::from_rgb(47, 210, 122),
                            format!("● Connected ({online_cnt})"),
                        );
                    } else {
                        ui.weak("○ Connect Hub");
                    }
                });
            });
            ui.add_space(6.0);
        });

        egui::TopBottomPanel::bottom("forge_footer").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.weak(format!(
                    "PS5: {}:{}  |  Buffer: {:.2} MB  |  Priority: {:?}  |  Windows Release Build",
                    self.ps5_ip_input,
                    self.ps5_port_input,
                    self.stream_buffer_mb,
                    self.stream_priority
                ));
            });
            ui.add_space(4.0);
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.add_space(4.0);
                match self.tab {
                    ActiveTab::Convert => self.ui_convert_and_inspect(ui),
                    ActiveTab::Edit => self.ui_edit(ui),
                    ActiveTab::Pack => self.ui_pack(ui),
                    ActiveTab::Storage => self.ui_storage(ui),
                    ActiveTab::Connect => self.ui_connect(ui),
                }
            });
        });
    }
}

impl PS5FileDumpApp {
    fn ui_convert_and_inspect(&mut self, ui: &mut egui::Ui) {
        let card_bg = egui::Color32::from_rgb(23, 23, 31);
        let mut should_analyze = false;

        card_frame(card_bg).show(ui, |ui| {
            ui.heading("Source Selection & PS5 Pre-Flight Compatibility Check");
            ui.weak("Pick any file (any extension) or game folder. Automatically detects magic bytes, inspects ZIP contents, verifies eboot.bin ELF64, and checks PS5 readiness.");
            ui.add_space(8.0);

            ui.horizontal(|ui| {
                ui.label("Source:");
                ui.add(egui::TextEdit::singleline(&mut self.target_input).desired_width(440.0));
                if ui.button("Pick File...").clicked() {
                    if let Some(p) = rfd::FileDialog::new().pick_file() {
                        self.target_input = p.display().to_string();
                        should_analyze = true;
                    }
                }
                if ui.button("Pick Folder...").clicked() {
                    if let Some(p) = rfd::FileDialog::new().pick_folder() {
                        self.target_input = p.display().to_string();
                        should_analyze = true;
                    }
                }
                if ui.button("Inspect").clicked() {
                    should_analyze = true;
                }
            });

            if let Some(err) = &self.analyzer_error {
                ui.add_space(6.0);
                ui.colored_label(egui::Color32::from_rgb(255, 107, 107), err);
            }
        });

        if should_analyze {
            self.run_analysis();
        }

        if let Some(rep) = &self.last_report {
            ui.add_space(10.0);
            bordered_card_frame(card_bg, egui::Color32::from_rgb(255, 122, 47)).show(ui, |ui| {
                let (badge_label, color) = match rep.status {
                    ReadinessStatus::Ready => {
                        ("✓ READY FOR PS5", egui::Color32::from_rgb(47, 210, 122))
                    }
                    ReadinessStatus::Warning => (
                        "⚠ WARNING — REVIEW NOTES",
                        egui::Color32::from_rgb(255, 181, 71),
                    ),
                    ReadinessStatus::Blocked => (
                        "✕ BLOCKED — FIX BEFORE RUN",
                        egui::Color32::from_rgb(255, 107, 107),
                    ),
                };

                ui.horizontal(|ui| {
                    ui.heading(
                        rep.metadata
                            .title
                            .as_deref()
                            .unwrap_or("Detected Game / Package"),
                    );
                    ui.colored_label(
                        color,
                        egui::RichText::new(badge_label).strong().size(15.0),
                    );
                });

                ui.add_space(8.0);
                ui.horizontal_wrapped(|ui| {
                    let tiles = [
                        ("FORMAT", rep.detected_label.clone()),
                        (
                            "TITLE ID",
                            rep.metadata
                                .title_id
                                .clone()
                                .unwrap_or_else(|| "N/A".into()),
                        ),
                        (
                            "REQ FW",
                            rep.metadata
                                .required_fw
                                .clone()
                                .unwrap_or_else(|| "Unknown".into()),
                        ),
                        (
                            "EBOOT ELF64",
                            if rep.metadata.eboot_valid_elf64 {
                                "Valid 64-bit".into()
                            } else {
                                "Not Verified".into()
                            },
                        ),
                        (
                            "SIZE",
                            format!(
                                "{:.2} MB ({} files)",
                                rep.metadata.total_bytes as f64 / (1024.0 * 1024.0),
                                rep.metadata.total_files
                            ),
                        ),
                    ];
                    for (lbl, val) in tiles {
                        tile_frame().show(ui, |ui| {
                            ui.vertical(|ui| {
                                ui.weak(lbl);
                                ui.strong(val);
                            });
                        });
                    }
                });

                if let Some(sha) = &rep.metadata.sha256_hex {
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        ui.weak("SHA-256:");
                        ui.monospace(sha);
                    });
                }

                if !rep.findings.is_empty() {
                    ui.add_space(8.0);
                    for f in &rep.findings {
                        let c = match f.severity {
                            ReadinessStatus::Ready => egui::Color32::from_rgb(47, 210, 122),
                            ReadinessStatus::Warning => egui::Color32::from_rgb(255, 181, 71),
                            ReadinessStatus::Blocked => egui::Color32::from_rgb(255, 107, 107),
                        };
                        tile_frame().show(ui, |ui| {
                            ui.colored_label(
                                c,
                                format!("[{:?}] {} — {}", f.severity, f.code, f.message),
                            );
                            ui.weak(format!("Action: {}", f.remediation));
                        });
                    }
                }
            });
        }

        ui.add_space(10.0);
        let mut should_convert = false;

        card_frame(card_bg).show(ui, |ui| {
            ui.heading("Target Format & Stream Conversion");
            ui.add_space(6.0);

            ui.horizontal_wrapped(|ui| {
                ui.label("Target Format:");
                ui.selectable_value(&mut self.target_format, StreamFormat::Folder, "Folder");
                ui.selectable_value(&mut self.target_format, StreamFormat::Zip, "ZIP");
                ui.selectable_value(&mut self.target_format, StreamFormat::Pkg, "FPKG (.pkg)");
                ui.selectable_value(&mut self.target_format, StreamFormat::ExFat, "exFAT");
                ui.selectable_value(&mut self.target_format, StreamFormat::Ffpkg, "FFPKG");
                ui.selectable_value(&mut self.target_format, StreamFormat::Ffpfs, "FFPFS");
                ui.selectable_value(&mut self.target_format, StreamFormat::Ffpfsc, "FFPFSC");
            });

            ui.horizontal(|ui| {
                ui.label("Profile:");
                ui.selectable_value(
                    &mut self.compression_profile,
                    CompressionProfile::Fast,
                    "Fast",
                );
                ui.selectable_value(
                    &mut self.compression_profile,
                    CompressionProfile::Balanced,
                    "Balanced",
                );
                ui.selectable_value(
                    &mut self.compression_profile,
                    CompressionProfile::Smallest,
                    "Smallest",
                );
                ui.selectable_value(
                    &mut self.compression_profile,
                    CompressionProfile::Stored,
                    "Stored",
                );
                if self.target_format == StreamFormat::Ffpfsc {
                    ui.separator();
                    ui.label("FFPFSC Level:");
                    ui.add(egui::Slider::new(&mut self.ffpfsc_level, 0..=9));
                }
            });

            ui.horizontal(|ui| {
                ui.label("Queue Priority:");
                ui.selectable_value(&mut self.stream_priority, JobPriority::High, "High");
                ui.selectable_value(&mut self.stream_priority, JobPriority::Normal, "Normal");
                ui.selectable_value(&mut self.stream_priority, JobPriority::Low, "Low");
            });

            ui.horizontal(|ui| {
                ui.label("Output:");
                ui.add(egui::TextEdit::singleline(&mut self.output_input).desired_width(420.0));
                if ui.button("Save File...").clicked() {
                    if let Some(p) = rfd::FileDialog::new().save_file() {
                        self.output_input = p.display().to_string();
                    }
                }
                if ui.button("Pick Folder...").clicked() {
                    if let Some(p) = rfd::FileDialog::new().pick_folder() {
                        self.output_input = p.display().to_string();
                        self.target_format = StreamFormat::Folder;
                    }
                }
            });

            ui.horizontal(|ui| {
                ui.label("Stream Buffer (MB):");
                ui.add(egui::Slider::new(&mut self.stream_buffer_mb, 0.25..=16.0));
                if ui.button("Start Convert Stream").clicked() {
                    should_convert = true;
                }
            });

            let conv_snapshot = self.conv_state.lock().unwrap().clone();
            match conv_snapshot {
                ConversionTaskState::Idle => {}
                ConversionTaskState::Running { label } => {
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.colored_label(egui::Color32::from_rgb(157, 182, 255), label);
                    });
                }
                ConversionTaskState::Finished(res) => {
                    ui.add_space(6.0);
                    ui.colored_label(
                        egui::Color32::from_rgb(47, 210, 122),
                        format!(
                            "✓ Completed: {:?} -> {:?} | Files: {} | Read: {} B | Written: {} B | Verified: {}",
                            res.source_format,
                            res.target_format,
                            res.files_processed,
                            res.bytes_read,
                            res.bytes_written,
                            res.verified
                        ),
                    );
                }
                ConversionTaskState::Failed(err) => {
                    ui.add_space(6.0);
                    ui.colored_label(
                        egui::Color32::from_rgb(255, 107, 107),
                        format!("✕ Failed: {err}"),
                    );
                }
            }
        });

        if should_convert {
            self.next_job_id += 1;
            self.start_conversion();
        }
    }

    fn ui_edit(&mut self, ui: &mut egui::Ui) {
        let card_bg = egui::Color32::from_rgb(23, 23, 31);
        let mut staged_rename: Option<(String, String)> = None;
        let mut staged_add: Option<(PathBuf, String)> = None;
        let mut staged_delete: Option<String> = None;
        let mut do_undo = false;
        let mut do_discard = false;
        let mut do_apply = false;
        let mut do_reload = false;

        card_frame(card_bg).show(ui, |ui| {
            ui.heading("Game Dump File Editor (Staged Changes + Undo + Apply)");
            ui.weak("Browse dump files, stage renames, additions, or deletions, then Apply safely.");
            ui.add_space(8.0);

            ui.horizontal(|ui| {
                ui.label("Dump Folder:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.editor_dir_input).desired_width(420.0),
                );
                if ui.button("Open Folder...").clicked() {
                    if let Some(p) = rfd::FileDialog::new().pick_folder() {
                        self.editor_dir_input = p.display().to_string();
                        do_reload = true;
                    }
                }
                if ui.button("Reload").clicked() {
                    do_reload = true;
                }
            });

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label("Rename From:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.editor_rename_from)
                        .desired_width(170.0),
                );
                ui.label("To:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.editor_rename_to).desired_width(170.0),
                );
                if ui.button("Stage Rename").clicked() && !self.editor_rename_from.trim().is_empty()
                {
                    staged_rename = Some((
                        self.editor_rename_from.trim().to_string(),
                        self.editor_rename_to.trim().to_string(),
                    ));
                    self.editor_rename_from.clear();
                    self.editor_rename_to.clear();
                }
                if ui.button("Add File...").clicked() {
                    if let Some(src_f) = rfd::FileDialog::new().pick_file() {
                        let name = src_f
                            .file_name()
                            .and_then(|s| s.to_str())
                            .unwrap_or("added_file.bin")
                            .to_string();
                        staged_add = Some((src_f, name));
                    }
                }
            });

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.strong(format!(
                    "Staged Changes: {}",
                    self.editor.pending_ops.len()
                ));
                if ui.button("Undo Last").clicked() {
                    do_undo = true;
                }
                if ui.button("Discard All").clicked() {
                    do_discard = true;
                }
                if ui.button("Apply Changes").clicked() {
                    do_apply = true;
                }
            });

            if let Some(st) = &self.editor_status {
                ui.colored_label(egui::Color32::from_rgb(47, 210, 122), st);
            }

            ui.separator();
            for entry in self.editor.entries.clone() {
                ui.horizontal(|ui| {
                    ui.monospace(&entry.rel_path);
                    if !entry.is_dir {
                        ui.weak(format!("({} B)", entry.size));
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.small_button("Stage Delete").clicked() {
                            staged_delete = Some(entry.rel_path.clone());
                        }
                        if ui.small_button("Select").clicked() {
                            self.editor_rename_from = entry.rel_path.clone();
                            self.editor_rename_to = entry.rel_path;
                        }
                    });
                });
            }
        });

        if do_reload {
            let p = PathBuf::from(self.editor_dir_input.trim());
            let _ = self.editor.load_folder(&p);
        }
        if let Some((from_rel, to_rel)) = staged_rename {
            self.editor
                .stage_op(EditOperation::Rename { from_rel, to_rel });
        }
        if let Some((src_file, target_rel)) = staged_add {
            self.editor.stage_op(EditOperation::AddOrReplace {
                src_file,
                target_rel,
            });
        }
        if let Some(rel_path) = staged_delete {
            self.editor.stage_op(EditOperation::Delete { rel_path });
        }
        if do_undo {
            self.editor.undo_last();
        }
        if do_discard {
            self.editor.discard_all();
        }
        if do_apply {
            match self.editor.apply_changes() {
                Ok(n) => {
                    self.editor_status = Some(format!("Applied {n} change(s) successfully."))
                }
                Err(e) => self.editor_status = Some(format!("Error: {e}")),
            }
        }
    }

    fn ui_pack(&mut self, ui: &mut egui::Ui) {
        let card_bg = egui::Color32::from_rgb(23, 23, 31);
        let mut do_pack = false;
        let mut do_unpack = false;

        card_frame(card_bg).show(ui, |ui| {
            ui.colored_label(
                egui::Color32::from_rgb(255, 216, 77),
                egui::RichText::new(
                    "Asset Packer & Unpacker (Zstd / LZ4 + 8-byte aligned ampr_emu.index)",
                )
                .strong()
                .size(16.0),
            );
            ui.weak("Compresses game assets into Zstd or LZ4 packs for runtime loading on PS5 via fakelib/libSceAmpr.sprx.");
            ui.add_space(8.0);

            ui.horizontal(|ui| {
                ui.label("Game Folder:");
                ui.add(egui::TextEdit::singleline(&mut self.pack_src_input).desired_width(400.0));
                if ui.button("Pick Source...").clicked() {
                    if let Some(p) = rfd::FileDialog::new().pick_folder() {
                        self.pack_src_input = p.display().to_string();
                    }
                }
            });

            ui.horizontal(|ui| {
                ui.label("Output Folder:");
                ui.add(egui::TextEdit::singleline(&mut self.pack_out_input).desired_width(400.0));
                if ui.button("Pick Output...").clicked() {
                    if let Some(p) = rfd::FileDialog::new().pick_folder() {
                        self.pack_out_input = p.display().to_string();
                    }
                }
            });

            ui.horizontal(|ui| {
                ui.label("Codec:");
                ui.selectable_value(&mut self.pack_codec, AssetCodec::Zstd, "Zstd Pack");
                ui.selectable_value(&mut self.pack_codec, AssetCodec::Lz4, "LZ4 Pack");
                if self.pack_codec == AssetCodec::Zstd {
                    ui.separator();
                    ui.label("Zstd Level:");
                    ui.add(egui::Slider::new(&mut self.pack_zstd_level, 1..=19));
                }
            });

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui.button("Pack Assets").clicked() {
                    do_pack = true;
                }
                if ui.button("Unpack Assets").clicked() {
                    do_unpack = true;
                }
            });

            if let Some(msg) = &self.pack_status {
                ui.add_space(6.0);
                ui.colored_label(egui::Color32::from_rgb(255, 216, 77), msg);
            }

            if let Some(st) = &self.pack_result {
                ui.add_space(6.0);
                ui.label(format!(
                    "Codec: {:?} | Packed Files: {} | Original: {} B -> Packed: {} B | libSceAmpr.sprx present: {}",
                    st.codec, st.files_packed, st.original_bytes, st.compressed_bytes, st.has_ampr_sprx
                ));
                if !st.has_ampr_sprx {
                    ui.colored_label(
                        egui::Color32::from_rgb(255, 181, 71),
                        "Warning: fakelib/libSceAmpr.sprx not found in output folder. Add it before running on PS5.",
                    );
                }
            }
        });

        if do_pack {
            let src = PathBuf::from(self.pack_src_input.trim());
            let dst = PathBuf::from(self.pack_out_input.trim());
            match pack_game_assets(&src, &dst, self.pack_codec, self.pack_zstd_level) {
                Ok(stats) => {
                    self.pack_status = Some("Assets packed successfully.".into());
                    self.pack_result = Some(stats);
                }
                Err(e) => self.pack_status = Some(format!("Pack failed: {e}")),
            }
        }
        if do_unpack {
            let src = PathBuf::from(self.pack_src_input.trim());
            let dst = PathBuf::from(self.pack_out_input.trim());
            match unpack_game_assets(&src, &dst) {
                Ok(n) => {
                    self.pack_status = Some(format!(
                        "Unpacked {n} compressed asset(s) to original format."
                    ))
                }
                Err(e) => self.pack_status = Some(format!("Unpack failed: {e}")),
            }
        }
    }

    fn ui_storage(&mut self, ui: &mut egui::Ui) {
        let card_bg = egui::Color32::from_rgb(23, 23, 31);
        let mut should_scan = false;
        let mut open_in_editor: Option<PathBuf> = None;
        let mut open_in_convert: Option<PathBuf> = None;

        card_frame(card_bg).show(ui, |ui| {
            ui.heading("Storage & Game Library Manager");
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label("Library Folder:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.library_dir_input).desired_width(400.0),
                );
                if ui.button("Select Folder...").clicked() {
                    if let Some(p) = rfd::FileDialog::new().pick_folder() {
                        self.library_dir_input = p.display().to_string();
                        should_scan = true;
                    }
                }
                if ui.button("Scan Library").clicked() {
                    should_scan = true;
                }
            });

            ui.horizontal(|ui| {
                ui.label("Search Filter:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.library_filter).desired_width(240.0),
                );
            });

            if let Some(err) = &self.library_error {
                ui.colored_label(egui::Color32::from_rgb(255, 107, 107), err);
            }
        });

        if should_scan {
            self.run_library_scan();
        }

        if let Some(sum) = &self.library_summary {
            ui.add_space(10.0);
            card_frame(card_bg).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.strong(format!("Total: {}", sum.items.len()));
                    ui.colored_label(
                        egui::Color32::from_rgb(47, 210, 122),
                        format!("Ready: {}", sum.ready_count),
                    );
                    ui.colored_label(
                        egui::Color32::from_rgb(255, 181, 71),
                        format!("Warning: {}", sum.warning_count),
                    );
                    ui.colored_label(
                        egui::Color32::from_rgb(255, 107, 107),
                        format!("Blocked: {}", sum.blocked_count),
                    );
                    ui.label(format!(
                        "Total Size: {:.2} GB",
                        sum.total_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
                    ));
                });
                ui.add_space(8.0);

                let q = self.library_filter.trim().to_ascii_lowercase();
                for item in sum.items.iter().filter(|it| {
                    if q.is_empty() {
                        return true;
                    }
                    let title = it
                        .report
                        .metadata
                        .title
                        .as_deref()
                        .unwrap_or("")
                        .to_ascii_lowercase();
                    let path_s = it.path.display().to_string().to_ascii_lowercase();
                    title.contains(&q) || path_s.contains(&q)
                }) {
                    let c = match item.report.status {
                        ReadinessStatus::Ready => egui::Color32::from_rgb(47, 210, 122),
                        ReadinessStatus::Warning => egui::Color32::from_rgb(255, 181, 71),
                        ReadinessStatus::Blocked => egui::Color32::from_rgb(255, 107, 107),
                    };
                    tile_frame().show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.colored_label(c, format!("[{:?}]", item.report.status));
                            ui.strong(
                                item.report
                                    .metadata
                                    .title
                                    .as_deref()
                                    .unwrap_or("Unnamed"),
                            );
                            ui.label(format!("({})", item.report.detected_label));
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if item.path.is_dir() && ui.small_button("Edit").clicked() {
                                    open_in_editor = Some(item.path.clone());
                                }
                                if ui.small_button("Convert").clicked() {
                                    open_in_convert = Some(item.path.clone());
                                }
                            });
                        });
                        ui.weak(item.path.display().to_string());
                    });
                    ui.add_space(4.0);
                }
            });
        }

        if let Some(p) = open_in_editor {
            self.editor_dir_input = p.display().to_string();
            let _ = self.editor.load_folder(&p);
            self.tab = ActiveTab::Edit;
        }
        if let Some(p) = open_in_convert {
            self.target_input = p.display().to_string();
            self.run_analysis();
            self.tab = ActiveTab::Convert;
        }
    }

    fn ui_connect(&mut self, ui: &mut egui::Ui) {
        let card_bg = egui::Color32::from_rgb(23, 23, 31);
        let mut do_send_elf = false;
        let mut do_add_endpoint = false;
        let mut do_probe_all = false;

        card_frame(card_bg).show(ui, |ui| {
            ui.heading("PS5 ELF Payload Sender (Port 9021)");
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label("PS5 IP:");
                ui.add(egui::TextEdit::singleline(&mut self.ps5_ip_input).desired_width(140.0));
                ui.label("Port:");
                ui.add(egui::TextEdit::singleline(&mut self.ps5_port_input).desired_width(64.0));
            });
            ui.horizontal(|ui| {
                ui.label("Payload:");
                ui.add(egui::TextEdit::singleline(&mut self.elf_file_input).desired_width(360.0));
                if ui.button("Select .elf...").clicked() {
                    if let Some(p) = rfd::FileDialog::new()
                        .add_filter("ELF", &["elf", "bin"])
                        .pick_file()
                    {
                        self.elf_file_input = p.display().to_string();
                    }
                }
                if ui.button("Send to PS5").clicked() {
                    do_send_elf = true;
                }
            });
        });

        ui.add_space(10.0);
        card_frame(card_bg).show(ui, |ui| {
            ui.heading("Paired Forge Peers & NAS Hubs (SMB, FTP, NFS)");
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label("Name:");
                ui.add(egui::TextEdit::singleline(&mut self.new_ep_name).desired_width(120.0));
                ui.selectable_value(&mut self.new_ep_proto, RemoteProtocol::Smb, "SMB");
                ui.selectable_value(&mut self.new_ep_proto, RemoteProtocol::Ftp, "FTP");
                ui.selectable_value(&mut self.new_ep_proto, RemoteProtocol::Nfs, "NFS");
                ui.selectable_value(&mut self.new_ep_proto, RemoteProtocol::ForgePeer, "Peer");
                ui.label("Host:");
                ui.add(egui::TextEdit::singleline(&mut self.new_ep_host).desired_width(110.0));
                ui.label("Port:");
                ui.add(egui::TextEdit::singleline(&mut self.new_ep_port).desired_width(54.0));
                ui.label("Share:");
                ui.add(egui::TextEdit::singleline(&mut self.new_ep_path).desired_width(100.0));
                if ui.button("Add").clicked() && !self.new_ep_name.trim().is_empty() {
                    do_add_endpoint = true;
                }
            });

            ui.add_space(6.0);
            if ui.button("Check All Connections").clicked() {
                do_probe_all = true;
            }

            if let Some(msg) = &self.net_status_msg {
                ui.add_space(6.0);
                ui.colored_label(egui::Color32::from_rgb(157, 182, 255), msg);
            }

            for (ep, health) in &self.health_results {
                ui.add_space(4.0);
                tile_frame().show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.strong(&ep.name);
                        ui.label(format!(
                            "[{:?}] {}:{} ({})",
                            ep.protocol, ep.host, ep.port, ep.share_or_path
                        ));
                        match health {
                            EndpointHealth::Online { latency_ms } => {
                                ui.colored_label(
                                    egui::Color32::from_rgb(47, 210, 122),
                                    format!("ONLINE ({latency_ms} ms)"),
                                );
                            }
                            EndpointHealth::Offline { reason } => {
                                ui.colored_label(
                                    egui::Color32::from_rgb(255, 107, 107),
                                    format!("OFFLINE: {reason}"),
                                );
                            }
                        }
                    });
                });
            }
        });

        if do_send_elf {
            let p = PathBuf::from(self.elf_file_input.trim());
            let port: u16 = self.ps5_port_input.trim().parse().unwrap_or(9021);
            match send_elf_payload(&p, self.ps5_ip_input.trim(), port) {
                Ok(()) => {
                    self.net_status_msg = Some("Payload sent successfully to PS5.".into())
                }
                Err(e) => self.net_status_msg = Some(format!("Failed: {e}")),
            }
        }
        if do_add_endpoint {
            let id = format!("ep-{}", self.new_ep_name.trim().to_lowercase());
            let port = self.new_ep_port.trim().parse().ok();
            self.connect_mgr.add_or_update(NetworkEndpoint::new(
                id,
                self.new_ep_name.trim(),
                self.new_ep_proto,
                self.new_ep_host.trim(),
                port,
                self.new_ep_path.trim(),
            ));
            self.new_ep_name.clear();
        }
        if do_probe_all {
            self.health_results = self.connect_mgr.check_all(400);
        }
    }
}

pub fn launch_gui() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1180.0, 800.0])
            .with_min_inner_size([900.0, 620.0])
            .with_title("PS5FileDump"),
        ..Default::default()
    };

    eframe::run_native(
        "PS5FileDump",
        options,
        Box::new(|cc| {
            apply_forge_dark_theme(&cc.egui_ctx);
            Ok(Box::new(PS5FileDumpApp::default()))
        }),
    )
}
