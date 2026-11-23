use crate::analyzer::{
    apply_suggested_fix, run_preflight_analysis, DiagnosticFinding, FixActionKind,
    PreFlightReport, ReadinessStatus,
};
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
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveTab {
    Convert,
    Edit,
    Pack,
    Storage,
    Connect,
    About,
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
    auto_output_name: bool,
    full_verification: bool,
    delete_source: bool,
    target_format: StreamFormat,
    compression_profile: CompressionProfile,
    ffpfsc_level: i32,
    stream_buffer_mb: f32,
    last_report: Option<PreFlightReport>,
    analyzer_error: Option<String>,
    fix_feedback: Option<(bool, String)>,
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
    _engine: Arc<StreamQueueEngine>,
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
            auto_output_name: true,
            full_verification: false,
            delete_source: false,
            target_format: StreamFormat::Zip,
            compression_profile: CompressionProfile::Fast,
            ffpfsc_level: 6,
            stream_buffer_mb: 2.0,
            last_report: None,
            analyzer_error: None,
            fix_feedback: None,
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
            _engine: Arc::new(StreamQueueEngine::new(2)),
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
    style.spacing.button_padding = egui::vec2(14.0, 7.0);
    style.spacing.window_margin = egui::Margin::same(14.0);

    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = egui::Color32::from_rgb(12, 14, 22);
    visuals.window_fill = egui::Color32::from_rgb(12, 14, 22);
    visuals.extreme_bg_color = egui::Color32::from_rgb(16, 19, 30);
    visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(20, 24, 38);
    visuals.widgets.noninteractive.rounding = egui::Rounding::same(12.0);
    visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(31, 36, 54);
    visuals.widgets.inactive.rounding = egui::Rounding::same(16.0);
    visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(42, 49, 72);
    visuals.widgets.hovered.rounding = egui::Rounding::same(16.0);
    visuals.widgets.active.bg_fill = egui::Color32::from_rgb(37, 99, 235);
    visuals.widgets.active.rounding = egui::Rounding::same(16.0);
    visuals.selection.bg_fill = egui::Color32::from_rgb(37, 99, 235);

    style.visuals = visuals;
    ctx.set_style(style);
}

fn panel_card() -> egui::Frame {
    egui::Frame::none()
        .fill(egui::Color32::from_rgb(20, 24, 38))
        .stroke(egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(36, 43, 66)))
        .rounding(egui::Rounding::same(16.0))
        .inner_margin(egui::Margin::same(16.0))
}

fn sub_card() -> egui::Frame {
    egui::Frame::none()
        .fill(egui::Color32::from_rgb(15, 18, 29))
        .stroke(egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(31, 37, 58)))
        .rounding(egui::Rounding::same(12.0))
        .inner_margin(egui::Margin::same(12.0))
}

fn format_badge(ui: &mut egui::Ui, label: &str, color: egui::Color32) {
    egui::Frame::none()
        .fill(color.linear_multiply(0.22))
        .stroke(egui::Stroke::new(1.0_f32, color.linear_multiply(0.75)))
        .rounding(egui::Rounding::same(8.0))
        .inner_margin(egui::Margin::symmetric(8.0, 3.0))
        .show(ui, |ui| {
            ui.colored_label(color, egui::RichText::new(label).small().strong());
        });
}

fn toggle_switch(ui: &mut egui::Ui, checked: &mut bool) -> egui::Response {
    let desired_size = egui::vec2(42.0, 22.0);
    let (rect, response) = ui.allocate_exact_size(desired_size, egui::Sense::click());
    if response.clicked() {
        *checked = !*checked;
    }
    if ui.is_rect_visible(rect) {
        let how_on = if *checked { 1.0_f32 } else { 0.0_f32 };
        let bg = if *checked {
            egui::Color32::from_rgb(37, 99, 235)
        } else {
            egui::Color32::from_rgb(47, 54, 77)
        };
        ui.painter().rect_filled(rect, 11.0, bg);
        let radius = 8.0_f32;
        let cx = egui::lerp(
            (rect.left() + radius + 3.0)..=(rect.right() - radius - 3.0),
            how_on,
        );
        ui.painter()
            .circle_filled(egui::pos2(cx, rect.center().y), radius, egui::Color32::WHITE);
    }
    response
}

impl PS5FileDumpApp {
    fn compute_default_output(&self, src_str: &str, fmt: StreamFormat) -> String {
        let p = Path::new(src_str.trim());
        if src_str.trim().is_empty() {
            return String::new();
        }
        let parent = p.parent().unwrap_or_else(|| Path::new("."));
        let stem = p
            .file_stem()
            .and_then(|s| s.to_str())
            .filter(|s| !s.is_empty())
            .or_else(|| p.file_name().and_then(|s| s.to_str()))
            .unwrap_or("ps5_dump");

        match fmt {
            StreamFormat::Folder => parent.join(format!("{stem}_out")).display().to_string(),
            StreamFormat::Zip => parent.join(format!("{stem}.zip")).display().to_string(),
            _ => parent.join(format!("{stem}.zip")).display().to_string(),
        }
    }

    fn sync_auto_output(&mut self) {
        if self.auto_output_name && !self.target_input.trim().is_empty() {
            self.output_input = self.compute_default_output(&self.target_input, self.target_format);
        }
    }

    fn run_analysis(&mut self) {
        self.analyzer_error = None;
        let path = PathBuf::from(self.target_input.trim());
        if path.as_os_str().is_empty() {
            self.analyzer_error = Some("Choose a source folder, image, or archive first.".into());
            return;
        }
        let fw = (!self.console_fw.trim().is_empty()).then_some(self.console_fw.trim());
        match run_preflight_analysis(&path, fw, None) {
            Ok(report) => {
                self.last_report = Some(report);
                self.sync_auto_output();
            }
            Err(e) => self.analyzer_error = Some(e.to_string()),
        }
    }

    fn execute_fix(&mut self, finding: &DiagnosticFinding) {
        let root_path = PathBuf::from(self.target_input.trim());
        match apply_suggested_fix(finding, &root_path) {
            Ok(msg) => {
                if finding.fix_action == FixActionKind::UseSuggestedRoot {
                    if let Some(ref new_root) = finding.fix_target_path {
                        self.target_input = new_root.display().to_string();
                    }
                }
                self.fix_feedback = Some((true, msg));
                self.run_analysis();
            }
            Err(e) => {
                self.fix_feedback = Some((false, e.to_string()));
            }
        }
    }

    fn start_conversion(&mut self) {
        let src = PathBuf::from(self.target_input.trim());
        let dst = PathBuf::from(self.output_input.trim());
        if src.as_os_str().is_empty() || dst.as_os_str().is_empty() {
            self.analyzer_error = Some("Choose a source first so output path is ready.".into());
            return;
        }
        let buf_bytes = ((self.stream_buffer_mb.clamp(0.25, 16.0)) * 1024.0 * 1024.0) as usize;
        let fw = (!self.console_fw.trim().is_empty()).then(|| self.console_fw.trim().to_string());
        let fmt = self.target_format;
        let profile = self.compression_profile;
        let level = self.ffpfsc_level;
        let verify = self.full_verification;
        let remove_src = self.delete_source;
        let state_arc = Arc::clone(&self.conv_state);

        *state_arc.lock().unwrap() = ConversionTaskState::Running {
            label: format!("Building {} -> {:?} ...", src.display(), fmt),
        };

        thread::spawn(move || {
            let outcome = prepare_conversion_plan(&src, &dst, Some(fmt), profile, level, buf_bytes)
                .and_then(|plan| execute_stream_conversion(&plan, fw.as_deref()))
                .and_then(|res| {
                    if verify && !res.verified {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Full verification failed on output stream.",
                        ));
                    }
                    if remove_src && res.verified {
                        if src.is_dir() {
                            let _ = std::fs::remove_dir_all(&src);
                        } else if src.is_file() {
                            let _ = std::fs::remove_file(&src);
                        }
                    }
                    Ok(res)
                });

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

        egui::TopBottomPanel::top("forge_topbar")
            .frame(
                egui::Frame::none()
                    .fill(egui::Color32::from_rgb(12, 14, 22))
                    .inner_margin(egui::Margin::symmetric(16.0, 10.0)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let online_cnt = self
                        .health_results
                        .iter()
                        .filter(|(_, h)| matches!(h, EndpointHealth::Online { .. }))
                        .count();

                    if online_cnt > 0 {
                        egui::Frame::none()
                            .fill(egui::Color32::from_rgb(20, 56, 38))
                            .rounding(egui::Rounding::same(16.0))
                            .inner_margin(egui::Margin::symmetric(12.0, 5.0))
                            .show(ui, |ui| {
                                ui.colored_label(
                                    egui::Color32::from_rgb(74, 222, 128),
                                    format!("Connected ({online_cnt})"),
                                );
                            });
                    } else {
                        egui::Frame::none()
                            .fill(egui::Color32::from_rgb(24, 28, 43))
                            .stroke(egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(42, 49, 72)))
                            .rounding(egui::Rounding::same(16.0))
                            .inner_margin(egui::Margin::symmetric(12.0, 5.0))
                            .show(ui, |ui| {
                                ui.weak("Disconnected");
                            });
                    }

                    ui.with_layout(
                        egui::Layout::centered_and_justified(egui::Direction::LeftToRight),
                        |ui| {
                            ui.horizontal(|ui| {
                                ui.selectable_value(&mut self.tab, ActiveTab::Convert, "Convert");
                                ui.selectable_value(&mut self.tab, ActiveTab::Edit, "Edit");
                                ui.selectable_value(&mut self.tab, ActiveTab::Pack, "Pack");
                                ui.selectable_value(&mut self.tab, ActiveTab::Storage, "Storage");
                                ui.selectable_value(&mut self.tab, ActiveTab::Connect, "Connect");
                                ui.selectable_value(&mut self.tab, ActiveTab::About, "About");
                            });
                        },
                    );

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.console_fw).desired_width(54.0),
                        );
                        ui.weak("FW");
                    });
                });
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.add_space(6.0);
                match self.tab {
                    ActiveTab::Convert => self.ui_convert_two_column(ui),
                    ActiveTab::Edit => self.ui_edit(ui),
                    ActiveTab::Pack => self.ui_pack(ui),
                    ActiveTab::Storage => self.ui_storage(ui),
                    ActiveTab::Connect => self.ui_connect(ui),
                    ActiveTab::About => self.ui_about(ui),
                }
            });
        });
    }
}

impl PS5FileDumpApp {
    fn ui_convert_two_column(&mut self, ui: &mut egui::Ui) {
        let mut should_analyze = false;
        let mut triggered_fix: Option<DiagnosticFinding> = None;
        let mut should_build = false;
        let mut format_changed = false;

        let avail = ui.available_size();
        let col_w = ((avail.x - 16.0) * 0.5).max(340.0);

        ui.horizontal_top(|ui| {
            ui.vertical(|ui| {
                ui.set_width(col_w);
                panel_card().show(ui, |ui| {
                    ui.heading("Source");
                    ui.add_space(12.0);

                    sub_card().show(ui, |ui| {
                        ui.set_min_height(210.0);
                        ui.vertical_centered(|ui| {
                            ui.add_space(14.0);
                            ui.colored_label(
                                egui::Color32::from_rgb(138, 152, 198),
                                egui::RichText::new("◎").size(34.0),
                            );
                            ui.add_space(6.0);
                            ui.strong("Choose a game folder, image or archive");
                            ui.add_space(10.0);

                            ui.horizontal_wrapped(|ui| {
                                format_badge(ui, "Folder", egui::Color32::from_rgb(96, 165, 250));
                                format_badge(ui, "zip", egui::Color32::from_rgb(250, 204, 21));
                                format_badge(ui, "gz", egui::Color32::from_rgb(56, 189, 248));
                                format_badge(ui, "exfat", egui::Color32::from_rgb(192, 132, 252));
                                format_badge(ui, "fpkg", egui::Color32::from_rgb(74, 222, 128));
                                format_badge(ui, "7z", egui::Color32::from_rgb(148, 163, 184));
                                format_badge(ui, "rar", egui::Color32::from_rgb(248, 113, 113));
                            });

                            ui.add_space(14.0);
                            ui.horizontal(|ui| {
                                if ui
                                    .add(
                                        egui::Button::new(
                                            egui::RichText::new("◎  Pick Folder").strong(),
                                        )
                                        .fill(egui::Color32::WHITE)
                                        .rounding(egui::Rounding::same(20.0)),
                                    )
                                    .clicked()
                                {
                                    if let Some(p) = rfd::FileDialog::new().pick_folder() {
                                        self.target_input = p.display().to_string();
                                        should_analyze = true;
                                    }
                                }
                                if ui
                                    .add(
                                        egui::Button::new("Pick File")
                                            .rounding(egui::Rounding::same(20.0)),
                                    )
                                    .clicked()
                                {
                                    if let Some(p) = rfd::FileDialog::new().pick_file() {
                                        self.target_input = p.display().to_string();
                                        should_analyze = true;
                                    }
                                }
                            });
                        });
                    });

                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        ui.label("Path:");
                        if ui
                            .add(
                                egui::TextEdit::singleline(&mut self.target_input)
                                    .desired_width((col_w - 130.0).max(140.0)),
                            )
                            .lost_focus()
                        {
                            should_analyze = true;
                        }
                        if ui.button("Inspect").clicked() {
                            should_analyze = true;
                        }
                    });

                    if let Some(err) = &self.analyzer_error {
                        ui.add_space(6.0);
                        ui.colored_label(egui::Color32::from_rgb(248, 113, 113), err);
                    }

                    if let Some((ok, msg)) = &self.fix_feedback {
                        ui.add_space(6.0);
                        let c = if *ok {
                            egui::Color32::from_rgb(74, 222, 128)
                        } else {
                            egui::Color32::from_rgb(248, 113, 113)
                        };
                        ui.colored_label(c, msg);
                    }
                });

                if let Some(rep) = &self.last_report {
                    ui.add_space(12.0);
                    panel_card().show(ui, |ui| {
                        let (status_txt, status_col) = match rep.status {
                            ReadinessStatus::Ready => {
                                ("Ready", egui::Color32::from_rgb(74, 222, 128))
                            }
                            ReadinessStatus::Warning => {
                                ("Warning", egui::Color32::from_rgb(250, 204, 21))
                            }
                            ReadinessStatus::Blocked => {
                                ("Blocked", egui::Color32::from_rgb(248, 113, 113))
                            }
                        };

                        ui.horizontal(|ui| {
                            ui.strong(
                                rep.metadata
                                    .title
                                    .as_deref()
                                    .unwrap_or("Dump Inspection & Repair"),
                            );
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    ui.colored_label(
                                        status_col,
                                        egui::RichText::new(status_txt).strong(),
                                    );
                                },
                            );
                        });

                        ui.add_space(4.0);
                        ui.weak(format!(
                            "Type: {}  |  Size: {:.2} MB  |  Files: {}  |  ELF64: {}",
                            rep.detected_label,
                            rep.metadata.total_bytes as f64 / (1024.0 * 1024.0),
                            rep.metadata.total_files,
                            if rep.metadata.eboot_valid_elf64 {
                                "OK"
                            } else {
                                "Invalid"
                            }
                        ));

                        if !rep.findings.is_empty() {
                            ui.add_space(8.0);
                            for f in &rep.findings {
                                sub_card().show(ui, |ui| {
                                    let c = match f.severity {
                                        ReadinessStatus::Ready => {
                                            egui::Color32::from_rgb(74, 222, 128)
                                        }
                                        ReadinessStatus::Warning => {
                                            egui::Color32::from_rgb(250, 204, 21)
                                        }
                                        ReadinessStatus::Blocked => {
                                            egui::Color32::from_rgb(248, 113, 113)
                                        }
                                    };
                                    ui.colored_label(c, format!("{}: {}", f.code, f.message));
                                    ui.add_space(2.0);
                                    ui.weak(&f.remediation);

                                    let btn_label = match f.fix_action {
                                        FixActionKind::UseSuggestedRoot => {
                                            Some("Use Suggested Root")
                                        }
                                        FixActionKind::GenerateParamJson => {
                                            Some("Generate param.json")
                                        }
                                        FixActionKind::IsolateFakelib => Some("Isolate fakelib"),
                                        FixActionKind::None => None,
                                    };
                                    if let Some(lbl) = btn_label {
                                        ui.add_space(6.0);
                                        if ui.small_button(lbl).clicked() {
                                            triggered_fix = Some(f.clone());
                                        }
                                    }
                                });
                                ui.add_space(6.0);
                            }
                        }
                    });
                }
            });

            ui.add_space(12.0);

            ui.vertical(|ui| {
                ui.set_width(col_w);
                panel_card().show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.heading("Target");
                        ui.with_layout(
                            egui::Layout::right_to_left(egui::Align::Center),
                            |ui| {
                                if ui.button("≡ Compare formats").clicked() {
                                    self.tab = ActiveTab::About;
                                }
                            },
                        );
                    });

                    ui.add_space(10.0);
                    ui.horizontal_wrapped(|ui| {
                        for (fmt, lbl) in [
                            (StreamFormat::Folder, "Folder"),
                            (StreamFormat::Zip, "zip"),
                        ] {
                            if ui.selectable_value(&mut self.target_format, fmt, lbl).clicked() {
                                format_changed = true;
                            }
                        }
                    });

                    ui.add_space(6.0);
                    let (hint_col, hint_txt) = match self.target_format {
                        StreamFormat::Zip => (
                            egui::Color32::from_rgb(74, 222, 128),
                            "Standard compressed ZIP archive with atomic .part write and size check.",
                        ),
                        StreamFormat::Folder => (
                            egui::Color32::from_rgb(96, 165, 250),
                            "Clean extracted or copied game directory preserving dump structure.",
                        ),
                        _ => (
                            egui::Color32::from_rgb(148, 163, 184),
                            "Select Folder or zip for supported conversion.",
                        ),
                    };
                    ui.colored_label(hint_col, hint_txt);

                    ui.add_space(12.0);
                    ui.strong("Compression");
                    ui.add_space(4.0);
                    ui.horizontal_wrapped(|ui| {
                        ui.selectable_value(
                            &mut self.compression_profile,
                            CompressionProfile::Fast,
                            "⚡ Fast",
                        );
                        ui.selectable_value(
                            &mut self.compression_profile,
                            CompressionProfile::Balanced,
                            "⚖ Balanced",
                        );
                        ui.selectable_value(
                            &mut self.compression_profile,
                            CompressionProfile::Smallest,
                            "↓ Smallest",
                        );
                        ui.selectable_value(
                            &mut self.compression_profile,
                            CompressionProfile::Stored,
                            "□ Stored",
                        );
                    });

                    if self.target_format == StreamFormat::Ffpfsc {
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            ui.label("Level:");
                            ui.add(egui::Slider::new(&mut self.ffpfsc_level, 0..=9));
                        });
                    }

                    ui.add_space(4.0);
                    ui.colored_label(
                        egui::Color32::from_rgb(74, 222, 128),
                        "Fast provides quick archiving; Balanced or Smallest reduces size further.",
                    );

                    ui.add_space(12.0);
                    sub_card().show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.vertical(|ui| {
                                ui.strong("Full verification");
                                ui.weak("Checks verified output integrity before finishing.");
                            });
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    toggle_switch(ui, &mut self.full_verification);
                                },
                            );
                        });
                    });

                    ui.add_space(8.0);
                    sub_card().show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.vertical(|ui| {
                                ui.strong("Delete the source");
                                ui.weak("No undo. Removes source only after verified completion.");
                            });
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    toggle_switch(ui, &mut self.delete_source);
                                },
                            );
                        });
                    });

                    ui.add_space(12.0);
                    ui.horizontal(|ui| {
                        ui.strong("Output");
                        ui.with_layout(
                            egui::Layout::right_to_left(egui::Align::Center),
                            |ui| {
                                if ui.small_button("Change").clicked() {
                                    self.auto_output_name = false;
                                    if let Some(p) = rfd::FileDialog::new().save_file() {
                                        self.output_input = p.display().to_string();
                                    }
                                }
                            },
                        );
                    });
                    ui.add_space(4.0);
                    sub_card().show(ui, |ui| {
                        if self.output_input.trim().is_empty() {
                            ui.weak("Choose a source first");
                        } else {
                            ui.monospace(&self.output_input);
                        }
                    });

                    ui.add_space(12.0);
                    ui.horizontal(|ui| {
                        if toggle_switch(ui, &mut self.auto_output_name).clicked() {
                            format_changed = true;
                        }
                        ui.strong("Generate name based on content");

                        ui.with_layout(
                            egui::Layout::right_to_left(egui::Align::Center),
                            |ui| {
                                let can_build = !self.target_input.trim().is_empty();
                                if ui
                                    .add_enabled(
                                        can_build,
                                        egui::Button::new(egui::RichText::new("⚡ Build").strong())
                                            .rounding(egui::Rounding::same(14.0)),
                                    )
                                    .clicked()
                                {
                                    should_build = true;
                                }
                            },
                        );
                    });

                    let conv_snapshot = self.conv_state.lock().unwrap().clone();
                    match conv_snapshot {
                        ConversionTaskState::Idle => {}
                        ConversionTaskState::Running { label } => {
                            ui.add_space(8.0);
                            ui.horizontal(|ui| {
                                ui.spinner();
                                ui.colored_label(egui::Color32::from_rgb(147, 197, 253), label);
                            });
                        }
                        ConversionTaskState::Finished(res) => {
                            ui.add_space(8.0);
                            ui.colored_label(
                                egui::Color32::from_rgb(74, 222, 128),
                                format!(
                                    "Done: {:?} -> {:?} ({} B)",
                                    res.source_format, res.target_format, res.bytes_written
                                ),
                            );
                        }
                        ConversionTaskState::Failed(err) => {
                            ui.add_space(8.0);
                            ui.colored_label(egui::Color32::from_rgb(248, 113, 113), err);
                        }
                    }
                });
            });
        });

        if format_changed {
            self.sync_auto_output();
        }
        if let Some(ref f) = triggered_fix {
            self.execute_fix(f);
        }
        if should_analyze {
            self.run_analysis();
        }
        if should_build {
            self.next_job_id += 1;
            self.start_conversion();
        }
    }

    fn ui_edit(&mut self, ui: &mut egui::Ui) {
        let mut staged_rename: Option<(String, String)> = None;
        let mut staged_add: Option<(PathBuf, String)> = None;
        let mut staged_delete: Option<String> = None;
        let mut do_undo = false;
        let mut do_discard = false;
        let mut do_apply = false;
        let mut do_reload = false;

        panel_card().show(ui, |ui| {
            ui.heading("Edit Dump");
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.label("Folder:");
                ui.add(egui::TextEdit::singleline(&mut self.editor_dir_input).desired_width(420.0));
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
                ui.add(egui::TextEdit::singleline(&mut self.editor_rename_to).desired_width(170.0));
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
                ui.strong(format!("Staged: {}", self.editor.pending_ops.len()));
                if ui.button("Undo Last").clicked() {
                    do_undo = true;
                }
                if ui.button("Discard All").clicked() {
                    do_discard = true;
                }
                if ui.button("Apply").clicked() {
                    do_apply = true;
                }
            });

            if let Some(st) = &self.editor_status {
                ui.colored_label(egui::Color32::from_rgb(74, 222, 128), st);
            }

            ui.separator();
            for entry in self.editor.entries.clone() {
                ui.horizontal(|ui| {
                    ui.monospace(&entry.rel_path);
                    if !entry.is_dir {
                        ui.weak(format!("({} B)", entry.size));
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.small_button("Delete").clicked() {
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
                Ok(n) => self.editor_status = Some(format!("Applied {n} change(s).")),
                Err(e) => self.editor_status = Some(format!("Error: {e}")),
            }
        }
    }

    fn ui_pack(&mut self, ui: &mut egui::Ui) {
        let mut do_pack = false;
        let mut do_unpack = false;

        panel_card().show(ui, |ui| {
            ui.heading("Pack (Zstd / LZ4)");
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.label("Source:");
                ui.add(egui::TextEdit::singleline(&mut self.pack_src_input).desired_width(400.0));
                if ui.button("Pick...").clicked() {
                    if let Some(p) = rfd::FileDialog::new().pick_folder() {
                        self.pack_src_input = p.display().to_string();
                    }
                }
            });
            ui.horizontal(|ui| {
                ui.label("Output:");
                ui.add(egui::TextEdit::singleline(&mut self.pack_out_input).desired_width(400.0));
                if ui.button("Pick...").clicked() {
                    if let Some(p) = rfd::FileDialog::new().pick_folder() {
                        self.pack_out_input = p.display().to_string();
                    }
                }
            });
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.pack_codec, AssetCodec::Zstd, "Zstd");
                ui.selectable_value(&mut self.pack_codec, AssetCodec::Lz4, "LZ4");
                if self.pack_codec == AssetCodec::Zstd {
                    ui.add(egui::Slider::new(&mut self.pack_zstd_level, 1..=19));
                }
                if ui.button("Pack").clicked() {
                    do_pack = true;
                }
                if ui.button("Unpack").clicked() {
                    do_unpack = true;
                }
            });

            if let Some(msg) = &self.pack_status {
                ui.add_space(6.0);
                ui.colored_label(egui::Color32::from_rgb(250, 204, 21), msg);
            }
            if let Some(st) = &self.pack_result {
                ui.add_space(6.0);
                ui.label(format!(
                    "Packed: {} | {} B -> {} B | ampr.sprx: {}",
                    st.files_packed, st.original_bytes, st.compressed_bytes, st.has_ampr_sprx
                ));
            }
        });

        if do_pack {
            let src = PathBuf::from(self.pack_src_input.trim());
            let dst = PathBuf::from(self.pack_out_input.trim());
            match pack_game_assets(&src, &dst, self.pack_codec, self.pack_zstd_level) {
                Ok(stats) => {
                    self.pack_status = Some("Packed successfully.".into());
                    self.pack_result = Some(stats);
                }
                Err(e) => self.pack_status = Some(format!("Pack failed: {e}")),
            }
        }
        if do_unpack {
            let src = PathBuf::from(self.pack_src_input.trim());
            let dst = PathBuf::from(self.pack_out_input.trim());
            match unpack_game_assets(&src, &dst) {
                Ok(n) => self.pack_status = Some(format!("Unpacked {n} asset(s).")),
                Err(e) => self.pack_status = Some(format!("Unpack failed: {e}")),
            }
        }
    }

    fn ui_storage(&mut self, ui: &mut egui::Ui) {
        let mut should_scan = false;
        let mut open_in_editor: Option<PathBuf> = None;
        let mut open_in_convert: Option<PathBuf> = None;

        panel_card().show(ui, |ui| {
            ui.heading("Storage Library");
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.label("Folder:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.library_dir_input).desired_width(400.0),
                );
                if ui.button("Pick...").clicked() {
                    if let Some(p) = rfd::FileDialog::new().pick_folder() {
                        self.library_dir_input = p.display().to_string();
                        should_scan = true;
                    }
                }
                if ui.button("Scan").clicked() {
                    should_scan = true;
                }
            });
            ui.horizontal(|ui| {
                ui.label("Filter:");
                ui.add(egui::TextEdit::singleline(&mut self.library_filter).desired_width(240.0));
            });
            if let Some(err) = &self.library_error {
                ui.colored_label(egui::Color32::from_rgb(248, 113, 113), err);
            }
        });

        if should_scan {
            self.run_library_scan();
        }

        if let Some(sum) = &self.library_summary {
            ui.add_space(10.0);
            panel_card().show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.strong(format!("Total: {}", sum.items.len()));
                    ui.colored_label(
                        egui::Color32::from_rgb(74, 222, 128),
                        format!("Ready: {}", sum.ready_count),
                    );
                    ui.colored_label(
                        egui::Color32::from_rgb(250, 204, 21),
                        format!("Warning: {}", sum.warning_count),
                    );
                    ui.colored_label(
                        egui::Color32::from_rgb(248, 113, 113),
                        format!("Blocked: {}", sum.blocked_count),
                    );
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
                    let p_s = it.path.display().to_string().to_ascii_lowercase();
                    title.contains(&q) || p_s.contains(&q)
                }) {
                    sub_card().show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.strong(item.report.metadata.title.as_deref().unwrap_or("Unnamed"));
                            ui.weak(format!("[{:?}]", item.report.status));
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if item.path.is_dir() && ui.small_button("Edit").clicked() {
                                        open_in_editor = Some(item.path.clone());
                                    }
                                    if ui.small_button("Convert").clicked() {
                                        open_in_convert = Some(item.path.clone());
                                    }
                                },
                            );
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
        let mut do_send_elf = false;
        let mut do_add_endpoint = false;
        let mut do_probe_all = false;

        panel_card().show(ui, |ui| {
            ui.heading("PS5 ELF Loader (Port 9021)");
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label("PS5 IP:");
                ui.add(egui::TextEdit::singleline(&mut self.ps5_ip_input).desired_width(140.0));
                ui.label("Port:");
                ui.add(egui::TextEdit::singleline(&mut self.ps5_port_input).desired_width(64.0));
            });
            ui.horizontal(|ui| {
                ui.label("ELF:");
                ui.add(egui::TextEdit::singleline(&mut self.elf_file_input).desired_width(360.0));
                if ui.button("Pick...").clicked() {
                    if let Some(p) = rfd::FileDialog::new()
                        .add_filter("ELF", &["elf", "bin"])
                        .pick_file()
                    {
                        self.elf_file_input = p.display().to_string();
                    }
                }
                if ui.button("Send Payload").clicked() {
                    do_send_elf = true;
                }
            });
        });

        ui.add_space(10.0);
        panel_card().show(ui, |ui| {
            ui.heading("NAS & Peer Endpoints");
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
            if ui.button("Check Connections").clicked() {
                do_probe_all = true;
            }
            if let Some(msg) = &self.net_status_msg {
                ui.add_space(6.0);
                ui.colored_label(egui::Color32::from_rgb(147, 197, 253), msg);
            }
            for (ep, health) in &self.health_results {
                ui.add_space(4.0);
                sub_card().show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.strong(&ep.name);
                        ui.label(format!("{}:{} ({})", ep.host, ep.port, ep.share_or_path));
                        match health {
                            EndpointHealth::Online { latency_ms } => {
                                ui.colored_label(
                                    egui::Color32::from_rgb(74, 222, 128),
                                    format!("ONLINE ({latency_ms} ms)"),
                                );
                            }
                            EndpointHealth::Offline { reason } => {
                                ui.colored_label(
                                    egui::Color32::from_rgb(248, 113, 113),
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
                Ok(()) => self.net_status_msg = Some("Payload sent successfully.".into()),
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

    fn ui_about(&mut self, ui: &mut egui::Ui) {
        panel_card().show(ui, |ui| {
            ui.heading("About & Format Comparison");
            ui.add_space(8.0);
            ui.strong("PS5FileDump (Windows Native Release)");
            ui.weak("Dump pre-flight checker, auto-remediation helper, Zstd/LZ4 asset packer & real Folder/ZIP converter.");
            ui.add_space(10.0);
            sub_card().show(ui, |ui| {
                ui.strong("ZIP (.zip)");
                ui.weak("Standard compressed archive with atomic .part write and byte-count verification.");
            });
            ui.add_space(6.0);
            sub_card().show(ui, |ui| {
                ui.strong("Folder");
                ui.weak("Direct directory copy/extraction preserving param.json, eboot.bin, sce_sys, and fakelib.");
            });
        });
    }
}

pub fn launch_gui() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1180.0, 760.0])
            .with_min_inner_size([920.0, 600.0])
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
