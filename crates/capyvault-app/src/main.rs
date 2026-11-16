use arboard::Clipboard;
use capyvault_core::{
    exchange::{export_csv, export_xlsx, write_export_new, CsvMapping, CsvPreview},
    records::{generate_password, is_weak_password, Credential},
    storage::{StorageError, VaultSession},
    RecoveryKey, Unlock,
};
use eframe::egui::{self, Color32, RichText, Vec2};
use std::{
    collections::BTreeSet,
    path::PathBuf,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

const INK: Color32 = Color32::from_rgb(35, 48, 46);
const MUTED: Color32 = Color32::from_rgb(117, 132, 127);
const GREEN: Color32 = Color32::from_rgb(35, 126, 96);
const MINT: Color32 = Color32::from_rgb(224, 243, 234);
const CREAM: Color32 = Color32::from_rgb(249, 248, 242);
const GOLD: Color32 = Color32::from_rgb(220, 157, 70);

fn main() -> eframe::Result<()> {
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1240., 800.])
            .with_min_inner_size([920., 620.]),
        ..Default::default()
    };
    eframe::run_native(
        "CapyVault",
        opts,
        Box::new(|cc| {
            style(&cc.egui_ctx);
            Ok(Box::new(CapyApp::default()))
        }),
    )
}
fn style(ctx: &egui::Context) {
    let mut v = egui::Visuals::light();
    v.panel_fill = CREAM;
    v.window_fill = Color32::WHITE;
    v.override_text_color = Some(INK);
    v.widgets.inactive.bg_fill = Color32::from_rgb(239, 241, 235);
    v.widgets.hovered.bg_fill = MINT;
    v.widgets.active.bg_fill = GREEN;
    v.selection.bg_fill = GREEN;
    v.selection.stroke = egui::Stroke::new(1.0_f32, GREEN);
    ctx.set_visuals(v);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    All,
    Audit,
    Backups,
    Settings,
}
struct ImportState {
    bytes: Zeroizing<Vec<u8>>,
    mapping: CsvMapping,
    preview: CsvPreview,
}
struct CapyApp {
    session: Option<VaultSession>,
    path: Option<PathBuf>,
    creating: bool,
    password: Zeroizing<String>,
    confirm: Zeroizing<String>,
    recovery_input: Zeroizing<String>,
    use_recovery: bool,
    recovery_once: Option<Zeroizing<String>>,
    recovery_ack: bool,
    search: String,
    category: Option<String>,
    section: Section,
    selected: Option<String>,
    editor: Option<Credential>,
    editor_id: Option<String>,
    tags: String,
    recovery_methods: String,
    visible_password: bool,
    edit_password_visible: bool,
    show_generator: bool,
    generated: Zeroizing<String>,
    auto_lock_minutes: u64,
    auto_backup: bool,
    import: Option<ImportState>,
    export_confirm: Option<bool>,
    confirm_restore: Option<PathBuf>,
    confirm_delete: Option<String>,
    status: String,
    error: Option<String>,
    dirty: bool,
    usb_missing: bool,
    last_activity: Instant,
    show_exit_prompt: bool,
}
impl Default for CapyApp {
    fn default() -> Self {
        Self {
            session: None,
            path: None,
            creating: false,
            password: Zeroizing::new(String::new()),
            confirm: Zeroizing::new(String::new()),
            recovery_input: Zeroizing::new(String::new()),
            use_recovery: false,
            recovery_once: None,
            recovery_ack: false,
            search: String::new(),
            category: None,
            section: Section::All,
            selected: None,
            editor: None,
            editor_id: None,
            tags: String::new(),
            recovery_methods: String::new(),
            visible_password: false,
            edit_password_visible: false,
            show_generator: false,
            generated: Zeroizing::new(String::new()),
            auto_lock_minutes: 5,
            auto_backup: true,
            import: None,
            export_confirm: None,
            confirm_restore: None,
            confirm_delete: None,
            status: String::new(),
            error: None,
            dirty: false,
            usb_missing: false,
            last_activity: Instant::now(),
            show_exit_prompt: false,
        }
    }
}

impl eframe::App for CapyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if ctx.input(|i| !i.events.is_empty()) {
            self.last_activity = Instant::now();
        }
        let missing = self.session.is_some() && self.path.as_ref().is_some_and(|p| !p.exists());
        if missing && !self.usb_missing && self.error.is_none() {
            self.error = Some(
                "El archivo de la bóveda no está disponible. Comprueba el USB antes de guardar."
                    .into(),
            );
        }
        self.usb_missing = missing;
        if self.session.is_some()
            && self.auto_lock_minutes > 0
            && self.last_activity.elapsed() > Duration::from_secs(self.auto_lock_minutes * 60)
        {
            if self.dirty {
                match self.save() {
                    Ok(()) => self.lock(),
                    Err(e) => {
                        self.error = Some(format!("No se pudo guardar antes del bloqueo: {e}"))
                    }
                }
            } else {
                self.lock();
            }
        }
        ctx.request_repaint_after(Duration::from_secs(1));
        if ctx.input(|i| i.key_pressed(egui::Key::L) && i.modifiers.ctrl) && self.session.is_some()
        {
            self.lock();
        }
        self.draw_top(ctx);
        if self.session.is_none() {
            self.draw_gate(ctx);
        } else if self.recovery_once.is_some() {
            self.draw_recovery_once(ctx);
        } else {
            self.draw_vault(ctx);
        }
        self.draw_overlays(ctx);
        if ctx.input(|i| i.viewport().close_requested()) && (self.dirty || self.editor.is_some()) {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.show_exit_prompt = true;
        }
    }
}

impl CapyApp {
    fn draw_top(&self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("top")
            .frame(
                egui::Frame::new()
                    .fill(Color32::WHITE)
                    .inner_margin(egui::Margin::symmetric(22, 12)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    capy_mark(ui, 32.);
                    ui.add_space(8.);
                    ui.heading(RichText::new("CapyVault").size(23.).strong().color(INK));
                    ui.label(RichText::new("· tu espacio seguro").color(MUTED));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if self.session.is_some() && ui.button("⏻  Bloquear").clicked() {
                            ui.ctx()
                                .data_mut(|d| d.insert_temp(egui::Id::new("lock_now"), true));
                        }
                    });
                });
            });
    }
    fn draw_gate(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().frame(egui::Frame::new().fill(CREAM).inner_margin(30.)).show(ctx,|ui|{
   ui.add_space(22.);ui.horizontal(|ui|{ui.add_space(80.);ui.vertical(|ui|{ui.label(RichText::new("Cuentas bajo llave.\nTranquilidad a mano.").size(32.).strong().color(INK));ui.add_space(12.);ui.label(RichText::new("Una bóveda cifrada que viaja contigo, sin cuentas en línea ni sincronización obligatoria.").size(16.).color(MUTED));ui.add_space(28.);
    if self.path.is_none(){ui.label(RichText::new("EMPIEZA CON TU BÓVEDA").size(11.).strong().color(GREEN));ui.add_space(8.);ui.horizontal(|ui|{if primary(ui,"＋  Crear bóveda nueva").clicked(){self.creating=true;}if ui.button("Abrir archivo .capyvault").clicked(){self.pick_existing();}});if self.creating{ui.add_space(12.);ui.label("Contraseña maestra (mínimo 12 caracteres)");ui.add(egui::TextEdit::singleline(&mut *self.password).password(true).desired_width(410.));ui.label("Repite la contraseña");ui.add(egui::TextEdit::singleline(&mut *self.confirm).password(true).desired_width(410.));if primary(ui,"Elegir ubicación y crear").clicked(){self.create_vault();}}ui.add_space(14.);let drives=removable_roots();if !drives.is_empty(){ui.label(RichText::new("Unidades extraíbles detectadas").color(MUTED));ui.horizontal_wrapped(|ui|for p in drives{if ui.button(format!("▣  {}",p.display())).clicked(){self.path=Some(p.join("CapyVault").join("Main.capyvault"));}});}}
    else{ui.horizontal(|ui|{ui.label(RichText::new("BÓVEDA").size(11.).strong().color(GREEN));if ui.small_button("Cambiar archivo").clicked(){self.pick_existing();}});ui.label(RichText::new(self.path.as_ref().unwrap().display().to_string()).color(MUTED));ui.add_space(14.);
     if self.use_recovery{ui.label("Clave de recuperación");ui.add(egui::TextEdit::singleline(&mut *self.recovery_input).password(true).desired_width(410.).hint_text("Pega tu clave de recuperación"));}
     else{ui.label("Contraseña maestra");ui.add(egui::TextEdit::singleline(&mut *self.password).password(true).desired_width(410.).hint_text("Escribe tu contraseña"));}
     ui.add_space(8.);if primary(ui,"Desbloquear bóveda").clicked(){self.unlock_vault();}ui.add_space(8.);if ui.link(if self.use_recovery{"Usar contraseña maestra"}else{"Desbloquear con clave de recuperación"}).clicked(){self.use_recovery=!self.use_recovery;}
    }
    if self.path.is_none(){ui.add_space(12.);ui.label(RichText::new("CapyVault crea y modifica solo sus propios archivos.").size(12.).color(MUTED));}
   });ui.add_space(40.);ui.vertical_centered(|ui|{capy_illustration(ui);ui.add_space(8.);ui.label(RichText::new("Todo queda en tu dispositivo. Siempre.").color(MUTED));});});
  });
    }
    fn draw_recovery_once(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().frame(egui::Frame::new().fill(CREAM).inner_margin(32.)).show(ctx,|ui|{ui.vertical_centered(|ui|{ui.add_space(60.);capy_mark(ui,52.);ui.add_space(16.);ui.heading(RichText::new("Guarda esta clave de recuperación").size(28.).strong());ui.add_space(8.);ui.label("Se muestra una sola vez. Consérvala fuera del USB; permite abrir esta bóveda si olvidas la contraseña.");ui.add_space(18.);egui::Frame::new().fill(Color32::WHITE).corner_radius(12.).inner_margin(20.).show(ui,|ui|{ui.add(egui::TextEdit::multiline(&mut **self.recovery_once.as_mut().unwrap()).desired_width(540.).desired_rows(2).font(egui::TextStyle::Monospace));ui.horizontal(|ui|{if ui.button("Copiar clave").clicked(){let key=Zeroizing::new(self.recovery_once.as_ref().unwrap().to_string());self.copy_secret(&key);}ui.label("Cópiala en un lugar seguro separado del USB.");});});ui.add_space(14.);ui.checkbox(&mut self.recovery_ack,"He guardado la clave fuera de esta ubicación.");if primary(ui,"Continuar").clicked()&&self.recovery_ack{self.recovery_once=None;self.status="Bóveda creada. Añade tu primera cuenta.".into();}});});
    }
    fn draw_vault(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("sidebar")
            .resizable(false)
            .exact_width(224.)
            .frame(egui::Frame::new().fill(Color32::WHITE).inner_margin(16.))
            .show(ctx, |ui| {
                ui.add_space(6.);
                ui.label(RichText::new("TU ESPACIO").size(10.).strong().color(MUTED));
                ui.add_space(10.);
                for (s, label, ico) in [
                    (Section::All, "Todas las cuentas", "▦"),
                    (Section::Audit, "Revisión de seguridad", "◈"),
                    (Section::Backups, "Copias de seguridad", "◷"),
                    (Section::Settings, "Ajustes", "⚙"),
                ] {
                    if nav_item(ui, self.section == s, ico, label).clicked() {
                        self.section = s;
                        self.editor = None;
                        self.import = None;
                    }
                }
                ui.add_space(24.);
                ui.label(RichText::new("CATEGORÍAS").size(10.).strong().color(MUTED));
                ui.add_space(8.);
                if let Some(session) = &self.session {
                    let cats: BTreeSet<String> = session
                        .data()
                        .records
                        .iter()
                        .map(|r| r.category.clone())
                        .collect();
                    for cat in cats {
                        if ui
                            .selectable_label(
                                self.category.as_deref() == Some(&cat),
                                format!("◦  {cat}"),
                            )
                            .clicked()
                        {
                            self.category = Some(cat);
                            self.section = Section::All;
                        }
                    }
                }
                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    ui.separator();
                    ui.label(RichText::new("Modo sin conexión").size(12.).color(GREEN));
                    ui.label(
                        RichText::new("Sin telemetría · sin cuenta")
                            .size(11.)
                            .color(MUTED),
                    );
                });
            });
        egui::TopBottomPanel::bottom("status")
            .frame(
                egui::Frame::new()
                    .fill(Color32::WHITE)
                    .inner_margin(egui::Margin::symmetric(18, 7)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("●").color(if self.dirty { GOLD } else { GREEN }));
                    ui.label(
                        RichText::new(if self.dirty {
                            "Cambios sin guardar"
                        } else if self.status.is_empty() {
                            "Bóveda cifrada"
                        } else {
                            &self.status
                        })
                        .size(12.)
                        .color(MUTED),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if self.dirty && ui.button("Guardar cambios").clicked() {
                            if let Err(e) = self.save() {
                                self.error = Some(e.to_string());
                            }
                        }
                        if let Some(p) = &self.path {
                            ui.label(
                                RichText::new(p.display().to_string())
                                    .size(11.)
                                    .color(MUTED),
                            );
                        }
                    });
                });
            });
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(CREAM).inner_margin(20.))
            .show(ctx, |ui| {
                if self.editor.is_some() {
                    self.draw_editor(ui);
                    return;
                }
                if self.import.is_some() {
                    self.draw_import(ui);
                    return;
                }
                match self.section {
                    Section::All => self.draw_accounts(ui),
                    Section::Audit => self.draw_audit(ui),
                    Section::Backups => self.draw_backups(ui),
                    Section::Settings => self.draw_settings(ui),
                }
            });
    }
    fn draw_accounts(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.heading(
                    RichText::new(self.category.as_deref().unwrap_or("Todas las cuentas"))
                        .size(27.)
                        .strong(),
                );
                ui.label(
                    RichText::new(format!(
                        "{} registros guardados en tu bóveda",
                        self.session.as_ref().unwrap().data().records.len()
                    ))
                    .color(MUTED),
                );
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if primary(ui, "＋  Nueva cuenta").clicked() {
                    self.start_editor(None);
                }
                if ui.button("Importar CSV").clicked() {
                    self.pick_csv();
                }
            });
        });
        ui.add_space(18.);
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.search)
                    .desired_width(320.)
                    .hint_text("⌕  Buscar cuenta, usuario o etiqueta…"),
            );
            if ui.button("⤓ Exportar").clicked() {
                self.export_confirm = Some(false);
            }
            if ui.button("⤴ Copia cifrada").clicked() {
                self.export_vault();
            }
        });
        let session = self.session.as_ref().unwrap();
        let indices = session
            .data()
            .search_indices(&self.search, self.category.as_deref());
        let selected = self.selected.clone();
        ui.add_space(12.);
        ui.columns(2,|cols|{
   egui::ScrollArea::vertical().show(&mut cols[0],|ui|{if indices.is_empty(){ui.add_space(32.);ui.label(RichText::new("No encontramos coincidencias.").color(MUTED));}for idx in indices{let r=&self.session.as_ref().unwrap().data().records[idx];let active=selected.as_deref()==Some(&r.id);let title=if r.service.is_empty(){"Cuenta sin nombre"}else{&r.service};egui::Frame::new().fill(if active{MINT}else{Color32::WHITE}).corner_radius(10.).inner_margin(12.).show(ui,|ui|{ui.horizontal(|ui|{ui.label(RichText::new("◉").size(22.).color(GREEN));ui.vertical(|ui|{ui.label(RichText::new(title).strong());ui.label(RichText::new(if r.username.is_empty(){&r.url}else{&r.username}).size(12.).color(MUTED));});if ui.button("›").clicked(){self.selected=Some(r.id.clone());}});});ui.add_space(6.);}});
    cols[1].vertical(|ui|{
     if let Some(id)=self.selected.clone(){
      let record=self.session.as_ref().unwrap().data().records.iter().find(|r|r.id==id).map(Credential::copy_for_edit);
      if let Some(r)=record{egui::Frame::new().fill(Color32::WHITE).corner_radius(14.).inner_margin(20.).show(ui,|ui|{
       ui.horizontal(|ui|{ui.vertical(|ui|{ui.label(RichText::new(&r.category.to_uppercase()).size(10.).strong().color(GREEN));ui.heading(RichText::new(if r.service.is_empty(){"Cuenta"}else{&r.service}).size(24.).strong());});ui.with_layout(egui::Layout::right_to_left(egui::Align::Center),|ui|{if ui.button("Eliminar").clicked(){self.confirm_delete=Some(r.id.clone());}if ui.button("Editar").clicked(){self.start_editor(Some(&r.id));}});});
       ui.add_space(16.);field(ui,"Usuario",&r.username);if !r.username.is_empty()&&ui.small_button("Copiar usuario").clicked(){self.copy_string(&r.username);}
       ui.add_space(10.);ui.horizontal(|ui|{ui.label(RichText::new("CONTRASEÑA").size(10.).strong().color(MUTED));ui.with_layout(egui::Layout::right_to_left(egui::Align::Center),|ui|{if ui.small_button(if self.visible_password{"Ocultar"}else{"Mostrar"}).clicked(){self.visible_password=!self.visible_password;}if ui.small_button("Copiar").clicked()&&!r.password.is_empty(){self.copy_string(&r.password);}});});
       if self.visible_password{ui.label(&r.password);}else{ui.label("••••••••••••");}
       ui.add_space(12.);field(ui,"Sitio web",&r.url);field(ui,"Correo asociado",&r.email);field(ui,"Etiquetas",&r.tags.join(" · "));if !r.notes.is_empty(){ui.add_space(8.);ui.label(RichText::new("NOTAS").size(10.).strong().color(MUTED));ui.label(&r.notes);}
       if !r.recovery_methods.is_empty(){ui.add_space(8.);field(ui,"Recuperación",&r.recovery_methods.join(" · "));}if !r.totp_secret.is_empty(){ui.add_space(8.);field(ui,"Autenticación 2FA",&r.totp_secret);}
       for custom in &r.custom_fields{ui.add_space(6.);field(ui,&custom.name,if custom.secret{"••••••••"}else{&custom.value});}
       if is_weak_password(&r.password)&&!r.password.is_empty(){ui.add_space(12.);ui.label(RichText::new("◇  Esta contraseña puede ser débil; revisa la auditoría.").color(Color32::from_rgb(174,111,35)));}
       ui.add_space(14.);ui.label(RichText::new(format!("Actualizado {}",r.modified_at)).size(11.).color(MUTED));
      });}else{ui.centered_and_justified(|ui|{ui.label(RichText::new("Elige una cuenta para ver sus datos.").color(MUTED));});}
     }
    });
  });
    }
    fn draw_editor(&mut self, ui: &mut egui::Ui) {
        let mut record = self.editor.take().unwrap();
        let mut canceled = false;
        let mut save_clicked = false;
        ui.horizontal(|ui| {
            ui.heading(if self.editor_id.is_some() {
                "Editar cuenta"
            } else {
                "Nueva cuenta"
            });
            if ui.button("Cerrar").clicked() {
                canceled = true;
            }
        });
        if canceled {
            self.tags.zeroize();
            self.recovery_methods.zeroize();
            self.editor_id = None;
            return;
        }
        ui.add_space(8.);
        ui.label(RichText::new("Los cambios se guardan cifrados en la bóveda.").color(MUTED));
        ui.columns(2, |cols| {
            text_field(
                &mut cols[0],
                "Servicio",
                "Ej. Correo personal",
                &mut record.service,
            );
            text_field(&mut cols[0], "Nombre de usuario", "", &mut record.username);
            cols[0].label(RichText::new("Contraseña").size(12.).strong());
            cols[0].horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut record.password)
                        .password(!self.edit_password_visible)
                        .desired_width(290.)
                        .hint_text("Puede dejarse en blanco"),
                );
                if ui
                    .small_button(if self.edit_password_visible {
                        "Ocultar"
                    } else {
                        "Mostrar"
                    })
                    .clicked()
                {
                    self.edit_password_visible = !self.edit_password_visible;
                }
            });
            if cols[0].button("Generar contraseña segura").clicked() {
                self.generated = Zeroizing::new(
                    generate_password(24, true, true, true, true).unwrap_or_default(),
                );
                self.show_generator = true;
            }
            text_field(&mut cols[1], "URL", "https://…", &mut record.url);
            text_field(&mut cols[1], "Correo asociado", "", &mut record.email);
            text_field(&mut cols[1], "Categoría", "General", &mut record.category);
            text_field(
                &mut cols[1],
                "Etiquetas",
                "Separadas por comas",
                &mut self.tags,
            );
            text_field(
                &mut cols[1],
                "Métodos de recuperación",
                "Uno por línea",
                &mut self.recovery_methods,
            );
        });
        ui.label("Notas");
        ui.add(
            egui::TextEdit::multiline(&mut record.notes)
                .desired_rows(4)
                .desired_width(f32::INFINITY),
        );
        ui.horizontal(|ui| {
            ui.label("Clave 2FA/TOTP");
            ui.add(
                egui::TextEdit::singleline(&mut record.totp_secret)
                    .password(true)
                    .desired_width(280.),
            );
        });
        ui.add_space(10.);
        ui.label(RichText::new("Campos personalizados").size(12.).strong());
        for field in &mut record.custom_fields {
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut field.name)
                        .desired_width(170.)
                        .hint_text("Nombre"),
                );
                ui.add(
                    egui::TextEdit::singleline(&mut field.value)
                        .desired_width(280.)
                        .password(field.secret)
                        .hint_text("Valor"),
                );
                ui.checkbox(&mut field.secret, "Oculto");
            });
        }
        if ui.small_button("＋ Añadir campo").clicked() {
            record
                .custom_fields
                .push(capyvault_core::records::CustomField::default());
        }
        ui.add_space(14.);
        ui.horizontal(|ui| {
            if primary(ui, "Guardar en la bóveda").clicked() {
                save_clicked = true;
            }
            if ui.button("Cancelar").clicked() {
                canceled = true;
            }
        });
        if save_clicked {
            record.tags = self
                .tags
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect();
            record.recovery_methods = self
                .recovery_methods
                .lines()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect();
            let result = if let Some(id) = &self.editor_id {
                self.session.as_mut().unwrap().update(id, record)
            } else {
                self.session.as_mut().unwrap().add(record)
            };
            match result {
                Ok(()) => {
                    self.dirty = true;
                    self.editor_id = None;
                    self.tags.zeroize();
                    self.recovery_methods.zeroize();
                    self.status = "Cuenta actualizada. Guarda para escribirla en el USB.".into();
                }
                Err(e) => self.error = Some(e.to_string()),
            }
        } else if canceled {
            self.editor_id = None;
            self.tags.zeroize();
            self.recovery_methods.zeroize();
        } else {
            self.editor = Some(record);
        }
    }
    fn draw_audit(&mut self, ui: &mut egui::Ui) {
        let data = self.session.as_ref().unwrap().data();
        ui.heading("Revisión de seguridad");
        ui.label(
            RichText::new("Comprobación local. Tus contraseñas no salen de la bóveda.")
                .color(MUTED),
        );
        ui.add_space(14.);
        let weak = data.weak_password_indices();
        let duplicate = data.duplicate_pairs();
        ui.horizontal(|ui| {
            metric(ui, "Contraseñas débiles", weak.len(), GOLD);
            metric(
                ui,
                "Duplicados",
                duplicate.len(),
                if duplicate.is_empty() { GREEN } else { GOLD },
            );
        });
        ui.add_space(16.);
        if weak.is_empty() && duplicate.is_empty() {
            ui.label("✓  No hay avisos en las cuentas guardadas.");
        }
        for i in weak {
            let r = &data.records[i];
            ui.label(
                RichText::new(format!("◇  {} — contraseña débil o vacía", r.service))
                    .color(Color32::from_rgb(174, 111, 35)),
            );
        }
        for (a, b) in duplicate {
            ui.label(
                RichText::new(format!(
                    "⟲  Posible duplicado: {} / {}",
                    data.records[a].service, data.records[b].service
                ))
                .color(Color32::from_rgb(174, 111, 35)),
            );
        }
    }
    fn draw_backups(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Copias de seguridad");
            if primary(ui, "Crear copia ahora").clicked() {
                match self.session.as_ref().unwrap().create_backup() {
                    Ok(p) => self.status = format!("Copia cifrada creada: {}", p.display()),
                    Err(e) => self.error = Some(e.to_string()),
                }
            }
        });
        ui.add_space(8.);
        ui.label(
            RichText::new(
                "Las copias conservan el formato cifrado original. No se eliminan automáticamente.",
            )
            .color(MUTED),
        );
        let backups = self.session.as_ref().unwrap().list_backups();
        match backups {
            Ok(list) => {
                if list.is_empty() {
                    ui.add_space(20.);
                    ui.label("Todavía no hay copias anteriores.");
                }
                for p in list {
                    egui::Frame::new()
                        .fill(Color32::WHITE)
                        .corner_radius(8.)
                        .inner_margin(12.)
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(p.file_name().unwrap_or_default().to_string_lossy());
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if ui.button("Restaurar…").clicked() {
                                            self.confirm_restore = Some(p.clone());
                                        }
                                    },
                                );
                            });
                        });
                }
            }
            Err(e) => self.error = Some(e.to_string()),
        }
    }
    fn draw_settings(&mut self, ui: &mut egui::Ui) {
        ui.heading("Ajustes");
        ui.label(RichText::new("Preferencias de esta sesión.").color(MUTED));
        ui.add_space(16.);
        ui.horizontal(|ui| {
            ui.label("Bloqueo por inactividad");
            egui::ComboBox::from_id_salt("auto_lock")
                .selected_text(format!("{} min", self.auto_lock_minutes))
                .show_ui(ui, |ui| {
                    for (v, t) in [
                        (1, "1 minuto"),
                        (5, "5 minutos"),
                        (10, "10 minutos"),
                        (15, "15 minutos"),
                        (0, "Desactivado"),
                    ] {
                        ui.selectable_value(&mut self.auto_lock_minutes, v, t);
                    }
                });
        });
        ui.checkbox(
            &mut self.auto_backup,
            "Crear una copia cifrada antes de cada guardado",
        );
        self.session
            .as_mut()
            .unwrap()
            .set_auto_backup(self.auto_backup);
        ui.add_space(14.);
        ui.label(RichText::new("La bóveda se bloquea al cerrar la aplicación. No se guardan contraseñas en ajustes ni en registros de diagnóstico.").color(MUTED));
    }
    fn draw_import(&mut self, ui: &mut egui::Ui) {
        let mut cancel = false;
        let commit;
        {
            let state = self.import.as_mut().unwrap();
            ui.horizontal(|ui| {
                ui.heading("Vista previa de importación");
                if ui.button("Cancelar").clicked() {
                    cancel = true;
                }
            });
            ui.label(format!(
                "{} filas · {} seleccionadas · los duplicados se dejan desmarcados",
                state.preview.candidates.len(),
                state.preview.selected_count()
            ));
            let fields = [
                ("Servicio", 0),
                ("Usuario", 1),
                ("Contraseña", 2),
                ("URL", 3),
                ("Correo", 4),
                ("Categoría", 5),
                ("Notas", 6),
                ("2FA", 7),
            ];
            for (name, k) in fields {
                ui.horizontal(|ui| {
                    ui.label(name);
                    let slot = match k {
                        0 => &mut state.mapping.service,
                        1 => &mut state.mapping.username,
                        2 => &mut state.mapping.password,
                        3 => &mut state.mapping.url,
                        4 => &mut state.mapping.email,
                        5 => &mut state.mapping.category,
                        6 => &mut state.mapping.notes,
                        _ => &mut state.mapping.totp,
                    };
                    let before = *slot;
                    let selected = slot
                        .and_then(|i| state.preview.headers.get(i))
                        .map(String::as_str)
                        .unwrap_or("— sin asignar —");
                    egui::ComboBox::from_id_salt(("map", k))
                        .selected_text(selected)
                        .show_ui(ui, |ui| {
                            ui.selectable_value(slot, None, "— sin asignar —");
                            for (i, h) in state.preview.headers.iter().enumerate() {
                                ui.selectable_value(slot, Some(i), h);
                            }
                        });
                    if *slot != before {
                        match CsvPreview::parse(
                            &state.bytes,
                            &self.session.as_ref().unwrap().data(),
                            &state.mapping,
                        ) {
                            Ok(p) => state.preview = p,
                            Err(e) => self.error = Some(e.to_string()),
                        }
                    }
                });
            }
            ui.horizontal(|ui| {
                if ui.small_button("Seleccionar todo").clicked() {
                    state.preview.select_all(true);
                }
                if ui.small_button("Deseleccionar todo").clicked() {
                    state.preview.select_all(false);
                }
            });
            egui::ScrollArea::vertical()
                .max_height(390.)
                .show(ui, |ui| {
                    for c in &mut state.preview.candidates {
                        ui.horizontal(|ui| {
                            ui.checkbox(&mut c.selected, "");
                            ui.label(if c.credential.service.is_empty() {
                                "(sin nombre)"
                            } else {
                                &c.credential.service
                            });
                            ui.label(RichText::new(&c.credential.username).color(MUTED));
                            ui.label(if c.duplicate {
                                RichText::new("Duplicado").color(GOLD)
                            } else {
                                RichText::new("Nuevo").color(GREEN)
                            });
                        });
                    }
                });
            commit = primary(ui, "Importar registros seleccionados").clicked();
        }
        if cancel {
            self.import = None;
        } else if commit {
            let state = self.import.take().unwrap();
            match state
                .preview
                .commit(self.session.as_mut().unwrap().data_mut())
            {
                Ok(n) => {
                    self.dirty = true;
                    self.status =
                        format!("{n} registros importados. Guarda los cambios para cifrarlos.");
                }
                Err(e) => self.error = Some(e.to_string()),
            }
        }
    }
    fn draw_overlays(&mut self, ctx: &egui::Context) {
        if ctx.data(|d| {
            d.get_temp::<bool>(egui::Id::new("lock_now"))
                .unwrap_or(false)
        }) {
            ctx.data_mut(|d| d.remove::<bool>(egui::Id::new("lock_now")));
            self.lock();
        }
        if let Some(message) = self.error.clone() {
            egui::Window::new("CapyVault · aviso")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
                .show(ctx, |ui| {
                    ui.label(message);
                    if primary(ui, "Entendido").clicked() {
                        self.error = None;
                    }
                });
        }
        if self.show_generator {
            egui::Window::new("Generador seguro")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label("Contraseña aleatoria · 24 caracteres");
                    ui.add(
                        egui::TextEdit::singleline(&mut *self.generated)
                            .password(true)
                            .desired_width(300.),
                    );
                    ui.horizontal(|ui| {
                        if ui.button("Regenerar").clicked() {
                            self.generated = Zeroizing::new(
                                generate_password(24, true, true, true, true).unwrap_or_default(),
                            );
                        }
                        if ui.button("Copiar").clicked() {
                            let copy = Zeroizing::new(self.generated.to_string());
                            self.copy_secret(&copy);
                        }
                        if primary(ui, "Usar y cerrar").clicked() {
                            if let Some(record) = self.editor.as_mut() {
                                record.password = self.generated.to_string();
                            }
                            self.show_generator = false;
                        }
                    });
                });
        }
        if let Some(confirm) = self.export_confirm {
            egui::Window::new("Exportar en texto legible").collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER,Vec2::ZERO).show(ctx,|ui|{ui.label("CSV y XLSX pueden dejar tus contraseñas visibles para cualquier persona que abra el archivo.");ui.checkbox(&mut self.export_confirm.as_mut().unwrap(),"Entiendo que el archivo exportado no estará cifrado.");ui.horizontal(|ui|{if primary(ui,"Continuar…").clicked()&&self.export_confirm==Some(true){self.export_confirm=None;self.perform_export();}if ui.button("Cancelar").clicked(){self.export_confirm=None;}});});
            let _ = confirm;
        }
        if self.show_exit_prompt {
            egui::Window::new("Cambios sin guardar")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
                .show(ctx, |ui| {
                    ui.label("¿Quieres guardar las modificaciones antes de cerrar?");
                    ui.horizontal(|ui| {
                        if primary(ui, "Guardar y cerrar").clicked() {
                            match self.save() {
                                Ok(()) => {
                                    self.show_exit_prompt = false;
                                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                                }
                                Err(e) => self.error = Some(e.to_string()),
                            }
                        }
                        if ui.button("Descartar y cerrar").clicked() {
                            self.dirty = false;
                            self.session = None;
                            self.show_exit_prompt = false;
                            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                        if ui.button("Seguir aquí").clicked() {
                            self.show_exit_prompt = false;
                        }
                    });
                });
        }
        if let Some(path) = self.confirm_restore.clone() {
            egui::Window::new("Restaurar copia")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
                .show(ctx, |ui| {
                    ui.label(
                        "El contenido actual se conservará como copia cifrada antes de restaurar.",
                    );
                    ui.horizontal(|ui| {
                        if primary(ui, "Restaurar versión").clicked() {
                            match self.session.as_mut().unwrap().restore_backup(&path) {
                                Ok(()) => {
                                    self.dirty = false;
                                    self.status = "Versión anterior restaurada.".into();
                                }
                                Err(e) => self.error = Some(e.to_string()),
                            }
                            self.confirm_restore = None;
                        }
                        if ui.button("Cancelar").clicked() {
                            self.confirm_restore = None;
                        }
                    });
                });
        }
        if let Some(id) = self.confirm_delete.clone() {
            egui::Window::new("Eliminar cuenta")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
                .show(ctx, |ui| {
                    ui.label("La cuenta se eliminará de la próxima versión guardada de la bóveda.");
                    ui.horizontal(|ui| {
                        if primary(ui, "Eliminar cuenta").clicked() {
                            match self.session.as_mut().unwrap().delete(&id) {
                                Ok(()) => {
                                    self.dirty = true;
                                    self.selected = None;
                                    self.status =
                                        "Cuenta eliminada de la sesión. Guarda los cambios.".into();
                                }
                                Err(e) => self.error = Some(e.to_string()),
                            }
                            self.confirm_delete = None;
                        }
                        if ui.button("Cancelar").clicked() {
                            self.confirm_delete = None;
                        }
                    });
                });
        }
    }
    fn save(&mut self) -> Result<(), StorageError> {
        let s = self
            .session
            .as_mut()
            .ok_or_else(|| StorageError::Data("vault locked".into()))?;
        s.set_auto_backup(self.auto_backup);
        s.save()?;
        self.dirty = false;
        self.status = "Guardado verificado y cifrado".into();
        Ok(())
    }
    fn lock(&mut self) {
        if self.dirty {
            if let Err(e) = self.save() {
                self.error = Some(format!("No se pudo guardar; la bóveda sigue abierta. {e}"));
                return;
            }
        }
        self.session = None;
        self.selected = None;
        self.search.clear();
        self.password.zeroize();
        self.confirm.zeroize();
        self.recovery_input.zeroize();
        self.generated.zeroize();
        self.editor = None;
        self.editor_id = None;
        self.tags.zeroize();
        self.recovery_methods.zeroize();
        self.import = None;
        self.visible_password = false;
        self.last_activity = Instant::now();
        self.status = "Bóveda bloqueada".into();
    }
    fn pick_existing(&mut self) {
        if let Some(p) = rfd::FileDialog::new()
            .add_filter("CapyVault", &["capyvault"])
            .pick_file()
        {
            self.path = Some(p);
            self.creating = false;
            self.use_recovery = false;
        }
    }
    fn create_vault(&mut self) {
        if self.password.len() < 12 {
            self.error = Some("Elige una contraseña maestra de al menos 12 caracteres.".into());
            return;
        }
        if self.password.as_str() != self.confirm.as_str() {
            self.error = Some("Las contraseñas no coinciden.".into());
            return;
        }
        if let Some(folder) = rfd::FileDialog::new()
            .set_title("Elige dónde crear tu carpeta CapyVault")
            .pick_folder()
        {
            let dir = folder.join("CapyVault");
            if let Err(e) = std::fs::create_dir_all(&dir) {
                self.error = Some(e.to_string());
                return;
            }
            let p = dir.join("Main.capyvault");
            match VaultSession::create(&p, self.password.as_bytes()) {
                Ok((s, r)) => {
                    self.path = Some(p);
                    self.recovery_once = Some(Zeroizing::new(r.encode()));
                    self.session = Some(s);
                    self.password.zeroize();
                    self.confirm.zeroize();
                }
                Err(e) => self.error = Some(e.to_string()),
            }
        }
    }
    fn unlock_vault(&mut self) {
        let Some(p) = self.path.clone() else { return };
        let result = if self.use_recovery {
            RecoveryKey::decode(&self.recovery_input).and_then(|k| {
                VaultSession::open(&p, Unlock::Recovery(&k))
                    .map_err(|_| capyvault_core::VaultError::Crypto)
            })
        } else {
            VaultSession::open(&p, Unlock::MasterPassword(self.password.as_bytes()))
                .map_err(|_| capyvault_core::VaultError::Crypto)
        };
        match result {
            Ok(s) => {
                self.session = Some(s);
                self.password.zeroize();
                self.recovery_input.zeroize();
                self.dirty = false;
                self.selected = None;
                self.status = "Bóveda desbloqueada".into();
                self.last_activity = Instant::now();
            }
            Err(_) => self.error = Some(
                "No se pudo abrir: comprueba la clave, el archivo y la conexión al dispositivo."
                    .into(),
            ),
        }
    }
    fn start_editor(&mut self, id: Option<&str>) {
        if let Some(id) = id {
            if let Some(r) = self
                .session
                .as_ref()
                .unwrap()
                .data()
                .records
                .iter()
                .find(|r| r.id == id)
            {
                let new = r.copy_for_edit();
                self.tags = r.tags.join(", ");
                self.recovery_methods = r.recovery_methods.join("\n");
                self.editor_id = Some(id.to_owned());
                self.editor = Some(new);
                return;
            }
        }
        self.tags.clear();
        self.recovery_methods.clear();
        self.editor_id = None;
        self.editor = Some(Credential::default());
    }
    fn pick_csv(&mut self) {
        if let Some(p) = rfd::FileDialog::new()
            .add_filter("CSV", &["csv"])
            .pick_file()
        {
            match std::fs::read(&p) {
                Ok(b) => {
                    let bytes = Zeroizing::new(b);
                    let mut rdr = csv::ReaderBuilder::new()
                        .flexible(true)
                        .from_reader(bytes.as_slice());
                    match rdr.headers() {
                        Ok(h) => {
                            let headers = h.iter().map(str::to_owned).collect::<Vec<_>>();
                            let mapping = CsvMapping::suggest(&headers);
                            match CsvPreview::parse(
                                &bytes,
                                &self.session.as_ref().unwrap().data(),
                                &mapping,
                            ) {
                                Ok(preview) => {
                                    self.import = Some(ImportState {
                                        bytes,
                                        mapping,
                                        preview,
                                    })
                                }
                                Err(e) => self.error = Some(e.to_string()),
                            }
                        }
                        Err(_) => {
                            self.error = Some("El archivo CSV no tiene una cabecera válida.".into())
                        }
                    }
                }
                Err(e) => self.error = Some(e.to_string()),
            }
        }
    }
    fn perform_export(&mut self) {
        let choice = rfd::MessageDialog::new()
            .set_title("Formato de exportación")
            .set_description("Elige el formato; ambos generan un archivo sin cifrar.")
            .set_buttons(rfd::MessageButtons::YesNo)
            .show();
        let records = &self.session.as_ref().unwrap().data().records;
        let data = if choice == rfd::MessageDialogResult::Yes {
            export_csv(records)
        } else {
            export_xlsx(records)
        };
        match data {
            Ok(data) => {
                let data = Zeroizing::new(data);
                let filter = if choice == rfd::MessageDialogResult::Yes {
                    ("CSV", vec!["csv"])
                } else {
                    ("Excel", vec!["xlsx"])
                };
                if let Some(p) = rfd::FileDialog::new()
                    .add_filter(filter.0, &filter.1)
                    .save_file()
                {
                    match write_export_new(&p, &data) {
                        Ok(()) => self.status = format!("Exportación creada en {}", p.display()),
                        Err(e) => self.error = Some(e.to_string()),
                    }
                }
            }
            Err(e) => self.error = Some(e.to_string()),
        }
    }
    fn export_vault(&mut self) {
        if let Some(p) = rfd::FileDialog::new()
            .add_filter("CapyVault cifrado", &["capyvault"])
            .set_file_name("Copia.capyvault")
            .save_file()
        {
            match self.session.as_ref().unwrap().export_encrypted_copy(&p) {
                Ok(()) => self.status = "Copia cifrada verificada.".into(),
                Err(e) => self.error = Some(e.to_string()),
            }
        }
    }
    fn copy_string(&mut self, s: &str) {
        let mut value = Zeroizing::new(s.to_owned());
        self.copy_secret(&value);
        value.zeroize();
    }
    fn copy_secret(&mut self, s: &str) {
        let mut expected = Zeroizing::new(s.to_owned());
        let Ok(mut c) = Clipboard::new() else {
            self.error = Some("No se pudo acceder al portapapeles.".into());
            return;
        };
        if c.set_text(expected.to_string()).is_err() {
            self.error = Some("No se pudo copiar la credencial.".into());
            return;
        }
        let mut timer_value = Zeroizing::new(expected.to_string());
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(30));
            if let Ok(mut cb) = Clipboard::new() {
                if cb.get_text().ok().as_deref() == Some(timer_value.as_str()) {
                    let _ = cb.clear();
                }
            }
            timer_value.zeroize();
        });
        expected.zeroize();
        self.status = "Copiado; se borrará del portapapeles en 30 segundos si sigue igual.".into();
    }
}

fn primary(ui: &mut egui::Ui, text: &str) -> egui::Response {
    ui.add(
        egui::Button::new(RichText::new(text).strong().color(Color32::WHITE))
            .fill(GREEN)
            .corner_radius(9.)
            .min_size(Vec2::new(0., 38.)),
    )
}
fn nav_item(ui: &mut egui::Ui, selected: bool, icon: &str, label: &str) -> egui::Response {
    ui.add_sized(
        [190., 36.],
        egui::Button::selectable(selected, format!("{icon}   {label}")),
    )
}
fn field(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.label(
        RichText::new(label.to_uppercase())
            .size(10.)
            .strong()
            .color(MUTED),
    );
    ui.label(if value.is_empty() { "—" } else { value });
}
fn text_field(ui: &mut egui::Ui, label: &str, hint: &str, value: &mut String) {
    ui.label(RichText::new(label).size(12.).strong());
    ui.add(
        egui::TextEdit::singleline(value)
            .desired_width(360.)
            .hint_text(hint),
    );
    ui.add_space(8.);
}
fn metric(ui: &mut egui::Ui, label: &str, n: usize, color: Color32) {
    egui::Frame::new()
        .fill(Color32::WHITE)
        .corner_radius(12.)
        .inner_margin(16.)
        .show(ui, |ui| {
            ui.label(RichText::new(n.to_string()).size(28.).strong().color(color));
            ui.label(RichText::new(label).color(MUTED));
        });
}
fn ellipse(p: &egui::Painter, rect: egui::Rect, color: Color32) {
    let center = rect.center();
    let radius = rect.size() * 0.5;
    let points = (0..32)
        .map(|i| {
            let a = i as f32 * std::f32::consts::TAU / 32.;
            center + Vec2::new(a.cos() * radius.x, a.sin() * radius.y)
        })
        .collect();
    p.add(egui::Shape::convex_polygon(
        points,
        color,
        egui::Stroke::NONE,
    ));
}
fn capy_mark(ui: &mut egui::Ui, size: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), egui::Sense::hover());
    let p = ui.painter();
    let c = rect.center();
    p.circle_filled(c, size * 0.49, Color32::from_rgb(232, 243, 233));
    ellipse(
        p,
        egui::Rect::from_center_size(c + Vec2::new(0., 2.), Vec2::new(size * 0.54, size * 0.35)),
        Color32::from_rgb(164, 112, 76),
    );
    p.circle_filled(c + Vec2::new(-size * 0.17, -size * 0.08), size * 0.055, INK);
    p.circle_filled(c + Vec2::new(size * 0.17, -size * 0.08), size * 0.055, INK);
    p.circle_filled(
        c + Vec2::new(0., size * 0.05),
        size * 0.04,
        Color32::from_rgb(61, 49, 43),
    );
    p.circle_filled(
        c + Vec2::new(-size * 0.24, -size * 0.27),
        size * 0.085,
        Color32::from_rgb(164, 112, 76),
    );
    p.circle_filled(
        c + Vec2::new(size * 0.24, -size * 0.27),
        size * 0.085,
        Color32::from_rgb(164, 112, 76),
    );
}
fn capy_illustration(ui: &mut egui::Ui) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(240., 180.), egui::Sense::hover());
    let p = ui.painter();
    let c = rect.center();
    p.circle_filled(c, 74., Color32::from_rgb(231, 242, 231));
    ellipse(
        p,
        egui::Rect::from_center_size(c + Vec2::new(0., 14.), Vec2::new(142., 88.)),
        Color32::from_rgb(163, 110, 73),
    );
    p.circle_filled(
        c + Vec2::new(-40., -22.),
        23.,
        Color32::from_rgb(163, 110, 73),
    );
    p.circle_filled(
        c + Vec2::new(40., -22.),
        23.,
        Color32::from_rgb(163, 110, 73),
    );
    p.circle_filled(
        c + Vec2::new(-40., -22.),
        11.,
        Color32::from_rgb(236, 202, 167),
    );
    p.circle_filled(
        c + Vec2::new(40., -22.),
        11.,
        Color32::from_rgb(236, 202, 167),
    );
    p.circle_filled(c + Vec2::new(-23., 2.), 4., INK);
    p.circle_filled(c + Vec2::new(23., 2.), 4., INK);
    ellipse(
        p,
        egui::Rect::from_center_size(c + Vec2::new(0., 27.), Vec2::new(34., 24.)),
        Color32::from_rgb(222, 191, 156),
    );
    p.circle_filled(c + Vec2::new(0., 17.), 5., Color32::from_rgb(58, 45, 39));
    p.circle_filled(c + Vec2::new(85., -57.), 18., GOLD);
    p.circle_filled(c + Vec2::new(85., -57.), 7., Color32::WHITE);
}
fn removable_roots() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};
        let mut roots = Vec::new();
        unsafe {
            let bits = GetLogicalDrives();
            for n in 0..26 {
                if bits & (1 << n) != 0 {
                    let s = [b'A' as u16 + n as u16, b':' as u16, b'\\' as u16, 0];
                    if GetDriveTypeW(s.as_ptr()) == 2 {
                        roots.push(PathBuf::from(std::ffi::OsString::from_wide(&s[..3])));
                    }
                }
            }
        }
        roots
    }
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/mounts")
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.split_whitespace().nth(1))
            .filter(|p| {
                p.starts_with("/media/") || p.starts_with("/run/media/") || p.starts_with("/mnt/")
            })
            .map(PathBuf::from)
            .collect()
    }
    #[cfg(target_os = "android")]
    {
        Vec::new()
    }
}
