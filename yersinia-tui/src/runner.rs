//! TUI Runner
//!
//! Manages the TUI event loop, terminal setup/teardown, and integration
//! with the protocol registry and attack launcher.

use crate::app::{
    ActiveAttack, App, AttackConfig, AttackEntry, AttackParameter, InterfaceEntry, ParamInputState,
    ProtocolEntry, Screen,
};
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use uuid::Uuid;
use yersinia_core::{AttackId, Interface, Protocol};

/// TUI Context - holds the protocol registry and attack handles
pub struct TuiContext {
    /// Protocol registry
    pub protocols: Vec<Box<dyn Protocol>>,
    /// Active attack handles
    pub attack_handles: HashMap<Uuid, Arc<yersinia_core::attack::AttackHandle>>,
    /// Network interfaces
    pub interfaces: Vec<InterfaceInfo>,
}

/// Interface information
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub name: String,
    pub description: String,
    pub is_up: bool,
    pub is_loopback: bool,
}

impl TuiContext {
    pub fn new(protocols: Vec<Box<dyn Protocol>>) -> Self {
        Self {
            protocols,
            attack_handles: HashMap::new(),
            interfaces: Vec::new(),
        }
    }

    /// Load network interfaces
    pub fn load_interfaces(&mut self) -> io::Result<()> {
        // Try to load interfaces using pcap
        match pcap::Device::list() {
            Ok(devices) => {
                self.interfaces = devices
                    .into_iter()
                    .map(|dev| InterfaceInfo {
                        name: dev.name.clone(),
                        description: dev.desc.unwrap_or_else(|| dev.name.clone()),
                        is_up: true,
                        is_loopback: dev.flags.is_loopback(),
                    })
                    .collect();
                Ok(())
            }
            Err(e) => {
                // If pcap fails, return an error
                Err(io::Error::other(
                    format!("Failed to enumerate network interfaces: {}", e),
                ))
            }
        }
    }

    /// Get protocol by short name
    pub fn get_protocol(&self, short_name: &str) -> Option<&dyn Protocol> {
        self.protocols
            .iter()
            .find(|p| p.shortname().to_lowercase() == short_name.to_lowercase())
            .map(|p| p.as_ref())
    }
}

/// Run the TUI
pub fn run_tui(mut context: TuiContext) -> io::Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app
    let mut app = App::new();

    // Load protocols into app
    let protocol_entries: Vec<ProtocolEntry> = context
        .protocols
        .iter()
        .map(|p| ProtocolEntry {
            name: p.name().to_string(),
            short_name: p.shortname().to_string(),
            description: p.name().to_string(),
            attack_count: p.attacks().len(),
        })
        .collect();
    app.set_protocols(protocol_entries);

    // Load interfaces
    if let Err(e) = context.load_interfaces() {
        app.error_message = Some(format!("Failed to load interfaces: {}", e));
    } else {
        let interface_entries: Vec<InterfaceEntry> = context
            .interfaces
            .iter()
            .map(|i| InterfaceEntry {
                name: i.name.clone(),
                description: i.description.clone(),
                is_up: i.is_up,
                is_loopback: i.is_loopback,
            })
            .collect();
        app.set_interfaces(interface_entries);
    }

    // Current attacks list for tracking
    let mut current_attacks: Vec<AttackEntry> = Vec::new();

    // Main event loop
    let result = run_app(&mut terminal, &mut app, &mut context, &mut current_attacks);

    // Cleanup terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

/// Main application loop
fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
    context: &mut TuiContext,
    current_attacks: &mut Vec<AttackEntry>,
) -> io::Result<()> {
    loop {
        // Handle screen-specific logic
        match app.screen {
            Screen::AttackList => {
                // Load attacks for currently selected protocol
                if current_attacks.is_empty() {
                    if let Some(protocol_entry) = app.protocols.get(app.selected_protocol_idx) {
                        if let Some(protocol) = context.get_protocol(&protocol_entry.short_name) {
                            *current_attacks = protocol
                                .attacks()
                                .iter()
                                .map(|a| AttackEntry {
                                    id: a.id.0,
                                    name: a.name.to_string(),
                                    description: a.description.to_string(),
                                    parameters: a
                                        .parameters
                                        .iter()
                                        .map(|p| AttackParameter {
                                            name: p.name.to_string(),
                                            description: p.description.to_string(),
                                            param_type: format!("{:?}", p.param_type),
                                            required: p.required,
                                            default: p.default.clone(),
                                        })
                                        .collect(),
                                })
                                .collect();
                        }
                    }
                }
            }
            Screen::InterfaceList => {
                // When entering interface selection, prepare attack config
                if app.current_attack_config.is_none() {
                    if let (Some(protocol_entry), Some(attack)) = (
                        app.protocols.get(app.selected_protocol_idx),
                        current_attacks.get(app.selected_attack_idx),
                    ) {
                        app.current_attack_config = Some(AttackConfig {
                            protocol_name: protocol_entry.name.clone(),
                            attack: attack.clone(),
                            interface_name: String::new(),
                            parameters: HashMap::new(),
                        });
                    }
                }
            }
            Screen::ParameterConfig => {
                // Handle parameter configuration
                if let Some(ref mut config) = app.current_attack_config {
                    // Set interface name when first entering param config
                    if config.interface_name.is_empty() {
                        if let Some(iface) = app.interfaces.get(app.selected_interface_idx) {
                            config.interface_name = iface.name.clone();
                        }
                    }

                    // Handle parameter input
                    if app.param_input_state.is_none() {
                        // Find next parameter that needs input
                        let next_param = config.attack.parameters.iter().find(|p| {
                            p.required && !config.parameters.contains_key(&p.name)
                        });

                        if let Some(param) = next_param {
                            // Start input for this parameter
                            app.param_input_state = Some(ParamInputState {
                                param_name: param.name.clone(),
                                param_description: param.description.clone(),
                                param_type: param.param_type.clone(),
                                required: param.required,
                                input_buffer: param.default.clone().unwrap_or_default(),
                                cursor_position: param
                                    .default
                                    .as_ref()
                                    .map(|d| d.len())
                                    .unwrap_or(0),
                            });
                        }
                    }
                }
            }
            Screen::ProtocolList => {
                // Clear attacks when returning to protocol list
                current_attacks.clear();
            }
            _ => {}
        }

        // Render UI
        terminal.draw(|f| {
            // Special rendering for attack list with dynamic content
            if app.screen == Screen::AttackList && !current_attacks.is_empty() {
                render_attack_list_with_content(f, app, current_attacks);
            } else {
                // Use app's built-in rendering
                match app.screen {
                    Screen::MainMenu => app.render_main_menu(f),
                    Screen::ProtocolList => app.render_protocol_list(f),
                    Screen::AttackList => app.render_attack_list(f),
                    Screen::InterfaceList => app.render_interface_list(f),
                    Screen::ParameterConfig => app.render_parameter_config(f),
                    Screen::ActiveAttacks => app.render_active_attacks(f),
                    Screen::Help => app.render_help(f),
                }
            }
        })?;

        // Handle input with timeout for updating stats
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                // Special handling for parameter input completion
                if app.screen == Screen::ParameterConfig {
                    if let Some(ref input_state) = app.param_input_state.clone() {
                        if key.code == KeyCode::Enter {
                            // Save parameter value
                            if let Some(ref mut config) = app.current_attack_config {
                                let param_name = input_state.param_name.clone();
                                let param_value = input_state.input_buffer.clone();

                                if !param_value.is_empty() || !input_state.required {
                                    config.parameters.insert(param_name, param_value);
                                }

                                // Clear input state
                                app.param_input_state = None;
                            }
                            continue; // Skip normal input handling
                        }
                    } else {
                        // No active parameter input - check if we should launch
                        if key.code == KeyCode::Enter {
                            if let Some(ref config) = app.current_attack_config.clone() {
                                // Attempt to launch attack
                                match launch_attack_from_config(context, config) {
                                    Ok(attack_info) => {
                                        app.add_active_attack(attack_info);
                                        app.success_message = Some(format!(
                                            "Attack launched: {} on {}",
                                            config.attack.name, config.protocol_name
                                        ));
                                        app.screen = Screen::ActiveAttacks;
                                        app.current_attack_config = None;
                                    }
                                    Err(e) => {
                                        app.error_message = Some(format!("Failed to launch attack: {}", e));
                                    }
                                }
                                continue;
                            }
                        }
                    }
                }

                // Handle pause/stop in active attacks screen
                if app.screen == Screen::ActiveAttacks {
                    match key.code {
                        KeyCode::Char('p') => {
                            if let Some(attack) = app.active_attacks.get(app.selected_active_attack_idx) {
                                if let Some(handle) = context.attack_handles.get(&attack.id) {
                                    if attack.is_paused {
                                        handle.resume();
                                        app.success_message = Some("Attack resumed".to_string());
                                    } else {
                                        handle.pause();
                                        app.success_message = Some("Attack paused".to_string());
                                    }
                                }
                            }
                            continue;
                        }
                        KeyCode::Char('s') => {
                            if let Some(attack) = app.active_attacks.get(app.selected_active_attack_idx) {
                                if let Some(handle) = context.attack_handles.get(&attack.id) {
                                    handle.stop();
                                    app.success_message = Some("Attack stopped".to_string());
                                }
                            }
                            continue;
                        }
                        _ => {}
                    }
                }

                // Normal input handling
                app.handle_input(key)?;

                // Check for quit
                if app.should_quit {
                    // Stop all active attacks
                    for handle in context.attack_handles.values() {
                        handle.stop();
                    }
                    break;
                }
            }
        }

        // Update active attack statistics
        for attack in &mut app.active_attacks {
            if let Some(handle) = context.attack_handles.get(&attack.id) {
                let stats = handle.stats();
                attack.packets_sent = stats.packets_sent;
                attack.bytes_sent = stats.bytes_sent;
                attack.errors = stats.errors;
                attack.is_running = stats.is_running;
                attack.is_paused = stats.is_paused;
            }
        }
    }

    Ok(())
}

/// Render attack list with dynamic content
fn render_attack_list_with_content(
    f: &mut ratatui::Frame,
    app: &App,
    attacks: &[AttackEntry],
) {
    use ratatui::{
        layout::{Alignment, Constraint, Direction, Layout},
        style::{Color, Modifier, Style},
        text::{Line, Span},
        widgets::{Block, Borders, List, ListItem, Paragraph},
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(f.size());

    // Title
    let protocol_name = app
        .protocols
        .get(app.selected_protocol_idx)
        .map(|p| p.name.as_str())
        .unwrap_or("Unknown");
    let title = Paragraph::new(format!("Select Attack - Protocol: {}", protocol_name))
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(title, chunks[0]);

    // Attack list
    let items: Vec<ListItem> = attacks
        .iter()
        .enumerate()
        .map(|(i, attack)| {
            let style = if i == app.selected_attack_idx {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };

            let param_count = attack.parameters.len();
            let req_params = attack.parameters.iter().filter(|p| p.required).count();

            ListItem::new(vec![
                Line::from(vec![Span::styled(
                    format!("  [{}] {}", attack.id, attack.name),
                    style,
                )]),
                Line::from(vec![Span::styled(
                    format!(
                        "    {} (Params: {} total, {} required)",
                        attack.description, param_count, req_params
                    ),
                    if i == app.selected_attack_idx {
                        Style::default().fg(Color::Black).bg(Color::Cyan)
                    } else {
                        Style::default().fg(Color::Gray)
                    },
                )]),
            ])
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Attacks (↑↓ to navigate, Enter to select, Esc to go back)"),
        )
        .style(Style::default().fg(Color::White));

    f.render_widget(list, chunks[1]);

    // Status bar
    app.render_status_bar(f, chunks[2]);
}

/// Launch attack from configuration
fn launch_attack_from_config(
    context: &mut TuiContext,
    config: &AttackConfig,
) -> Result<ActiveAttack, String> {
    // Get protocol
    let protocol = context
        .get_protocol(&config.protocol_name)
        .ok_or_else(|| format!("Protocol '{}' not found", config.protocol_name))?;

    // Create attack params
    let mut attack_params = yersinia_core::protocol::AttackParams::new();
    for (key, value) in &config.parameters {
        attack_params = attack_params.set(key.clone(), value.clone());
    }

    // Create interface
    let interface = Interface::new(
        config.interface_name.clone(),
        0,
        yersinia_core::MacAddr::new([0, 0, 0, 0, 0, 0]),
    );

    // Launch attack synchronously (since we're in a blocking context)
    let attack_id = AttackId(config.attack.id);

    // Use tokio runtime to execute async operation
    let handle = tokio::runtime::Runtime::new()
        .map_err(|e| format!("Failed to create runtime: {}", e))?
        .block_on(async {
            protocol
                .launch_attack(attack_id, attack_params, &interface)
                .await
        })
        .map_err(|e| format!("Failed to launch attack: {}", e))?;

    let attack_info = ActiveAttack {
        id: handle.id,
        protocol_name: config.protocol_name.clone(),
        attack_name: config.attack.name.clone(),
        interface: config.interface_name.clone(),
        started_at: SystemTime::now(),
        packets_sent: 0,
        bytes_sent: 0,
        errors: 0,
        is_running: true,
        is_paused: false,
    };

    // Store handle
    context.attack_handles.insert(handle.id, Arc::new(handle));

    Ok(attack_info)
}
