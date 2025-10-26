//! TUI Application State and Logic

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    backend::Backend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, List, ListItem, Paragraph, Wrap,
    },
    Frame, Terminal,
};
use std::collections::HashMap;
use std::io;
use std::time::{Duration, SystemTime};
use uuid::Uuid;

/// Application state
pub struct App {
    /// Current screen
    pub screen: Screen,
    /// Should the app quit?
    pub should_quit: bool,
    /// List of available protocols
    pub protocols: Vec<ProtocolEntry>,
    /// List of available network interfaces
    pub interfaces: Vec<InterfaceEntry>,
    /// Currently selected protocol index
    pub selected_protocol_idx: usize,
    /// Currently selected attack index
    pub selected_attack_idx: usize,
    /// Currently selected interface index
    pub selected_interface_idx: usize,
    /// Current attack being configured
    pub current_attack_config: Option<AttackConfig>,
    /// Active attacks
    pub active_attacks: Vec<ActiveAttack>,
    /// Selected active attack index
    pub selected_active_attack_idx: usize,
    /// Parameter input state
    pub param_input_state: Option<ParamInputState>,
    /// Error message to display
    pub error_message: Option<String>,
    /// Success message to display
    pub success_message: Option<String>,
}

/// Current screen being displayed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    /// Main menu
    MainMenu,
    /// Protocol selection
    ProtocolList,
    /// Attack selection for chosen protocol
    AttackList,
    /// Interface selection
    InterfaceList,
    /// Parameter configuration
    ParameterConfig,
    /// Active attacks monitoring
    ActiveAttacks,
    /// Help screen
    Help,
}

/// Protocol entry for the UI
#[derive(Debug, Clone)]
pub struct ProtocolEntry {
    pub name: String,
    pub short_name: String,
    pub description: String,
    pub attack_count: usize,
}

/// Attack entry for the UI
#[derive(Debug, Clone)]
pub struct AttackEntry {
    pub id: u8,
    pub name: String,
    pub description: String,
    pub parameters: Vec<AttackParameter>,
}

/// Attack parameter
#[derive(Debug, Clone)]
pub struct AttackParameter {
    pub name: String,
    pub description: String,
    pub param_type: String,
    pub required: bool,
    pub default: Option<String>,
}

/// Interface entry for the UI
#[derive(Debug, Clone)]
pub struct InterfaceEntry {
    pub name: String,
    pub description: String,
    pub is_up: bool,
    pub is_loopback: bool,
}

/// Attack configuration in progress
#[derive(Debug, Clone)]
pub struct AttackConfig {
    pub protocol_name: String,
    pub attack: AttackEntry,
    pub interface_name: String,
    pub parameters: HashMap<String, String>,
}

/// Active attack information
#[derive(Debug, Clone)]
pub struct ActiveAttack {
    pub id: Uuid,
    pub protocol_name: String,
    pub attack_name: String,
    pub interface: String,
    pub started_at: SystemTime,
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub errors: u64,
    pub is_running: bool,
    pub is_paused: bool,
}

/// Parameter input state
#[derive(Debug, Clone)]
pub struct ParamInputState {
    pub param_name: String,
    pub param_description: String,
    pub param_type: String,
    pub required: bool,
    pub input_buffer: String,
    pub cursor_position: usize,
}

impl App {
    /// Create a new application instance
    pub fn new() -> Self {
        Self {
            screen: Screen::MainMenu,
            should_quit: false,
            protocols: Vec::new(),
            interfaces: Vec::new(),
            selected_protocol_idx: 0,
            selected_attack_idx: 0,
            selected_interface_idx: 0,
            current_attack_config: None,
            active_attacks: Vec::new(),
            selected_active_attack_idx: 0,
            param_input_state: None,
            error_message: None,
            success_message: None,
        }
    }

    /// Set protocols from registry
    pub fn set_protocols(&mut self, protocols: Vec<ProtocolEntry>) {
        self.protocols = protocols;
    }

    /// Set interfaces
    pub fn set_interfaces(&mut self, interfaces: Vec<InterfaceEntry>) {
        self.interfaces = interfaces;
    }

    /// Add an active attack
    pub fn add_active_attack(&mut self, attack: ActiveAttack) {
        self.active_attacks.push(attack);
    }

    /// Update active attack statistics
    pub fn update_attack_stats(&mut self, attack_id: Uuid, packets: u64, bytes: u64, errors: u64, is_running: bool, is_paused: bool) {
        if let Some(attack) = self.active_attacks.iter_mut().find(|a| a.id == attack_id) {
            attack.packets_sent = packets;
            attack.bytes_sent = bytes;
            attack.errors = errors;
            attack.is_running = is_running;
            attack.is_paused = is_paused;
        }
    }

    /// Get attacks for currently selected protocol
    pub fn get_current_protocol_attacks(&self) -> Vec<AttackEntry> {
        // This will be populated by the caller
        Vec::new()
    }

    /// Handle keyboard input
    pub fn handle_input(&mut self, key: KeyEvent) -> io::Result<()> {
        // Clear messages on any input
        if key.code != KeyCode::Null {
            self.error_message = None;
            self.success_message = None;
        }

        // Check for quit shortcut (q or Ctrl+C)
        if key.code == KeyCode::Char('q') && self.screen == Screen::MainMenu {
            self.should_quit = true;
            return Ok(());
        }

        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.should_quit = true;
            return Ok(());
        }

        match self.screen {
            Screen::MainMenu => self.handle_main_menu_input(key),
            Screen::ProtocolList => self.handle_protocol_list_input(key),
            Screen::AttackList => self.handle_attack_list_input(key),
            Screen::InterfaceList => self.handle_interface_list_input(key),
            Screen::ParameterConfig => self.handle_parameter_config_input(key),
            Screen::ActiveAttacks => self.handle_active_attacks_input(key),
            Screen::Help => self.handle_help_input(key),
        }
    }

    fn handle_main_menu_input(&mut self, key: KeyEvent) -> io::Result<()> {
        match key.code {
            KeyCode::Char('1') | KeyCode::Enter => {
                if !self.protocols.is_empty() {
                    self.screen = Screen::ProtocolList;
                    self.selected_protocol_idx = 0;
                } else {
                    self.error_message = Some("No protocols available".to_string());
                }
            }
            KeyCode::Char('2') => {
                self.screen = Screen::ActiveAttacks;
                self.selected_active_attack_idx = 0;
            }
            KeyCode::Char('3') => {
                self.screen = Screen::Help;
            }
            KeyCode::Char('4') | KeyCode::Char('q') => {
                self.should_quit = true;
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_protocol_list_input(&mut self, key: KeyEvent) -> io::Result<()> {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if self.selected_protocol_idx > 0 {
                    self.selected_protocol_idx -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.selected_protocol_idx < self.protocols.len().saturating_sub(1) {
                    self.selected_protocol_idx += 1;
                }
            }
            KeyCode::Enter => {
                if !self.protocols.is_empty() {
                    self.screen = Screen::AttackList;
                    self.selected_attack_idx = 0;
                }
            }
            KeyCode::Esc | KeyCode::Char('q') => {
                self.screen = Screen::MainMenu;
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_attack_list_input(&mut self, key: KeyEvent) -> io::Result<()> {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if self.selected_attack_idx > 0 {
                    self.selected_attack_idx -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                // Attack count will be checked by caller
                self.selected_attack_idx += 1;
            }
            KeyCode::Enter => {
                // Move to interface selection
                if !self.interfaces.is_empty() {
                    self.screen = Screen::InterfaceList;
                    self.selected_interface_idx = 0;
                } else {
                    self.error_message = Some("No network interfaces available".to_string());
                }
            }
            KeyCode::Esc | KeyCode::Char('q') => {
                self.screen = Screen::ProtocolList;
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_interface_list_input(&mut self, key: KeyEvent) -> io::Result<()> {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if self.selected_interface_idx > 0 {
                    self.selected_interface_idx -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.selected_interface_idx < self.interfaces.len().saturating_sub(1) {
                    self.selected_interface_idx += 1;
                }
            }
            KeyCode::Enter => {
                // Interface selected, signal to move to parameter config
                // This will be handled by the caller
                self.screen = Screen::ParameterConfig;
            }
            KeyCode::Esc | KeyCode::Char('q') => {
                self.screen = Screen::AttackList;
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_parameter_config_input(&mut self, key: KeyEvent) -> io::Result<()> {
        if let Some(ref mut input_state) = self.param_input_state {
            match key.code {
                KeyCode::Char(c) => {
                    input_state.input_buffer.insert(input_state.cursor_position, c);
                    input_state.cursor_position += 1;
                }
                KeyCode::Backspace => {
                    if input_state.cursor_position > 0 {
                        input_state.input_buffer.remove(input_state.cursor_position - 1);
                        input_state.cursor_position -= 1;
                    }
                }
                KeyCode::Left => {
                    if input_state.cursor_position > 0 {
                        input_state.cursor_position -= 1;
                    }
                }
                KeyCode::Right => {
                    if input_state.cursor_position < input_state.input_buffer.len() {
                        input_state.cursor_position += 1;
                    }
                }
                KeyCode::Enter => {
                    // Parameter input complete - signal to caller
                }
                KeyCode::Esc => {
                    // Cancel parameter input
                    self.param_input_state = None;
                }
                _ => {}
            }
        } else {
            // No active parameter input
            match key.code {
                KeyCode::Enter => {
                    // Launch attack - handled by caller
                }
                KeyCode::Esc | KeyCode::Char('q') => {
                    self.screen = Screen::InterfaceList;
                    self.current_attack_config = None;
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn handle_active_attacks_input(&mut self, key: KeyEvent) -> io::Result<()> {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if self.selected_active_attack_idx > 0 {
                    self.selected_active_attack_idx -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.selected_active_attack_idx < self.active_attacks.len().saturating_sub(1) {
                    self.selected_active_attack_idx += 1;
                }
            }
            KeyCode::Char('p') => {
                // Toggle pause - handled by caller
            }
            KeyCode::Char('s') => {
                // Stop attack - handled by caller
            }
            KeyCode::Esc | KeyCode::Char('q') => {
                self.screen = Screen::MainMenu;
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_help_input(&mut self, key: KeyEvent) -> io::Result<()> {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter => {
                self.screen = Screen::MainMenu;
            }
            _ => {}
        }
        Ok(())
    }

    /// Render the UI
    pub fn render<B: Backend>(&mut self, terminal: &mut Terminal<B>) -> io::Result<()> {
        terminal.draw(|f| {
            match self.screen {
                Screen::MainMenu => self.render_main_menu(f),
                Screen::ProtocolList => self.render_protocol_list(f),
                Screen::AttackList => self.render_attack_list(f),
                Screen::InterfaceList => self.render_interface_list(f),
                Screen::ParameterConfig => self.render_parameter_config(f),
                Screen::ActiveAttacks => self.render_active_attacks(f),
                Screen::Help => self.render_help(f),
            }
        })?;
        Ok(())
    }

    pub fn render_main_menu(&self, f: &mut Frame) {
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
        let title = Paragraph::new("Yersinia-RS - Network Protocol Attack Tool (TUI)")
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(title, chunks[0]);

        // Menu options
        let menu_items = ["1. Launch Attack (Select Protocol)",
            "2. Monitor Active Attacks",
            "3. Help",
            "4. Exit (q)"];

        let menu: Vec<ListItem> = menu_items
            .iter()
            .map(|item| {
                ListItem::new(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(*item, Style::default().fg(Color::White)),
                ]))
            })
            .collect();

        let menu_list = List::new(menu)
            .block(Block::default().borders(Borders::ALL).title("Main Menu"))
            .style(Style::default().fg(Color::White));

        f.render_widget(menu_list, chunks[1]);

        // Status bar
        self.render_status_bar(f, chunks[2]);
    }

    pub fn render_protocol_list(&self, f: &mut Frame) {
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
        let title = Paragraph::new("Select Protocol")
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(title, chunks[0]);

        // Protocol list
        let items: Vec<ListItem> = self
            .protocols
            .iter()
            .enumerate()
            .map(|(i, proto)| {
                let style = if i == self.selected_protocol_idx {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                };

                ListItem::new(Line::from(vec![
                    Span::styled(
                        format!("  {:10} - {} ({} attacks)", proto.short_name, proto.description, proto.attack_count),
                        style,
                    ),
                ]))
            })
            .collect();

        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title("Protocols (↑↓ to navigate, Enter to select, Esc to go back)"))
            .style(Style::default().fg(Color::White));

        f.render_widget(list, chunks[1]);

        // Status bar
        self.render_status_bar(f, chunks[2]);
    }

    pub fn render_attack_list(&self, f: &mut Frame) {
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
        let protocol_name = self.protocols.get(self.selected_protocol_idx)
            .map(|p| p.name.as_str())
            .unwrap_or("Unknown");
        let title = Paragraph::new(format!("Select Attack - Protocol: {}", protocol_name))
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(title, chunks[0]);

        // Attack list (populated by caller)
        let placeholder = Paragraph::new("Loading attacks...")
            .block(Block::default().borders(Borders::ALL).title("Attacks (↑↓ to navigate, Enter to select, Esc to go back)"))
            .style(Style::default().fg(Color::White));

        f.render_widget(placeholder, chunks[1]);

        // Status bar
        self.render_status_bar(f, chunks[2]);
    }

    pub fn render_interface_list(&self, f: &mut Frame) {
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
        let title = Paragraph::new("Select Network Interface")
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(title, chunks[0]);

        // Interface list
        let items: Vec<ListItem> = self
            .interfaces
            .iter()
            .enumerate()
            .map(|(i, iface)| {
                let style = if i == self.selected_interface_idx {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                };

                let status = if iface.is_up { "UP" } else { "DOWN" };
                let loopback = if iface.is_loopback { " [LOOPBACK]" } else { "" };

                ListItem::new(Line::from(vec![
                    Span::styled(
                        format!("  {} - {} [{}]{}", iface.name, iface.description, status, loopback),
                        style,
                    ),
                ]))
            })
            .collect();

        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title("Interfaces (↑↓ to navigate, Enter to select, Esc to go back)"))
            .style(Style::default().fg(Color::White));

        f.render_widget(list, chunks[1]);

        // Status bar
        self.render_status_bar(f, chunks[2]);
    }

    pub fn render_parameter_config(&self, f: &mut Frame) {
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
        let title = Paragraph::new("Configure Attack Parameters")
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(title, chunks[0]);

        // Parameter configuration
        if let Some(ref input_state) = self.param_input_state {
            let text = vec![
                Line::from(vec![
                    Span::styled("Parameter: ", Style::default().fg(Color::Yellow)),
                    Span::styled(&input_state.param_name, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("Description: ", Style::default().fg(Color::Yellow)),
                    Span::styled(&input_state.param_description, Style::default().fg(Color::White)),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("Type: ", Style::default().fg(Color::Yellow)),
                    Span::styled(&input_state.param_type, Style::default().fg(Color::Cyan)),
                    Span::styled(if input_state.required { " [REQUIRED]" } else { " [OPTIONAL]" },
                        if input_state.required { Style::default().fg(Color::Red) } else { Style::default().fg(Color::Gray) }),
                ]),
                Line::from(""),
                Line::from(""),
                Line::from(vec![
                    Span::styled("Enter value: ", Style::default().fg(Color::Green)),
                    Span::styled(&input_state.input_buffer, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                    Span::styled("_", Style::default().fg(Color::White).add_modifier(Modifier::SLOW_BLINK)),
                ]),
            ];

            let paragraph = Paragraph::new(text)
                .block(Block::default().borders(Borders::ALL).title("Enter Parameter Value (Enter to confirm, Esc to skip)"))
                .wrap(Wrap { trim: true });

            f.render_widget(paragraph, chunks[1]);
        } else {
            let text = if let Some(ref config) = self.current_attack_config {
                let mut lines = vec![
                    Line::from(vec![
                        Span::styled("Protocol: ", Style::default().fg(Color::Yellow)),
                        Span::styled(&config.protocol_name, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                    ]),
                    Line::from(vec![
                        Span::styled("Attack: ", Style::default().fg(Color::Yellow)),
                        Span::styled(&config.attack.name, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                    ]),
                    Line::from(vec![
                        Span::styled("Interface: ", Style::default().fg(Color::Yellow)),
                        Span::styled(&config.interface_name, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                    ]),
                    Line::from(""),
                    Line::from(vec![
                        Span::styled("Parameters configured:", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                    ]),
                ];

                if config.parameters.is_empty() {
                    lines.push(Line::from("  (none)"));
                } else {
                    for (key, value) in &config.parameters {
                        lines.push(Line::from(vec![
                            Span::styled("  ", Style::default()),
                            Span::styled(key, Style::default().fg(Color::Cyan)),
                            Span::styled(" = ", Style::default().fg(Color::White)),
                            Span::styled(value, Style::default().fg(Color::Yellow)),
                        ]));
                    }
                }

                lines.push(Line::from(""));
                lines.push(Line::from(vec![
                    Span::styled("Press Enter to launch attack, Esc to cancel", Style::default().fg(Color::Gray).add_modifier(Modifier::ITALIC)),
                ]));

                lines
            } else {
                vec![Line::from("No attack configuration")]
            };

            let paragraph = Paragraph::new(text)
                .block(Block::default().borders(Borders::ALL).title("Attack Configuration"))
                .wrap(Wrap { trim: true });

            f.render_widget(paragraph, chunks[1]);
        }

        // Status bar
        self.render_status_bar(f, chunks[2]);
    }

    pub fn render_active_attacks(&self, f: &mut Frame) {
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
        let title = Paragraph::new(format!("Active Attacks ({})", self.active_attacks.len()))
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(title, chunks[0]);

        // Active attacks list
        if self.active_attacks.is_empty() {
            let placeholder = Paragraph::new("No active attacks\n\nPress 1 from the main menu to launch an attack")
                .alignment(Alignment::Center)
                .block(Block::default().borders(Borders::ALL).title("Monitoring (p to pause, s to stop, Esc to go back)"))
                .style(Style::default().fg(Color::Gray));

            f.render_widget(placeholder, chunks[1]);
        } else {
            let items: Vec<ListItem> = self
                .active_attacks
                .iter()
                .enumerate()
                .map(|(i, attack)| {
                    let style = if i == self.selected_active_attack_idx {
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::Cyan)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::White)
                    };

                    let status = if !attack.is_running {
                        "STOPPED"
                    } else if attack.is_paused {
                        "PAUSED"
                    } else {
                        "RUNNING"
                    };

                    let elapsed = SystemTime::now()
                        .duration_since(attack.started_at)
                        .unwrap_or(Duration::from_secs(0))
                        .as_secs();

                    ListItem::new(vec![
                        Line::from(vec![
                            Span::styled(
                                format!("  {} - {} [{}]", attack.protocol_name, attack.attack_name, status),
                                style,
                            ),
                        ]),
                        Line::from(vec![
                            Span::styled(
                                format!("    Interface: {} | Packets: {} | Bytes: {} | Errors: {} | Time: {}s",
                                    attack.interface, attack.packets_sent, attack.bytes_sent, attack.errors, elapsed),
                                if i == self.selected_active_attack_idx {
                                    Style::default().fg(Color::Black).bg(Color::Cyan)
                                } else {
                                    Style::default().fg(Color::Gray)
                                },
                            ),
                        ]),
                    ])
                })
                .collect();

            let list = List::new(items)
                .block(Block::default().borders(Borders::ALL).title("Active Attacks (↑↓ to navigate, p to pause, s to stop, Esc to go back)"))
                .style(Style::default().fg(Color::White));

            f.render_widget(list, chunks[1]);
        }

        // Status bar
        self.render_status_bar(f, chunks[2]);
    }

    pub fn render_help(&self, f: &mut Frame) {
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
        let title = Paragraph::new("Help - Yersinia-RS TUI")
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(title, chunks[0]);

        // Help text
        let help_text = vec![
            Line::from(vec![
                Span::styled("Yersinia-RS ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::styled("- Network Protocol Security Testing Tool", Style::default().fg(Color::White)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Navigation:", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            ]),
            Line::from("  ↑/↓ or k/j  - Move selection up/down"),
            Line::from("  Enter       - Confirm selection"),
            Line::from("  Esc or q    - Go back / Cancel"),
            Line::from("  Ctrl+C      - Quit application"),
            Line::from(""),
            Line::from(vec![
                Span::styled("Launching Attacks:", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            ]),
            Line::from("  1. Select 'Launch Attack' from main menu"),
            Line::from("  2. Choose a protocol (CDP, STP, DHCP, etc.)"),
            Line::from("  3. Select an attack type"),
            Line::from("  4. Choose a network interface"),
            Line::from("  5. Configure parameters (if required)"),
            Line::from("  6. Press Enter to launch"),
            Line::from(""),
            Line::from(vec![
                Span::styled("Managing Active Attacks:", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            ]),
            Line::from("  p - Pause/Resume attack"),
            Line::from("  s - Stop attack"),
            Line::from(""),
            Line::from(vec![
                Span::styled("Supported Protocols:", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            ]),
            Line::from("  ARP, CDP, DHCP, DTP, HSRP, ISL, LLDP, MPLS,"),
            Line::from("  STP/RSTP/MSTP, VTP, 802.1Q, 802.1X, and more..."),
            Line::from(""),
            Line::from(vec![
                Span::styled("Press Esc or q to return to main menu", Style::default().fg(Color::Gray).add_modifier(Modifier::ITALIC)),
            ]),
        ];

        let paragraph = Paragraph::new(help_text)
            .block(Block::default().borders(Borders::ALL))
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, chunks[1]);

        // Status bar
        self.render_status_bar(f, chunks[2]);
    }

    pub fn render_status_bar(&self, f: &mut Frame, area: Rect) {
        let status_text = if let Some(ref error) = self.error_message {
            vec![Line::from(vec![
                Span::styled("ERROR: ", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
                Span::styled(error, Style::default().fg(Color::Red)),
            ])]
        } else if let Some(ref success) = self.success_message {
            vec![Line::from(vec![
                Span::styled("SUCCESS: ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                Span::styled(success, Style::default().fg(Color::Green)),
            ])]
        } else {
            vec![Line::from(vec![
                Span::styled("Yersinia-RS v", Style::default().fg(Color::Gray)),
                Span::styled(env!("CARGO_PKG_VERSION"), Style::default().fg(Color::Gray)),
                Span::styled(" | Press q to quit, ? for help", Style::default().fg(Color::Gray)),
            ])]
        };

        let status = Paragraph::new(status_text)
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL));

        f.render_widget(status, area);
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}
