use anyhow::{Context, Result, anyhow, bail};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
    ExecutableCommand,
};
use ratatui::{
    prelude::*,
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Clear, Gauge, Paragraph, Row, Table, Wrap},
};
use regex::Regex;
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::{BTreeSet, HashMap},
    fs, io,
    path::{Path, PathBuf},
    time::Instant,
};
use tokio::sync::mpsc;
use tokio::time::{Duration, sleep};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DownloadMode {
    Github,
    GithubExternal,
}

impl DownloadMode {
    const ALL: [DownloadMode; 2] = [
        DownloadMode::Github,
        DownloadMode::GithubExternal,
    ];

    fn label(self) -> &'static str {
        match self {
            DownloadMode::Github => "GitHub only",
            DownloadMode::GithubExternal => "GitHub + External Site",
        }
    }

    fn needs_api_key(self) -> bool {
        !matches!(self, DownloadMode::Github)
    }

    fn next(self) -> Self {
        let index = Self::ALL.iter().position(|mode| *mode == self).unwrap_or(0);
        Self::ALL[(index + 1) % Self::ALL.len()]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FocusField {
    AppId,
    ApiKey,
}

impl FocusField {
    fn next(self, source_mode: DownloadMode, run_mode: RunMode) -> Self {
        match (run_mode.needs_app_id(), source_mode.needs_api_key(), self) {
            (true, false, _) => FocusField::AppId,
            (false, true, _) => FocusField::ApiKey,
            (false, false, _) => FocusField::AppId,
            (true, true, FocusField::AppId) => FocusField::ApiKey,
            (true, true, FocusField::ApiKey) => FocusField::AppId,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RunMode {
    SingleApp,
    FullRebase,
}

impl RunMode {
    const ALL: [RunMode; 2] = [RunMode::SingleApp, RunMode::FullRebase];

    fn label(self) -> &'static str {
        match self {
            RunMode::SingleApp => "Single App",
            RunMode::FullRebase => "Full Rebase",
        }
    }

    fn next(self) -> Self {
        let index = Self::ALL.iter().position(|mode| *mode == self).unwrap_or(0);
        Self::ALL[(index + 1) % Self::ALL.len()]
    }

    fn needs_app_id(self) -> bool {
        matches!(self, RunMode::SingleApp)
    }
}

#[derive(Default, Clone, Debug)]
struct RunSummary {
    target_label: String,
    steam_path: String,
    output_path: String,
    app_count: usize,
    lua_files: usize,
    depot_ids: Vec<String>,
    failed_apps: usize,
    recent_errors: Vec<String>,
    total: usize,
    downloaded: usize,
    skipped: usize,
    unavailable: usize,
    failed: usize,
    downloaded_bytes: u64,
    elapsed: String,
}

#[derive(Debug)]
struct App {
    mode: DownloadMode,
    run_mode: RunMode,
    focus: FocusField,
    app_id: String,
    api_key: String,
    logs: Vec<String>,
    status: String,
    progress: u16,
    busy: bool,
    summary: Option<RunSummary>,
    custom_lua_dir: Option<PathBuf>,
}

impl App {
    fn new(custom_lua_dir: Option<PathBuf>) -> Self {
        let mut app = Self {
            mode: DownloadMode::Github,
            run_mode: RunMode::SingleApp,
            focus: FocusField::AppId,
            app_id: String::new(),
            api_key: String::new(),
            logs: Vec::new(),
            status: "Enter a Steam AppID and press Enter.".to_string(),
            progress: 0,
            busy: false,
            summary: None,
            custom_lua_dir,
        };
        app.push_log("[*] Steam manifest downloader ready.");
        if let Some(ref path) = app.custom_lua_dir {
            app.push_log(format!("[*] Custom Lua directory: {}", path.display()));
        }
        app
    }

    fn reset_for_next_run(&mut self) {
        self.app_id.clear();
        self.logs.clear();
        self.summary = None;
        self.status = if self.run_mode.needs_app_id() {
            "Enter a Steam AppID and press Enter.".to_string()
        } else {
            let path_label = if let Some(ref path) = self.custom_lua_dir {
                path.display().to_string()
            } else {
                "stplug-in".to_string()
            };
            format!("Press Enter to scan every Lua file in {}.", path_label)
        };
        self.progress = 0;
        self.focus = if self.run_mode.needs_app_id() {
            FocusField::AppId
        } else if self.mode.needs_api_key() {
            FocusField::ApiKey
        } else {
            FocusField::AppId
        };
        self.push_log("[*] Session reset.");
        if let Some(ref path) = self.custom_lua_dir {
            self.push_log(format!("[*] Custom Lua directory: {}", path.display()));
        }
    }

    fn current_input(&mut self) -> &mut String {
        match self.focus {
            FocusField::AppId => &mut self.app_id,
            FocusField::ApiKey => &mut self.api_key,
        }
    }

    fn push_log<S: Into<String>>(&mut self, message: S) {
        self.logs.push(message.into());
        if self.logs.len() > 200 {
            let overflow = self.logs.len() - 200;
            self.logs.drain(0..overflow);
        }
    }
}

#[derive(Deserialize, Debug)]
struct SteamResponse {
    status: Option<String>,
    data: HashMap<String, AppData>,
}

#[derive(Deserialize, Debug)]
struct AppData {
    depots: HashMap<String, Value>,
}

#[derive(Clone, Debug)]
struct DownloadItem {
    depot_id: String,
    manifest_id: String,
}

#[derive(Debug)]
struct DownloadResult {
    outcome: DownloadOutcome,
    size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DownloadOutcome {
    Downloaded,
    SkippedExisting,
    Unavailable,
}

#[derive(Debug)]
struct AttemptResult {
    success: bool,
    is_404: bool,
    size: u64,
    attempts: usize,
    error: Option<String>,
}

struct Theme;

impl Theme {
    const BG: Color = Color::Rgb(9, 12, 20);
    const PANEL: Color = Color::Rgb(24, 31, 48);
    const BORDER: Color = Color::Rgb(77, 116, 196);
    const ACCENT: Color = Color::Rgb(74, 222, 128);
    const ACCENT_ALT: Color = Color::Rgb(56, 189, 248);
    const TITLE: Color = Color::Rgb(248, 250, 252);
    const MUTED: Color = Color::Rgb(148, 163, 184);
    const INPUT: Color = Color::Rgb(251, 191, 36);
    const INFO: Color = Color::Rgb(125, 211, 252);
    const SUCCESS: Color = Color::Rgb(74, 222, 128);
    const WARNING: Color = Color::Rgb(250, 204, 21);
    const ERROR: Color = Color::Rgb(248, 113, 113);
}

#[derive(Clone)]
struct RunRequest {
    mode: DownloadMode,
    run_mode: RunMode,
    app_id: String,
    api_key: String,
    lua_dir: Option<PathBuf>,
}

enum WorkerEvent {
    Reset,
    Log(String),
    Status(String),
    Progress(u16),
    Summary(RunSummary),
    Finished,
    Failed(String),
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let custom_lua_dir = if args.len() > 1 {
        Some(PathBuf::from(&args[1]))
    } else {
        None
    };

    let mut terminal = setup_terminal()?;
    let run_result = run_app(&mut terminal, custom_lua_dir).await;
    restore_terminal()?;

    if let Err(error) = run_result {
        eprintln!("Errore fatale: {error}");
    }

    Ok(())
}

fn setup_terminal() -> Result<Terminal<CrosstermBackend<io::Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    stdout.execute(EnterAlternateScreen)?;
    Ok(Terminal::new(CrosstermBackend::new(stdout))?)
}

fn restore_terminal() -> Result<()> {
    disable_raw_mode()?;
    io::stdout().execute(LeaveAlternateScreen)?;
    Ok(())
}

async fn run_app(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, custom_lua_dir: Option<PathBuf>) -> Result<()> {
    let client = Client::builder()
        .user_agent("steam-manifest-rust")
        .timeout(Duration::from_secs(120))
        .build()?;
    let mut app = App::new(custom_lua_dir);
    let mut worker_rx: Option<mpsc::UnboundedReceiver<WorkerEvent>> = None;

    loop {
        if let Some(rx) = worker_rx.as_mut() {
            let mut finished = false;
            while let Ok(event) = rx.try_recv() {
                finished = apply_worker_event(&mut app, event);
            }
            if finished {
                worker_rx = None;
            }
        }

        terminal.draw(|frame| render(frame, &app))?;

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }

                match key.code {
                    KeyCode::Esc => break,
                    KeyCode::Tab if !app.busy => {
                        app.focus = app.focus.next(app.mode, app.run_mode)
                    }
                    KeyCode::F(2) if !app.busy => {
                        app.mode = app.mode.next();
                        if !app.mode.needs_api_key() && !app.run_mode.needs_app_id() {
                            app.focus = FocusField::AppId;
                        } else if !app.mode.needs_api_key() && app.focus == FocusField::ApiKey {
                            app.focus = FocusField::AppId;
                        }
                        app.status = format!("Selected source: {}", app.mode.label());
                    }
                    KeyCode::F(3) if !app.busy => {
                        app.run_mode = app.run_mode.next();
                        app.focus = if app.run_mode.needs_app_id() {
                            FocusField::AppId
                        } else if app.mode.needs_api_key() {
                            FocusField::ApiKey
                        } else {
                            FocusField::AppId
                        };
                        app.status = if app.run_mode.needs_app_id() {
                            format!("Selected run mode: {}", app.run_mode.label())
                        } else {
                            "Selected run mode: Full Rebase".to_string()
                        };
                    }
                    KeyCode::Char('r') | KeyCode::Char('R') if !app.busy => app.reset_for_next_run(),
                    KeyCode::Backspace if !app.busy => {
                        app.current_input().pop();
                    }
                    KeyCode::Enter if !app.busy => {
                        let request = RunRequest {
                            mode: app.mode,
                            run_mode: app.run_mode,
                            app_id: app.app_id.trim().to_string(),
                            api_key: app.api_key.trim().to_string(),
                            lua_dir: app.custom_lua_dir.clone(),
                        };
                        let (tx, rx) = mpsc::unbounded_channel();
                        worker_rx = Some(rx);
                        app.busy = true;
                        let client = client.clone();
                        tokio::spawn(async move {
                            process_run(client, request, tx).await;
                        });
                    }
                    KeyCode::Char(c) if !app.busy => {
                        if matches!(app.focus, FocusField::AppId) {
                            if c.is_ascii_digit() && app.app_id.len() < 12 {
                                app.app_id.push(c);
                            }
                        } else if !c.is_control() {
                            app.api_key.push(c);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

fn render(frame: &mut Frame<'_>, app: &App) {
    frame.render_widget(Block::default().style(Style::default().bg(Theme::BG)), frame.area());

    let chunks = Layout::vertical([
        Constraint::Length(5),
        Constraint::Length(11),
        Constraint::Min(10),
        Constraint::Length(4),
    ])
    .split(frame.area());

    let top = Layout::horizontal([Constraint::Percentage(58), Constraint::Percentage(42)]).split(chunks[1]);
    let middle = Layout::horizontal([Constraint::Percentage(62), Constraint::Percentage(38)]).split(chunks[2]);
    let side_chunks =
        Layout::vertical([Constraint::Percentage(42), Constraint::Percentage(58)]).split(middle[1]);

    let title = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("STEAM ", Style::default().fg(Theme::ACCENT).add_modifier(Modifier::BOLD)),
            Span::styled("MANIFEST DOWNLOADER", Style::default().fg(Theme::TITLE).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("Mode: ", Style::default().fg(Theme::MUTED)),
            Span::styled(app.mode.label(), Style::default().fg(Theme::ACCENT_ALT).add_modifier(Modifier::BOLD)),
            Span::styled("  |  Run: ", Style::default().fg(Theme::MUTED)),
            Span::styled(app.run_mode.label(), Style::default().fg(Theme::INPUT).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("Made by ", Style::default().fg(Theme::MUTED)),
            Span::styled(
                " @borgox ",
                Style::default()
                    .fg(Theme::BG)
                    .bg(Theme::INPUT)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
    ])
    .block(panel("Overview", Theme::ACCENT_ALT));
    frame.render_widget(title, chunks[0]);

    let app_id_style = if app.focus == FocusField::AppId && app.run_mode.needs_app_id() {
        Style::default().fg(Theme::INPUT).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
    } else {
        Style::default().fg(Theme::TITLE)
    };
    let api_style = if app.focus == FocusField::ApiKey {
        Style::default().fg(Theme::INPUT).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
    } else {
        Style::default().fg(Theme::TITLE)
    };
    let api_key_display = if app.mode.needs_api_key() {
        if app.api_key.is_empty() {
            "<empty>".to_string()
        } else {
            format!(
                "{}{}",
                "*".repeat(app.api_key.len().min(16)),
                if app.api_key.len() > 16 { "..." } else { "" }
            )
        }
    } else {
        "not required".to_string()
    };
    let inputs = vec![
        if app.run_mode.needs_app_id() {
            Line::from(vec![
                Span::styled("AppID   ", Style::default().fg(Theme::MUTED)),
                Span::styled(
                    if app.app_id.is_empty() { "<enter app id>" } else { &app.app_id },
                    app_id_style,
                ),
            ])
        } else {
            let path_label = if let Some(ref path) = app.custom_lua_dir {
                format!("Every .lua file in {}", path.display())
            } else {
                "Every .lua file in Steam\\config\\stplug-in".to_string()
            };
            Line::from(vec![
                Span::styled("Scope   ", Style::default().fg(Theme::MUTED)),
                Span::styled(
                    path_label,
                    Style::default().fg(Theme::ACCENT).add_modifier(Modifier::BOLD),
                ),
            ])
        },
        Line::from(vec![
            Span::styled("API Key ", Style::default().fg(Theme::MUTED)),
            Span::styled(api_key_display, api_style),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Tab", key_style()),
            Span::styled(" switch field   ", Style::default().fg(Theme::MUTED)),
            Span::styled("F2", key_style()),
            Span::styled(" source   ", Style::default().fg(Theme::MUTED)),
            Span::styled("F3", key_style()),
            Span::styled(" run mode   ", Style::default().fg(Theme::MUTED)),
            Span::styled("R", key_style()),
            Span::styled(" reset   ", Style::default().fg(Theme::MUTED)),
            Span::styled("Esc", key_style()),
            Span::styled(" quit", Style::default().fg(Theme::MUTED)),
        ]),
    ];
    let input_panel = Paragraph::new(inputs).block(panel("Controls", Theme::ACCENT));
    frame.render_widget(input_panel, top[0]);

    let summary_rows = if let Some(summary) = &app.summary {
        vec![
            summary_row("Target", &summary.target_label),
            summary_row("Apps", &summary.app_count.to_string()),
            summary_row("Lua files", &summary.lua_files.to_string()),
            summary_row("Failed apps", &summary.failed_apps.to_string()),
            summary_row("Queued depots", &summary.total.to_string()),
            summary_row("Unique depots", &summary.depot_ids.len().to_string()),
            summary_row("Downloaded", &summary.downloaded.to_string()),
            summary_row("Skipped", &summary.skipped.to_string()),
            summary_row("Unavailable", &summary.unavailable.to_string()),
            summary_row("Failed", &summary.failed.to_string()),
            summary_row("Download size", &format_size(summary.downloaded_bytes)),
            summary_row("Elapsed", &summary.elapsed),
            summary_row("Steam", &truncate_path(&summary.steam_path, 30)),
            summary_row("Output", &truncate_path(&summary.output_path, 30)),
        ]
    } else {
        vec![
            summary_row("Target", "-"),
            summary_row("Apps", "-"),
            summary_row("Lua files", "-"),
            summary_row("Failed apps", "-"),
            summary_row("Queued depots", "-"),
            summary_row("Unique depots", "-"),
            summary_row("Downloaded", "-"),
            summary_row("Skipped", "-"),
            summary_row("Unavailable", "-"),
            summary_row("Failed", "-"),
            summary_row("Download size", "-"),
            summary_row("Elapsed", "-"),
            summary_row("Steam", "-"),
            summary_row("Output", "-"),
        ]
    };
    let summary = Table::new(summary_rows, [Constraint::Length(14), Constraint::Min(20)])
        .row_highlight_style(Style::default().bg(Theme::PANEL))
        .block(panel("Run Summary", Theme::ACCENT_ALT));
    frame.render_widget(summary, top[1]);

    let log_lines: Vec<Line> = app
        .logs
        .iter()
        .rev()
        .take(chunks[3].height.saturating_sub(2) as usize)
        .rev()
        .map(|line| style_log_line(line))
        .collect();
    let log_panel = Paragraph::new(log_lines)
        .wrap(Wrap { trim: false })
        .block(panel("Activity Log", Theme::WARNING));
    frame.render_widget(log_panel, middle[0]);

    let side_lines = vec![
        Line::from(vec![
            Span::styled("Selected Mode", Style::default().fg(Theme::MUTED)),
        ]),
        Line::from(vec![
            Span::styled(app.mode.label(), Style::default().fg(Theme::ACCENT_ALT).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Run Mode", Style::default().fg(Theme::MUTED)),
        ]),
        Line::from(vec![
            Span::styled(app.run_mode.label(), Style::default().fg(Theme::INPUT).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Focus", Style::default().fg(Theme::MUTED)),
        ]),
        Line::from(vec![
            Span::styled(
                match (app.focus, app.run_mode) {
                    (FocusField::AppId, RunMode::SingleApp) => "AppID field",
                    (FocusField::AppId, RunMode::FullRebase) => "Batch scope",
                    (FocusField::ApiKey, _) => "API key field",
                },
                Style::default().fg(Theme::INPUT).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Progress", Style::default().fg(Theme::MUTED)),
        ]),
        Line::from(vec![
            Span::styled(format!("{}%", app.progress), Style::default().fg(Theme::SUCCESS).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Hint", Style::default().fg(Theme::MUTED)),
        ]),
        Line::from("Use Full Rebase to process every Lua file in target directory."),
    ];
    let side_panel = Paragraph::new(side_lines).block(panel("Session", Theme::SUCCESS));
    frame.render_widget(side_panel, side_chunks[0]);

    let error_lines: Vec<Line> = if let Some(summary) = &app.summary {
        if summary.recent_errors.is_empty() {
            vec![Line::from(Span::styled(
                "No recent batch errors.",
                Style::default().fg(Theme::SUCCESS),
            ))]
        } else {
            summary
                .recent_errors
                .iter()
                .map(|error| Line::from(Span::styled(error.clone(), Style::default().fg(Theme::ERROR))))
                .collect()
        }
    } else {
        vec![Line::from(Span::styled(
            "Errors from the last run will appear here.",
            Style::default().fg(Theme::MUTED),
        ))]
    };
    let errors_panel = Paragraph::new(error_lines).wrap(Wrap { trim: true }).block(panel(
        "Recent Errors",
        Theme::ERROR,
    ));
    frame.render_widget(errors_panel, side_chunks[1]);

    let status_chunks = Layout::vertical([Constraint::Length(2), Constraint::Length(1)]).split(chunks[3]);
    let progress = Gauge::default()
        .block(panel("Progress", Theme::BORDER))
        .gauge_style(
            Style::default()
                .fg(if app.busy { Theme::ACCENT } else { Theme::ACCENT_ALT })
                .bg(Theme::PANEL)
                .add_modifier(Modifier::BOLD),
        )
        .percent(app.progress)
        .label(format!("{}%", app.progress));
    frame.render_widget(progress, status_chunks[0]);

    let status_text = Paragraph::new(Line::from(Span::styled(
        app.status.clone(),
        Style::default().fg(Theme::TITLE).add_modifier(Modifier::BOLD),
    )))
    .block(panel("Status", Theme::BORDER));
    frame.render_widget(status_text, status_chunks[1]);

    if app.busy {
        let area = centered_rect(60, 12, frame.area());
        frame.render_widget(Clear, area);
        let popup = Paragraph::new("Processing request...\nThe interface will refresh when the current run completes.")
            .alignment(Alignment::Center)
            .block(panel("Working", Theme::ACCENT));
        frame.render_widget(popup, area);
    }
}

fn apply_worker_event(app: &mut App, event: WorkerEvent) -> bool {
    match event {
        WorkerEvent::Reset => {
            app.logs.clear();
            app.summary = None;
            app.progress = 0;
        }
        WorkerEvent::Log(line) => app.push_log(line),
        WorkerEvent::Status(status) => app.status = status,
        WorkerEvent::Progress(progress) => app.progress = progress,
        WorkerEvent::Summary(summary) => app.summary = Some(summary),
        WorkerEvent::Finished => {
            app.busy = false;
            return true;
        }
        WorkerEvent::Failed(error) => {
            app.push_log(format!("[-] {error}"));
            app.status = format!("Error: {error}");
            app.busy = false;
            return true;
        }
    }
    false
}

fn style_log_line(line: &str) -> Line<'_> {
    let style = if line.starts_with("[+]") {
        Style::default().fg(Theme::SUCCESS)
    } else if line.starts_with("[-]") {
        Style::default().fg(Theme::ERROR)
    } else if line.starts_with("[!]") {
        Style::default().fg(Theme::WARNING)
    } else if line.starts_with("[*]") {
        Style::default().fg(Theme::INFO)
    } else {
        Style::default().fg(Theme::TITLE)
    };
    Line::styled(line.to_string(), style)
}

fn panel<'a>(title: &'a str, border_color: Color) -> Block<'a> {
    Block::default()
        .borders(Borders::ALL)
        .style(Style::default().bg(Theme::PANEL))
        .border_style(Style::default().fg(border_color))
        .title(Span::styled(
            format!(" {title} "),
            Style::default().fg(Theme::TITLE).add_modifier(Modifier::BOLD),
        ))
}

fn key_style() -> Style {
    Style::default()
        .fg(Theme::TITLE)
        .bg(Theme::BORDER)
        .add_modifier(Modifier::BOLD)
}

fn summary_row(label: &str, value: &str) -> Row<'static> {
    Row::new([label.to_string(), value.to_string()])
}

fn truncate_path(path: &str, max_len: usize) -> String {
    if path.chars().count() <= max_len {
        path.to_string()
    } else {
        let keep = max_len.saturating_sub(3);
        format!("...{}", path.chars().rev().take(keep).collect::<String>().chars().rev().collect::<String>())
    }
}

fn push_recent_error(errors: &mut Vec<String>, message: String) {
    errors.push(message);
    if errors.len() > 4 {
        let overflow = errors.len() - 4;
        errors.drain(0..overflow);
    }
}

fn centered_rect(percent_x: u16, height: u16, area: Rect) -> Rect {
    let vertical = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(height),
        Constraint::Fill(1),
    ])
    .split(area);
    let horizontal = Layout::horizontal([
        Constraint::Percentage((100 - percent_x) / 2),
        Constraint::Percentage(percent_x),
        Constraint::Percentage((100 - percent_x) / 2),
    ])
    .split(vertical[1]);
    horizontal[1]
}

async fn process_run(client: Client, request: RunRequest, tx: mpsc::UnboundedSender<WorkerEvent>) {
    if let Err(error) = process_run_inner(client, request, &tx).await {
        let _ = tx.send(WorkerEvent::Failed(error.to_string()));
    }
}

async fn process_run_inner(
    client: Client,
    request: RunRequest,
    tx: &mpsc::UnboundedSender<WorkerEvent>,
) -> Result<()> {
    let _ = tx.send(WorkerEvent::Reset);

    let app_id = request.app_id.trim().to_string();
    if request.run_mode.needs_app_id()
        && (app_id.is_empty() || !app_id.chars().all(|ch| ch.is_ascii_digit()))
    {
        bail!("Enter a valid numeric AppID.");
    }
    if request.mode.needs_api_key() && request.api_key.trim().is_empty() {
        bail!("This mode requires an API key.");
    }

    let _ = tx.send(WorkerEvent::Status(match request.run_mode {
        RunMode::SingleApp => format!("Inspecting AppID {app_id}"),
        RunMode::FullRebase => "Preparing full rebase scan".to_string(),
    }));
    let _ = tx.send(WorkerEvent::Log(format!("[*] Source: {}", request.mode.label())));
    let _ = tx.send(WorkerEvent::Log(format!("[*] Run mode: {}", request.run_mode.label())));
    if request.run_mode.needs_app_id() {
        let _ = tx.send(WorkerEvent::Log(format!("[*] AppID: {app_id}")));
    }

    let _ = tx.send(WorkerEvent::Progress(5));
    let _ = tx.send(WorkerEvent::Log("[*] Looking for Steam installation...".to_string()));
    let steam_path = find_steam_path().context("Steam installation not found")?;
    let _ = tx.send(WorkerEvent::Log(format!(
        "[+] Steam found at {}",
        steam_path.display()
    )));

    let depotcache = steam_path.join("depotcache");
    fs::create_dir_all(&depotcache).context("Unable to create depotcache directory")?;
    let _ = tx.send(WorkerEvent::Log(format!(
        "[*] Output: {}",
        depotcache.display()
    )));

    let _ = tx.send(WorkerEvent::Progress(15));
    let jobs = collect_lua_jobs(&steam_path, &request)?;
    if jobs.is_empty() {
        bail!("No eligible Lua files were found.");
    }
    let _ = tx.send(WorkerEvent::Log(format!(
        "[+] Collected {} Lua file(s) to process",
        jobs.len()
    )));

    let started = Instant::now();
    let mut totals = BatchTotals::default();
    let mut all_depots = BTreeSet::new();

    for (job_index, job) in jobs.iter().enumerate() {
        let progress = 20 + ((job_index * 70) / jobs.len()) as u16;
        let _ = tx.send(WorkerEvent::Progress(progress));
        let _ = tx.send(WorkerEvent::Status(format!(
            "Processing app {} ({}/{})",
            job.app_id,
            job_index + 1,
            jobs.len()
        )));
        let _ = tx.send(WorkerEvent::Log(format!(
            "[*] [{} / {}] Checking {}",
            job_index + 1,
            jobs.len(),
            job.lua_path.display()
        )));

        match process_single_lua_job(
            &client,
            &request.mode,
            request.api_key.trim(),
            &depotcache,
            job,
            tx,
        )
        .await
        {
            Ok(job_summary) => {
                totals.app_count += 1;
                totals.total += job_summary.total;
                totals.downloaded += job_summary.downloaded;
                totals.skipped += job_summary.skipped;
                totals.unavailable += job_summary.unavailable;
                totals.failed += job_summary.failed;
                if job_summary.failed > 0 {
                    totals.failed_apps += 1;
                    push_recent_error(
                        &mut totals.recent_errors,
                        format!("App {} had {} failed depot(s)", job.app_id, job_summary.failed),
                    );
                }
                totals.downloaded_bytes += job_summary.downloaded_bytes;
                for depot in job_summary.depot_ids {
                    all_depots.insert(depot);
                }
            }
            Err(error) if request.run_mode == RunMode::FullRebase => {
                totals.failed += 1;
                totals.failed_apps += 1;
                push_recent_error(
                    &mut totals.recent_errors,
                    format!("App {} skipped: {error}", job.app_id),
                );
                let _ = tx.send(WorkerEvent::Log(format!(
                    "[-] App {} skipped: {error}",
                    job.app_id
                )));
            }
            Err(error) => return Err(error),
        }
    }

    let final_status = if totals.failed == 0 {
        "Run completed".to_string()
    } else {
        format!("Run completed with {} errors", totals.failed)
    };
    let _ = tx.send(WorkerEvent::Progress(100));
    let _ = tx.send(WorkerEvent::Status(final_status));
    let _ = tx.send(WorkerEvent::Log("[+] Processing complete.".to_string()));

    let _ = tx.send(WorkerEvent::Summary(RunSummary {
        target_label: if request.run_mode == RunMode::SingleApp {
            app_id
        } else {
            "Full Rebase".to_string()
        },
        steam_path: steam_path.display().to_string(),
        output_path: depotcache.display().to_string(),
        app_count: totals.app_count,
        lua_files: jobs.len(),
        depot_ids: all_depots.into_iter().collect(),
        failed_apps: totals.failed_apps,
        recent_errors: totals.recent_errors,
        total: totals.total,
        downloaded: totals.downloaded,
        skipped: totals.skipped,
        unavailable: totals.unavailable,
        failed: totals.failed,
        downloaded_bytes: totals.downloaded_bytes,
        elapsed: format_elapsed(started.elapsed()),
    }));
    let _ = tx.send(WorkerEvent::Finished);

    Ok(())
}

#[derive(Default)]
struct BatchTotals {
    app_count: usize,
    total: usize,
    downloaded: usize,
    skipped: usize,
    unavailable: usize,
    failed: usize,
    failed_apps: usize,
    downloaded_bytes: u64,
    recent_errors: Vec<String>,
}

struct LuaJob {
    app_id: String,
    lua_path: PathBuf,
}

struct JobSummary {
    depot_ids: Vec<String>,
    total: usize,
    downloaded: usize,
    skipped: usize,
    unavailable: usize,
    failed: usize,
    downloaded_bytes: u64,
}

fn collect_lua_jobs(steam_path: &Path, request: &RunRequest) -> Result<Vec<LuaJob>> {
    let plugin_dir = if let Some(ref path) = request.lua_dir {
        path.clone()
    } else {
        steam_path.join("config").join("stplug-in")
    };
    if !plugin_dir.exists() {
        bail!("Lua directory not found: {}", plugin_dir.display());
    }

    if request.run_mode == RunMode::SingleApp {
        let lua_path = plugin_dir.join(format!("{}.lua", request.app_id.trim()));
        if !lua_path.exists() {
            bail!("Lua file not found: {}", lua_path.display());
        }
        return Ok(vec![LuaJob {
            app_id: request.app_id.trim().to_string(),
            lua_path,
        }]);
    }

    let mut jobs = Vec::new();
    for entry in fs::read_dir(&plugin_dir).context("Unable to scan Lua directory")? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("lua") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        if !stem.chars().all(|ch| ch.is_ascii_digit()) {
            continue;
        }
        jobs.push(LuaJob {
            app_id: stem.to_string(),
            lua_path: path,
        });
    }
    jobs.sort_by(|left, right| left.app_id.cmp(&right.app_id));
    Ok(jobs)
}

async fn process_single_lua_job(
    client: &Client,
    mode: &DownloadMode,
    api_key: &str,
    depotcache: &Path,
    job: &LuaJob,
    tx: &mpsc::UnboundedSender<WorkerEvent>,
) -> Result<JobSummary> {
    let _ = tx.send(WorkerEvent::Log(format!(
        "[*] Reading Lua data for app {}",
        job.app_id
    )));
    let depot_ids =
        extract_depot_ids(&fs::read_to_string(&job.lua_path).context("Unable to read Lua file")?);
    if depot_ids.is_empty() {
        bail!("No valid depot IDs were found in {}", job.lua_path.display());
    }
    let _ = tx.send(WorkerEvent::Log(format!(
        "[+] App {} exposes {} depot IDs",
        job.app_id,
        depot_ids.len()
    )));

    let _ = tx.send(WorkerEvent::Log(format!(
        "[*] Fetching SteamCMD app info for {}",
        job.app_id
    )));
    let response = client
        .get(format!("https://api.steamcmd.net/v1/info/{}", job.app_id))
        .send()
        .await
        .context("SteamCMD request failed")?;
    let body = response.text().await.context("SteamCMD response body could not be read")?;
    let parsed: SteamResponse =
        serde_json::from_str(&body).context("SteamCMD returned invalid JSON")?;
    if parsed.status.as_deref() != Some("success") {
        bail!("SteamCMD API did not return status=success for app {}", job.app_id);
    }

    let queue = build_download_queue(&parsed, &job.app_id, &depot_ids)?;
    if queue.is_empty() {
        bail!("No public manifests were found for app {}", job.app_id);
    }
    let _ = tx.send(WorkerEvent::Log(format!(
        "[+] App {} matched {} public manifests",
        job.app_id,
        queue.len()
    )));

    let mut downloaded = 0usize;
    let mut skipped = 0usize;
    let mut unavailable = 0usize;
    let mut failed = 0usize;
    let mut downloaded_bytes = 0u64;

    for item in &queue {
        let _ = tx.send(WorkerEvent::Log(format!(
            "[*] App {} depot {} -> manifest {}",
            job.app_id, item.depot_id, item.manifest_id
        )));
        match download_manifest(client, mode, api_key, depotcache, item).await {
            Ok(result) if result.outcome == DownloadOutcome::Downloaded => {
                downloaded += 1;
                downloaded_bytes += result.size;
                let _ = tx.send(WorkerEvent::Log(format!(
                    "[+] Depot {} downloaded ({})",
                    item.depot_id,
                    format_size(result.size)
                )));
            }
            Ok(result) if result.outcome == DownloadOutcome::SkippedExisting => {
                skipped += 1;
                let _ = tx.send(WorkerEvent::Log(format!(
                    "[!] Depot {} already up to date ({})",
                    item.depot_id,
                    format_size(result.size)
                )));
            }
            Ok(_) => {
                unavailable += 1;
                let _ = tx.send(WorkerEvent::Log(format!(
                    "[!] Depot {} is not available on the selected source, skipped",
                    item.depot_id
                )));
            }
            Err(error) => {
                failed += 1;
                let _ = tx.send(WorkerEvent::Log(format!(
                    "[-] Depot {} failed: {error}",
                    item.depot_id
                )));
            }
        }
    }

    Ok(JobSummary {
        depot_ids,
        total: queue.len(),
        downloaded,
        skipped,
        unavailable,
        failed,
        downloaded_bytes,
    })
}

fn build_download_queue(
    response: &SteamResponse,
    app_id: &str,
    depot_ids: &[String],
) -> Result<Vec<DownloadItem>> {
    let app_data = response
        .data
        .get(app_id)
        .ok_or_else(|| anyhow!("AppID {app_id} was not present in the SteamCMD response"))?;

    Ok(depot_ids
        .iter()
        .filter_map(|depot_id| {
            let manifest_id = app_data.depots.get(depot_id).and_then(extract_manifest_gid);
            manifest_id.map(|manifest_id| DownloadItem {
                depot_id: depot_id.clone(),
                manifest_id,
            })
        })
        .collect())
}

fn extract_manifest_gid(value: &Value) -> Option<String> {
    value
        .as_object()
        .and_then(|object| object.get("manifests"))
        .and_then(Value::as_object)
        .and_then(|manifests| manifests.get("public"))
        .and_then(Value::as_object)
        .and_then(|public| public.get("gid"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn extract_depot_ids(content: &str) -> Vec<String> {
    let regex =
        Regex::new(r#"addappid\s*\(\s*(\d+)\s*,\s*\d+\s*,\s*"[a-fA-F0-9]+""#).unwrap();
    let depots: BTreeSet<String> = regex
        .captures_iter(content)
        .filter_map(|capture| capture.get(1).map(|matched| matched.as_str().to_string()))
        .collect();
    depots.into_iter().collect()
}

async fn download_manifest(
    client: &Client,
    mode: &DownloadMode,
    api_key: &str,
    depotcache: &Path,
    item: &DownloadItem,
) -> Result<DownloadResult> {
    let filename = format!("{}_{}.manifest", item.depot_id, item.manifest_id);
    let output_path = depotcache.join(&filename);

    if let Ok(metadata) = fs::metadata(&output_path) {
        if metadata.len() > 0 {
            return Ok(DownloadResult {
                outcome: DownloadOutcome::SkippedExisting,
                size: metadata.len(),
            });
        }
        let _ = fs::remove_file(&output_path);
    }

    let github_url = format!(
        "https://raw.githubusercontent.com/qwe213312/k25FCdfEOoEJ42S6/main/{filename}"
    );
    let github_result = try_download_url(client, &github_url, &output_path, 2).await?;
    if github_result.success {
        return Ok(DownloadResult {
            outcome: DownloadOutcome::Downloaded,
            size: github_result.size,
        });
    }

    if github_result.is_404 {
        if let Some(fallback_url) = fallback_url(mode, api_key, item) {
            let fallback_result = try_download_url(client, &fallback_url, &output_path, 5).await?;
            if fallback_result.success {
                return Ok(DownloadResult {
                    outcome: DownloadOutcome::Downloaded,
                    size: fallback_result.size,
                });
            }
            bail!(
                "fallback failed after {} attempts: {}",
                fallback_result.attempts,
                fallback_result.error.unwrap_or_else(|| "unknown error".to_string())
            );
        }

        return Ok(DownloadResult {
            outcome: DownloadOutcome::Unavailable,
            size: 0,
        });
    }

    bail!(
        "GitHub failed after {} attempts: {}",
        github_result.attempts,
        github_result.error.unwrap_or_else(|| "unknown error".to_string())
    );
}

fn fallback_url(mode: &DownloadMode, api_key: &str, item: &DownloadItem) -> Option<String> {
    if api_key.is_empty() {
        return None;
    }

    match mode {
        DownloadMode::Github => None,
        DownloadMode::GithubExternal => Some(format!(
            "https://api.manifesthub1.filegear-sg.me/manifest?apikey={}&depotid={}&manifestid={}",
            api_key, item.depot_id, item.manifest_id
        )),
    }
}

async fn try_download_url(
    client: &Client,
    url: &str,
    output_path: &Path,
    max_retries: usize,
) -> Result<AttemptResult> {
    let mut last_error = None;

    for attempt in 1..=max_retries {
        if output_path.exists() {
            let _ = fs::remove_file(output_path);
        }

        match client.get(url).send().await {
            Ok(response) if response.status().is_success() => {
                let bytes = response.bytes().await?;
                if bytes.is_empty() {
                    last_error = Some("empty file".to_string());
                } else {
                    fs::write(output_path, &bytes)?;
                    return Ok(AttemptResult {
                        success: true,
                        is_404: false,
                        size: bytes.len() as u64,
                        attempts: attempt,
                        error: None,
                    });
                }
            }
            Ok(response) if response.status() == StatusCode::NOT_FOUND => {
                return Ok(AttemptResult {
                    success: false,
                    is_404: true,
                    size: 0,
                    attempts: attempt,
                    error: Some("not found (404)".to_string()),
                });
            }
            Ok(response) => {
                last_error = Some(format!("HTTP {}", response.status()));
            }
            Err(error) => {
                last_error = Some(error.to_string());
            }
        }

        if attempt < max_retries {
            sleep(Duration::from_secs(3)).await;
        }
    }

    Ok(AttemptResult {
        success: false,
        is_404: false,
        size: 0,
        attempts: max_retries,
        error: last_error,
    })
}

fn format_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

fn format_elapsed(duration: std::time::Duration) -> String {
    let total_seconds = duration.as_secs();
    let minutes = total_seconds / 60;
    let seconds = total_seconds % 60;
    format!("{minutes:02}:{seconds:02}")
}

fn find_steam_path() -> Result<PathBuf> {
    #[cfg(windows)]
    {
        if let Some(path) = find_steam_path_from_registry() {
            return Ok(path);
        }
    }

    let mut candidates = Vec::new();
    if let Some(program_files_x86) = std::env::var_os("ProgramFiles(x86)") {
        candidates.push(PathBuf::from(program_files_x86).join("Steam"));
    }
    if let Some(program_files) = std::env::var_os("ProgramFiles") {
        candidates.push(PathBuf::from(program_files).join("Steam"));
    }
    candidates.push(PathBuf::from(r"C:\Program Files (x86)\Steam"));
    candidates.push(PathBuf::from(r"C:\Programmi (x86)\Steam"));
    candidates.push(PathBuf::from(r"D:\Steam"));

    for path in candidates {
        if looks_like_steam_dir(&path) {
            return Ok(path);
        }
    }

    bail!("Steam installation not found.")
}

fn looks_like_steam_dir(path: &Path) -> bool {
    path.join("steam.exe").exists()
        || path.join("Steam.exe").exists()
        || path.join("config").join("stplug-in").exists()
}

#[cfg(windows)]
fn find_steam_path_from_registry() -> Option<PathBuf> {
    use winreg::RegKey;
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

    let entries = [
        (HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Valve\Steam"),
        (HKEY_LOCAL_MACHINE, r"SOFTWARE\Valve\Steam"),
        (HKEY_CURRENT_USER, r"SOFTWARE\Valve\Steam"),
    ];

    for (hive, subkey) in entries {
        let key = RegKey::predef(hive);
        if let Ok(opened) = key.open_subkey(subkey) {
            let install_path: Result<String, _> = opened.get_value("InstallPath");
            if let Ok(path) = install_path {
                let steam_path = PathBuf::from(path);
                if looks_like_steam_dir(&steam_path) {
                    return Some(steam_path);
                }
            }
        }
    }

    None
}
