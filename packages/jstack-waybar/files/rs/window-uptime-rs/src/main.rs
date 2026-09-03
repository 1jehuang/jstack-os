use niri_ipc::socket::Socket;
use niri_ipc::{Event, Request, Response, Window};
use serde::Serialize;
use std::collections::HashMap;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Persisted state: window_id -> creation unix timestamp
type PersistedState = HashMap<String, f64>;

fn state_path() -> PathBuf {
    let cache = std::env::var("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
            PathBuf::from(home).join(".cache")
        });
    cache.join("niri-window-times.json")
}

fn load_state() -> PersistedState {
    std::fs::read_to_string(state_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_state(state: &PersistedState) {
    if let Ok(json) = serde_json::to_string(state) {
        let _ = std::fs::write(state_path(), json);
    }
}

fn now_unix() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn format_duration(secs: u64) -> String {
    if secs < 60 {
        return format!("{}s", secs);
    }
    let mins = secs / 60;
    if mins < 60 {
        return format!("{}m", mins);
    }
    let hours = mins / 60;
    let m = mins % 60;
    if hours < 24 {
        if m > 0 {
            return format!("{}h{}m", hours, m);
        }
        return format!("{}h", hours);
    }
    let days = hours / 24;
    let h = hours % 24;
    if h > 0 {
        format!("{}d{}h", days, h)
    } else {
        format!("{}d", days)
    }
}

fn format_tooltip(secs: u64) -> String {
    let mut parts = Vec::new();
    let mut rem = secs;
    if rem >= 86400 {
        parts.push(format!("{}d", rem / 86400));
        rem %= 86400;
    }
    if rem >= 3600 {
        parts.push(format!("{}h", rem / 3600));
        rem %= 3600;
    }
    if rem >= 60 {
        parts.push(format!("{}m", rem / 60));
        rem %= 60;
    }
    parts.push(format!("{}s", rem));
    parts.join(" ")
}

#[derive(Serialize)]
struct WaybarOutput {
    text: String,
    tooltip: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    class: String,
}

fn emit(text: &str, tooltip: &str) {
    let out = WaybarOutput {
        text: text.to_string(),
        tooltip: tooltip.to_string(),
        class: String::new(),
    };
    if let Ok(json) = serde_json::to_string(&out) {
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        let _ = writeln!(handle, "{}", json);
        let _ = handle.flush();
    }
}

fn main() {
    loop {
        if let Err(e) = run() {
            eprintln!("window-uptime error: {}, reconnecting in 2s...", e);
            std::thread::sleep(Duration::from_secs(2));
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut window_times = load_state();
    let now = now_unix();

    // Seed current windows
    let windows = fetch_windows()?;
    let current_ids: std::collections::HashSet<String> =
        windows.iter().map(|w| w.id.to_string()).collect();

    for id in &current_ids {
        window_times.entry(id.clone()).or_insert(now);
    }
    // Prune closed windows
    window_times.retain(|k, _| current_ids.contains(k));
    save_state(&window_times);

    // Find initial focused window
    let mut focused_id: Option<u64> = windows.iter().find(|w| w.is_focused).map(|w| w.id);

    // Emit initial state
    emit_uptime(focused_id, &window_times);

    // Subscribe to event stream
    let mut socket = Socket::connect()?;
    let reply = socket.send(Request::EventStream)?;
    match reply {
        Ok(Response::Handled) => {}
        Ok(other) => return Err(format!("Unexpected response: {:?}", other).into()),
        Err(msg) => return Err(msg.into()),
    }

    let mut read_event = socket.read_events();
    let mut last_emit = Instant::now();

    // We need periodic ticks to update the displayed time.
    // The niri event stream is blocking, so we'll use a thread to send tick signals.
    let (tx, rx) = std::sync::mpsc::channel::<EventOrTick>();

    // Tick thread: send a tick every 10s
    let tx_tick = tx.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(10));
        if tx_tick.send(EventOrTick::Tick).is_err() {
            break;
        }
    });

    // Event reader thread
    let tx_event = tx;
    let _event_thread = std::thread::spawn(move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        loop {
            let event = read_event()?;
            if tx_event.send(EventOrTick::Event(event)).is_err() {
                break;
            }
        }
        Ok(())
    });

    loop {
        let msg = rx.recv()?;

        match msg {
            EventOrTick::Event(event) => {
                match event {
                    Event::WindowsChanged { windows } => {
                        let now = now_unix();
                        let new_ids: std::collections::HashSet<String> =
                            windows.iter().map(|w| w.id.to_string()).collect();

                        for id in &new_ids {
                            window_times.entry(id.clone()).or_insert(now);
                        }
                        window_times.retain(|k, _| new_ids.contains(k));
                        save_state(&window_times);

                        focused_id = windows.iter().find(|w| w.is_focused).map(|w| w.id);
                    }
                    Event::WindowOpenedOrChanged { window } => {
                        let id_str = window.id.to_string();
                        window_times.entry(id_str).or_insert(now_unix());
                        save_state(&window_times);
                        if window.is_focused {
                            focused_id = Some(window.id);
                        }
                    }
                    Event::WindowClosed { id } => {
                        window_times.remove(&id.to_string());
                        save_state(&window_times);
                    }
                    Event::WindowFocusChanged { id } => {
                        focused_id = id;
                    }
                    _ => continue,
                }
            }
            EventOrTick::Tick => {}
        }

        // Rate-limit output to avoid spamming waybar
        if last_emit.elapsed() >= Duration::from_millis(500) {
            emit_uptime(focused_id, &window_times);
            last_emit = Instant::now();
        }
    }
}

fn emit_uptime(focused_id: Option<u64>, window_times: &PersistedState) {
    if let Some(id) = focused_id {
        let id_str = id.to_string();
        if let Some(&created) = window_times.get(&id_str) {
            let age = (now_unix() - created).max(0.0) as u64;
            let text = format!(" {}", format_duration(age));
            let tooltip = format_tooltip(age);
            emit(&text, &tooltip);
            return;
        }
    }
    emit("", "");
}

fn fetch_windows() -> Result<Vec<Window>, Box<dyn std::error::Error>> {
    let mut socket = Socket::connect()?;
    match socket.send(Request::Windows)? {
        Ok(Response::Windows(w)) => Ok(w),
        Ok(other) => Err(format!("Unexpected: {:?}", other).into()),
        Err(msg) => Err(msg.into()),
    }
}

enum EventOrTick {
    Event(Event),
    Tick,
}
