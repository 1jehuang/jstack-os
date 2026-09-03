use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

const NOTIFICATION_STATE_FILE: &str = "/tmp/battery-shutdown-notified";
const SHUTDOWN_THRESHOLD: u32 = 2;

// Battery icons (Material Design Icons)
const ICONS: [&str; 10] = [
    "\u{F007A}", // battery-10
    "\u{F007B}", // battery-20
    "\u{F007C}", // battery-30
    "\u{F007D}", // battery-40
    "\u{F007E}", // battery-50
    "\u{F007F}", // battery-60
    "\u{F0080}", // battery-70
    "\u{F0081}", // battery-80
    "\u{F0082}", // battery-90
    "\u{F0079}", // battery-100
];
const ICON_CHARGING: &str = "\u{F0084}";
const ICON_PLUGGED: &str = "\u{F06A5}";

struct Config {
    battery: String,
    high: u32,
    medium: u32,
    warning: u32,
    critical: u32,
}

impl Config {
    fn from_env() -> Self {
        Self {
            battery: env::var("WAYBAR_BATTERY").unwrap_or_else(|_| "BAT0".to_string()),
            high: env::var("WAYBAR_BATTERY_HIGH")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(80),
            medium: env::var("WAYBAR_BATTERY_MEDIUM")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(60),
            warning: env::var("WAYBAR_BATTERY_WARNING")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(40),
            critical: env::var("WAYBAR_BATTERY_CRITICAL")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(20),
        }
    }

    fn base_path(&self) -> String {
        format!("/sys/class/power_supply/{}", self.battery)
    }
}

fn read_int(base: &str, name: &str) -> Option<i64> {
    fs::read_to_string(format!("{}/{}", base, name))
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

fn read_str(base: &str, name: &str) -> Option<String> {
    fs::read_to_string(format!("{}/{}", base, name))
        .ok()
        .map(|s| s.trim().to_string())
}

fn pick_icon(capacity: u32) -> &'static str {
    let idx = (capacity / 10).min(9) as usize;
    ICONS[idx]
}

fn compute_hours(base: &str, status: &str) -> Option<f64> {
    let (now, full, rate) = if let (Some(en), Some(ef), Some(pn)) = (
        read_int(base, "energy_now"),
        read_int(base, "energy_full"),
        read_int(base, "power_now"),
    ) {
        (en, ef, pn)
    } else if let (Some(cn), Some(cf), Some(cu)) = (
        read_int(base, "charge_now"),
        read_int(base, "charge_full"),
        read_int(base, "current_now"),
    ) {
        (cn, cf, cu)
    } else {
        return None;
    };

    let rate = rate.abs();
    if rate <= 0 {
        return None;
    }

    let remaining = match status {
        "Charging" => (full - now).max(0),
        "Discharging" => now.max(0),
        _ => return None,
    };

    Some(remaining as f64 / rate as f64)
}

fn format_time(hours: Option<f64>) -> String {
    match hours {
        Some(h) if h > 0.0 => {
            if h < 1.0 {
                let minutes = (h * 60.0).round().max(1.0) as u32;
                format!("{} min", minutes)
            } else {
                let rounded = (h * 10.0).round() / 10.0;
                let s = format!("{:.1}", rounded);
                let s = s.trim_end_matches('0').trim_end_matches('.');
                format!("{} h", s)
            }
        }
        _ => String::new(),
    }
}

fn compute_minutes_to_threshold(base: &str, capacity: u32) -> Option<f64> {
    if capacity <= SHUTDOWN_THRESHOLD {
        return Some(0.0);
    }

    let (full, rate) = if let (Some(ef), Some(pn)) = (
        read_int(base, "energy_full"),
        read_int(base, "power_now"),
    ) {
        (ef, pn)
    } else if let (Some(cf), Some(cu)) = (
        read_int(base, "charge_full"),
        read_int(base, "current_now"),
    ) {
        (cf, cu)
    } else {
        return None;
    };

    let rate = rate.abs();
    if rate <= 0 {
        return None;
    }

    let threshold_energy = full as f64 * (SHUTDOWN_THRESHOLD as f64 / 100.0);
    let current_energy = full as f64 * (capacity as f64 / 100.0);
    let remaining = current_energy - threshold_energy;

    if remaining <= 0.0 {
        return Some(0.0);
    }

    Some((remaining / rate as f64) * 60.0)
}

fn check_shutdown_warning(base: &str, capacity: u32, status: &str) {
    if status != "Discharging" {
        let _ = fs::remove_file(NOTIFICATION_STATE_FILE);
        return;
    }

    let Some(minutes_left) = compute_minutes_to_threshold(base, capacity) else {
        return;
    };

    let notified = Path::new(NOTIFICATION_STATE_FILE).exists();

    if minutes_left <= 1.0 && !notified {
        let _ = Command::new("notify-send")
            .args([
                "-u", "critical",
                "-i", "battery-empty",
                "Battery Critical",
                &format!("~1 minute until shutdown at {}%! Plug in now!", SHUTDOWN_THRESHOLD),
            ])
            .spawn();
        let _ = fs::write(NOTIFICATION_STATE_FILE, capacity.to_string());
    } else if minutes_left > 2.0 && notified {
        let _ = fs::remove_file(NOTIFICATION_STATE_FILE);
    }
}

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn main() {
    let config = Config::from_env();
    let base = config.base_path();

    if !Path::new(&base).is_dir() {
        println!(r#"{{"text": "", "class": "disconnected"}}"#);
        return;
    }

    let Some(capacity) = read_int(&base, "capacity").map(|c| c as u32) else {
        println!(r#"{{"text": "", "class": "disconnected"}}"#);
        return;
    };

    let status = read_str(&base, "status").unwrap_or_else(|| "Unknown".to_string());

    // Check for imminent shutdown warning
    check_shutdown_warning(&base, capacity, &status);

    let hours = compute_hours(&base, &status);
    let time_str = format_time(hours);

    // Build CSS classes
    let mut classes: Vec<String> = Vec::new();
    if capacity <= config.critical {
        classes.push("critical".to_string());
    } else if capacity <= config.warning {
        classes.push("warning".to_string());
    } else if capacity <= config.medium {
        classes.push("medium".to_string());
    } else if capacity > config.high {
        classes.push("high".to_string());
    }
    classes.push(status.to_lowercase().replace(' ', "-"));

    let (_icon, text, tooltip) = match status.as_str() {
        "Charging" => {
            let text = if time_str.is_empty() {
                format!("{} {}%", ICON_CHARGING, capacity)
            } else {
                format!("{} {}% ({})", ICON_CHARGING, capacity, time_str)
            };
            let tooltip = if time_str.is_empty() {
                format!("Battery: {}%\nTime until full: n/a", capacity)
            } else {
                format!("Battery: {}%\nTime until full: {}", capacity, time_str)
            };
            (ICON_CHARGING, text, tooltip)
        }
        "Discharging" => {
            let icon = pick_icon(capacity);
            let text = if time_str.is_empty() {
                format!("{} {}%", icon, capacity)
            } else {
                format!("{} {}% ({})", icon, capacity, time_str)
            };
            let tooltip = if time_str.is_empty() {
                format!("Battery: {}%\nTime remaining: n/a", capacity)
            } else {
                format!("Battery: {}%\nTime remaining: {}", capacity, time_str)
            };
            (icon, text, tooltip)
        }
        _ => {
            let tooltip = if status == "Full" {
                format!("Battery: {}%\nFully charged", capacity)
            } else if status != "Unknown" {
                format!("Battery: {}%\nStatus: {}", capacity, status)
            } else {
                format!("Battery: {}%", capacity)
            };
            let text = format!("{} {}%", ICON_PLUGGED, capacity);
            (ICON_PLUGGED, text, tooltip)
        }
    };

    println!(
        r#"{{"text": "{}", "tooltip": "{}", "class": "{}"}}"#,
        escape_json(&text),
        escape_json(&tooltip),
        classes.join(" ")
    );
}
