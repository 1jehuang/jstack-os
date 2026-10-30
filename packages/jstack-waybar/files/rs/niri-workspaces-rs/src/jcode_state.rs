//! Best-effort Jcode session status for terminal windows. No unknown state is
//! interpreted as completion, and ambiguous process trees are left uncolored.
use serde_json::Value;
use std::collections::{HashMap, HashSet, VecDeque};
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

const MAX_RESPONSE: u64 = 4 * 1024 * 1024;

/// Query every discoverable debug socket. Stale sockets and malformed replies
/// are deliberately ignored so a missing Jcode server cannot break Waybar.
pub fn snapshot() -> HashMap<String, String> {
    let runtime = env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .or_else(|| {
            let uid = env::var("UID")
                .ok()
                .and_then(|s| s.parse::<u32>().ok())
                .or_else(|| fs::metadata("/proc/self").ok().map(|m| m.uid()))?;
            Some(PathBuf::from(format!("/run/user/{uid}")))
        });
    let mut dirs = vec![PathBuf::from("/tmp")];
    if let Some(runtime) = runtime {
        dirs.insert(0, runtime);
    }
    let mut states = HashMap::new();
    let mut visited = HashSet::new();
    for dir in dirs {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if !name.starts_with("jcode")
                || !name.ends_with("-debug.sock")
                || !entry.file_type().is_ok_and(|t| t.is_socket())
                || !visited.insert(entry.path())
            {
                continue;
            }
            if let Some(found) = query_socket(&entry.path()) {
                states.extend(found);
            }
        }
    }
    states
}

fn query_socket(path: &Path) -> Option<HashMap<String, String>> {
    let mut stream = UnixStream::connect(path).ok()?;
    let timeout = Some(Duration::from_millis(200));
    stream.set_read_timeout(timeout).ok()?;
    stream.set_write_timeout(timeout).ok()?;
    stream
        .write_all(
            b"{\"type\":\"debug_command\",\"id\":1,\"command\":\"sessions\",\"session_id\":null}\n",
        )
        .ok()?;
    let mut line = Vec::new();
    // Take before buffering so no more than the limit plus one byte is read.
    BufReader::new(stream.take(MAX_RESPONSE + 1))
        .read_until(b'\n', &mut line)
        .ok()?;
    if line.len() as u64 > MAX_RESPONSE || line.last() != Some(&b'\n') {
        return None;
    }
    let response: Value = serde_json::from_slice(&line).ok()?;
    parse_response(&response)
}

fn parse_response(response: &Value) -> Option<HashMap<String, String>> {
    if response.get("type")?.as_str()? != "debug_response" || response.get("ok")?.as_bool()? != true
    {
        return None;
    }
    let output: Value = serde_json::from_str(response.get("output")?.as_str()?).ok()?;
    let mut states = HashMap::new();
    for session in output.as_array()? {
        if let (Some(id), Some(status)) = (
            session.get("session_id").and_then(Value::as_str),
            session.get("status").and_then(Value::as_str),
        ) {
            if !id.is_empty() {
                states.insert(id.to_owned(), status.to_owned());
            }
        }
    }
    Some(states)
}

fn state_color(state: &str) -> Option<&'static str> {
    match state {
        "running" => Some("#89dceb"),
        "blocked" => Some("#f38ba8"),
        "ready" | "idle" | "done" | "completed" => Some("#a6e3a1"),
        _ => None,
    }
}

/// Resolve an exact session title (also works over SSH), otherwise a unique
/// locally registered client below this window's PID. Shared terminal-server
/// PIDs with several sessions are ambiguous and intentionally get no color.
pub fn window_color(
    pid: Option<i32>,
    title: &str,
    states: &HashMap<String, String>,
) -> Option<&'static str> {
    let titled: Vec<_> = states.keys().filter(|id| title_has_id(title, id)).collect();
    if titled.len() == 1 {
        return states.get(titled[0]).and_then(|s| state_color(s));
    }
    if titled.len() > 1 {
        return None;
    }
    let pid = pid.filter(|p| *p > 0)? as u32;
    let home = env::var_os("JCODE_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|p| PathBuf::from(p).join(".jcode")))?;
    let session = registered_session(pid, &home.join("client_sessions"), Path::new("/proc"))?;
    states.get(&session).and_then(|s| state_color(s))
}

fn title_has_id(title: &str, id: &str) -> bool {
    !id.is_empty()
        && title.match_indices(id).any(|(start, _)| {
            let end = start + id.len();
            let token = |c: char| c.is_alphanumeric() || c == '_' || c == '-';
            !title[..start].chars().next_back().is_some_and(token)
                && !title[end..].chars().next().is_some_and(token)
        })
}

fn is_terminal(proc: &Path, pid: u32) -> bool {
    let dir = proc.join(pid.to_string());
    let executable = fs::read_link(dir.join("exe")).ok();
    let comm = fs::read_to_string(dir.join("comm")).unwrap_or_default();
    let name = executable
        .as_deref()
        .and_then(Path::file_name)
        .and_then(|s| s.to_str())
        .unwrap_or(comm.trim());
    matches!(
        name,
        "kitty"
            | "alacritty"
            | "foot"
            | "footclient"
            | "wezterm"
            | "wezterm-gui"
            | "gnome-terminal"
            | "gnome-terminal-server"
            | "konsole"
            | "xterm"
            | "st"
            | "ghostty"
            | "rio"
            | "kgx"
            | "tilix"
            | "terminator"
            | "urxvt"
            | "urxvtd"
    )
}

fn registered_session(root: u32, registry: &Path, proc: &Path) -> Option<String> {
    let mut queue = VecDeque::from([root]);
    let mut visited = HashSet::new();
    let mut sessions = HashSet::new();
    while let Some(pid) = queue.pop_front() {
        if !visited.insert(pid) || (pid != root && is_terminal(proc, pid)) {
            continue;
        }
        if let Ok(id) = fs::read_to_string(registry.join(pid.to_string())) {
            let id = id.trim();
            if !id.is_empty() {
                sessions.insert(id.to_owned());
            }
        }
        // Check all task children, not just the thread-group leader.
        let Ok(tasks) = fs::read_dir(proc.join(pid.to_string()).join("task")) else {
            continue;
        };
        for task in tasks.flatten() {
            if let Ok(children) = fs::read_to_string(task.path().join("children")) {
                queue.extend(
                    children
                        .split_whitespace()
                        .filter_map(|p| p.parse::<u32>().ok()),
                );
            }
        }
    }
    if sessions.len() == 1 {
        sessions.into_iter().next()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_colors_only() {
        assert_eq!(state_color("running"), Some("#89dceb"));
        assert_eq!(state_color("blocked"), Some("#f38ba8"));
        for state in ["ready", "idle", "done", "completed"] {
            assert_eq!(state_color(state), Some("#a6e3a1"));
        }
        for state in ["", "unknown", "stopped", "failed", "null"] {
            assert_eq!(state_color(state), None);
        }
    }

    #[test]
    fn response_ignores_missing_status() {
        let response = serde_json::json!({"type":"debug_response", "ok":true,
            "output": r#"[{"session_id":"a","status":"running"},{"session_id":"b","status":null},{"session_id":"c","status":"mystery"}]"#});
        let states = parse_response(&response).unwrap();
        assert_eq!(states.len(), 2);
        assert_eq!(states.get("a").map(String::as_str), Some("running"));
        assert!(!states.contains_key("b"));
        assert_eq!(window_color(None, "remote: c", &states), None);
        assert!(parse_response(
            &serde_json::json!({"type":"debug_response","ok":false,"output":"[]"})
        )
        .is_none());
    }

    #[test]
    fn remote_title_requires_full_unambiguous_id() {
        let states = HashMap::from([
            ("session_fox_123".into(), "running".into()),
            ("session_cat_456".into(), "blocked".into()),
        ]);
        assert_eq!(
            window_color(None, "SSH [session_fox_123]", &states),
            Some("#89dceb")
        );
        assert_eq!(window_color(None, "session_fox_1234", &states), None);
        assert_eq!(window_color(None, "fox", &states), None);
        assert_eq!(
            window_color(None, "session_fox_123 session_cat_456", &states),
            None
        );
    }

    #[test]
    fn socket_protocol_and_response_bound() {
        use std::os::unix::net::UnixListener;
        for oversized in [false, true] {
            let path = env::temp_dir().join(format!(
                "jcode-state-socket-{}-{oversized}",
                std::process::id()
            ));
            let listener = UnixListener::bind(&path).unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = String::new();
                BufReader::new(stream.try_clone().unwrap())
                    .read_line(&mut request)
                    .unwrap();
                let request: Value = serde_json::from_str(&request).unwrap();
                assert_eq!(request["command"], "sessions");
                assert_eq!(request["type"], "debug_command");
                if oversized {
                    // Client closes at its cap, so BrokenPipe is expected.
                    let _ = stream.write_all(&vec![b'x'; MAX_RESPONSE as usize + 2]);
                } else {
                    let reply = serde_json::json!({"type":"debug_response","ok":true,
                        "output":"[{\"session_id\":\"socket_session\",\"status\":\"blocked\"}]"});
                    writeln!(stream, "{reply}").unwrap();
                }
            });
            let states = query_socket(&path);
            server.join().unwrap();
            fs::remove_file(path).unwrap();
            if oversized {
                assert!(states.is_none());
            } else {
                assert_eq!(
                    states.unwrap().get("socket_session").map(String::as_str),
                    Some("blocked")
                );
            }
        }
    }

    #[test]
    fn fixture_registry_excludes_nested_terminals_and_ambiguous_clients() {
        let root = env::temp_dir().join(format!("jcode-state-test-{}", std::process::id()));
        fs::create_dir_all(root.join("registry")).unwrap();
        let proc = root.join("proc");
        for (pid, children, comm) in [
            (10, "11 20", "kitty"),
            (11, "12", "bash"),
            (12, "", "jcode"),
            (20, "21", "alacritty"),
            (21, "", "jcode"),
        ] {
            let task = proc.join(format!("{pid}/task/{pid}"));
            fs::create_dir_all(&task).unwrap();
            fs::write(task.join("children"), children).unwrap();
            fs::write(proc.join(format!("{pid}/comm")), comm).unwrap();
        }
        let registry = root.join("registry");
        fs::write(registry.join("12"), "session_a\n").unwrap();
        fs::write(registry.join("21"), "session_b").unwrap();
        fs::write(registry.join("999"), "stale").unwrap();
        assert_eq!(
            registered_session(10, &registry, &proc).as_deref(),
            Some("session_a")
        );
        fs::write(registry.join("11"), "session_c").unwrap();
        assert_eq!(registered_session(10, &registry, &proc), None);
        fs::write(registry.join("11"), "session_a").unwrap();
        assert_eq!(
            registered_session(10, &registry, &proc).as_deref(),
            Some("session_a")
        );
        fs::remove_dir_all(root).unwrap();
    }
}
