// infra-session: Session persistence.
//
// Stores recent files and window state as JSON in the user's config directory.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// An entry in the recent files list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentFile {
    pub path: PathBuf,
    pub last_opened: String,
}

/// Window geometry to restore on next launch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowState {
    pub width: f32,
    pub height: f32,
}

impl Default for WindowState {
    fn default() -> Self {
        Self {
            width: 1280.0,
            height: 800.0,
        }
    }
}

/// Bookmark at a byte offset in a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bookmark {
    pub file_path: PathBuf,
    pub offset: u64,
    pub label: String,
}

/// Session state that is persisted across app launches.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionState {
    pub recent_files: Vec<RecentFile>,
    pub window: WindowState,
    pub bookmarks: Vec<Bookmark>,
    /// Path of the last file that was open when the app closed (legacy, single-file).
    /// Kept for backward compatibility with older session files.
    #[serde(default)]
    pub last_open_file: Option<PathBuf>,
    /// Paths of all file tabs that were open when the app closed.
    #[serde(default)]
    pub last_open_files: Vec<PathBuf>,
    /// Index of the active tab at close time.
    #[serde(default)]
    pub last_active_tab: usize,
    /// Serialized dock layout (JSON blob from egui_dock::DockState).
    /// Stored as a raw Value to decouple infra-session from egui_dock types.
    #[serde(default)]
    pub dock_layout: Option<serde_json::Value>,
}

impl SessionState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_recent(&mut self, path: PathBuf) {
        self.recent_files.retain(|r| r.path != path);
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        self.recent_files.insert(
            0,
            RecentFile {
                path,
                last_opened: now,
            },
        );
        self.recent_files.truncate(20);
    }

    pub fn add_bookmark(&mut self, file_path: PathBuf, offset: u64, label: String) {
        // Don't duplicate same file+offset.
        self.bookmarks
            .retain(|b| !(b.file_path == file_path && b.offset == offset));
        self.bookmarks.push(Bookmark {
            file_path,
            offset,
            label,
        });
    }

    pub fn remove_bookmark(&mut self, file_path: &Path, offset: u64) {
        self.bookmarks
            .retain(|b| !(b.file_path == file_path && b.offset == offset));
    }

    pub fn bookmarks_for_file(&self, file_path: &Path) -> Vec<&Bookmark> {
        self.bookmarks
            .iter()
            .filter(|b| b.file_path == file_path)
            .collect()
    }
}

/// Get the session file path: ~/.tinkerspark/session.json
pub fn session_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".tinkerspark").join("session.json"))
}

/// Load session state from disk. Returns default if file doesn't exist
/// or can't be parsed.
pub fn load_session() -> SessionState {
    let Some(path) = session_path() else {
        return SessionState::default();
    };
    match std::fs::read_to_string(&path) {
        Ok(json) => serde_json::from_str(&json).unwrap_or_default(),
        Err(_) => SessionState::default(),
    }
}

/// Save session state to disk. Creates the directory if needed.
/// Errors are logged but not propagated — session loss is not fatal.
pub fn save_session(state: &SessionState) {
    let Some(path) = session_path() else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match serde_json::to_string_pretty(state) {
        Ok(json) => {
            if let Err(e) = std::fs::write(&path, json) {
                eprintln!("Failed to save session: {e}");
            }
        }
        Err(e) => {
            eprintln!("Failed to serialize session: {e}");
        }
    }
}
