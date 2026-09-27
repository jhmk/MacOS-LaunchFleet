//! Privileged helper channel.
//!
//! # Why this exists
//!
//! The previous implementation ran
//! `osascript -e 'do shell script "sudo -v" with administrator privileges'`
//! and then assumed later `sudo -n ...` calls from the *app* process would
//! succeed. They cannot: `do shell script ... with administrator privileges`
//! runs the command as **root** via `security_authtrampoline`, so `sudo -v`
//! refreshes the timestamp for uid 0, not for the logged-in user. The app then
//! calls `sudo -n` as uid 501 and gets "a password is required". macOS also
//! defaults to `tty_tickets`, and a GUI app has no controlling tty.
//!
//! # Design
//!
//! On activation we re-exec **our own binary** as root with
//! `--privileged-helper <dir>`. Parent and helper talk over a pair of FIFOs
//! inside a 0700 directory. The channel does **not** carry shell commands: it
//! carries a closed [`Request`] enum, and the root side re-validates every path
//! against an allowlist before touching the filesystem. A compromised webview
//! therefore cannot turn this into arbitrary root code execution.
//!
//! Activation performs a `Ping`/`Pong` handshake and asserts `uid == 0`. If the
//! handshake fails, activation fails — System Mode never reports success
//! unless a working root channel actually exists.
//!
//! ## Known limitation
//!
//! While active, any process running as the *same user* that can guess the
//! random FIFO path and read the token could issue privileged operations. This
//! is the same trust boundary as a cached `sudo` timestamp. The directory is
//! 0700 with a random name, and the token is sent over the FIFO (never written
//! to disk and never passed in argv, where `ps` would expose it).

use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Directories whose plists we are willing to touch with root privileges.
/// `/System` is deliberately absent: it is on the sealed read-only volume and
/// protected by SIP.
pub const ALLOWED_PRIVILEGED_DIRS: &[&str] = &["/Library/LaunchDaemons", "/Library/LaunchAgents"];

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

// ───────────────────────── Wire protocol ─────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum Request {
    Ping,
    /// `launchctl enable|disable <domain>/<label>`
    SetEnabled {
        domain: String,
        label: String,
        enabled: bool,
    },
    /// `launchctl bootout <domain>/<label>`
    Bootout { domain: String, label: String },
    /// `launchctl bootstrap <domain> <plist>`
    Bootstrap { domain: String, plist: PathBuf },
    /// `launchctl print <domain>` — used to read system-domain service state.
    PrintDomain { domain: String },
    /// Move a plist into the quarantine directory (reversible "delete").
    Quarantine { src: PathBuf, dest: PathBuf },
    /// Move a quarantined plist back to its original location.
    Restore { src: PathBuf, dest: PathBuf },
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub id: u64,
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
    /// Effective uid of the helper. Used by the handshake to prove we are root.
    #[serde(default)]
    pub uid: u32,
}

impl Response {
    pub fn ok(&self) -> bool {
        self.code == 0
    }

    /// Best-effort human-readable failure reason.
    pub fn error_text(&self) -> String {
        let s = self.stderr.trim();
        if !s.is_empty() {
            return s.to_string();
        }
        let o = self.stdout.trim();
        if !o.is_empty() {
            return o.to_string();
        }
        format!("exit code {}", self.code)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Envelope {
    id: u64,
    token: String,
    req: Request,
}

// ───────────────────────── Path validation ─────────────────────────

/// Resolve `p` and confirm it sits inside one of `allowed`.
///
/// Uses `canonicalize` so that `..` traversal and symlinks pointing outside the
/// allowlist are rejected. Enforced on **both** sides of the channel: the
/// client fails fast for a good error message, the root side enforces it for
/// real.
pub fn validate_in_allowed_dirs(p: &Path, allowed: &[&str]) -> Result<PathBuf, String> {
    let canon = p
        .canonicalize()
        .map_err(|e| format!("cannot resolve {}: {}", p.display(), e))?;

    for dir in allowed {
        let base = match Path::new(dir).canonicalize() {
            Ok(b) => b,
            Err(_) => continue,
        };
        if canon.starts_with(&base) {
            return Ok(canon);
        }
    }

    Err(format!(
        "refusing to operate on {} — outside managed directories ({})",
        canon.display(),
        allowed.join(", ")
    ))
}

/// Same as [`validate_in_allowed_dirs`] but for a destination that does not
/// exist yet: the *parent* must resolve into the allowlist.
pub fn validate_parent_in_allowed_dirs(p: &Path, allowed: &[&str]) -> Result<PathBuf, String> {
    let parent = p
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", p.display()))?;
    let canon_parent = validate_in_allowed_dirs(parent, allowed)?;
    let name = p
        .file_name()
        .ok_or_else(|| format!("{} has no file name", p.display()))?;
    Ok(canon_parent.join(name))
}

// ───────────────────────── Helper (root) side ─────────────────────────

/// Entry point for `--privileged-helper <dir>`. Runs as root, never returns a
/// GUI. Exits when the parent closes the request FIFO.
pub fn run_helper(dir: &Path) -> ! {
    let rx_path = dir.join("req");
    let tx_path = dir.join("res");

    // Open in the same order as the client to avoid a FIFO rendezvous deadlock.
    let rx = match File::open(&rx_path) {
        Ok(f) => f,
        Err(_) => std::process::exit(1),
    };
    let mut tx = match OpenOptions::new().write(true).open(&tx_path) {
        Ok(f) => f,
        Err(_) => std::process::exit(1),
    };

    let mut reader = BufReader::new(rx);

    // First line is the shared token.
    let mut token = String::new();
    if reader.read_line(&mut token).is_err() {
        std::process::exit(1);
    }
    let token = token.trim().to_string();
    if token.is_empty() {
        std::process::exit(1);
    }

    let uid = unsafe { libc::geteuid() };

    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,  // parent exited
            Ok(_) => {}
            Err(_) => break,
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let env: Envelope = match serde_json::from_str(line) {
            Ok(e) => e,
            Err(_) => continue,
        };

        // Constant-time-ish token check.
        if !constant_time_eq(env.token.as_bytes(), token.as_bytes()) {
            continue;
        }

        if matches!(env.req, Request::Shutdown) {
            break;
        }

        let mut resp = handle(env.req, uid);
        resp.id = env.id;
        resp.uid = uid;

        if let Ok(json) = serde_json::to_string(&resp) {
            if writeln!(tx, "{}", json).is_err() {
                break;
            }
            let _ = tx.flush();
        }
    }

    std::process::exit(0);
}

fn handle(req: Request, uid: u32) -> Response {
    match req {
        Request::Ping => Response {
            id: 0,
            code: 0,
            stdout: "pong".into(),
            stderr: String::new(),
            uid,
        },

        Request::SetEnabled {
            domain,
            label,
            enabled,
        } => {
            let verb = if enabled { "enable" } else { "disable" };
            run(&["/bin/launchctl", verb, &format!("{}/{}", domain, label)])
        }

        Request::Bootout { domain, label } => run(&[
            "/bin/launchctl",
            "bootout",
            &format!("{}/{}", domain, label),
        ]),

        Request::Bootstrap { domain, plist } => {
            match validate_in_allowed_dirs(&plist, ALLOWED_PRIVILEGED_DIRS) {
                Ok(p) => run(&["/bin/launchctl", "bootstrap", &domain, &p.to_string_lossy()]),
                Err(e) => denied(e),
            }
        }

        Request::PrintDomain { domain } => run(&["/bin/launchctl", "print", &domain]),

        Request::Quarantine { src, dest } => {
            // src must be a managed plist; dest is the app's quarantine dir.
            let src = match validate_in_allowed_dirs(&src, ALLOWED_PRIVILEGED_DIRS) {
                Ok(p) => p,
                Err(e) => return denied(e),
            };
            move_file(&src, &dest)
        }

        Request::Restore { src, dest } => {
            let dest = match validate_parent_in_allowed_dirs(&dest, ALLOWED_PRIVILEGED_DIRS) {
                Ok(p) => p,
                Err(e) => return denied(e),
            };
            move_file(&src, &dest)
        }

        Request::Shutdown => Response {
            id: 0,
            code: 0,
            stdout: String::new(),
            stderr: String::new(),
            uid,
        },
    }
}

fn move_file(src: &Path, dest: &Path) -> Response {
    if let Some(parent) = dest.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return failure(format!("cannot create {}: {}", parent.display(), e));
        }
    }
    // rename() fails across filesystems; fall back to copy+remove.
    match std::fs::rename(src, dest) {
        Ok(_) => success(),
        Err(_) => match std::fs::copy(src, dest).and_then(|_| std::fs::remove_file(src)) {
            Ok(_) => success(),
            Err(e) => failure(format!("cannot move {}: {}", src.display(), e)),
        },
    }
}

fn run(argv: &[&str]) -> Response {
    match Command::new(argv[0]).args(&argv[1..]).output() {
        Ok(out) => Response {
            id: 0,
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            uid: 0,
        },
        Err(e) => failure(format!("failed to execute {}: {}", argv[0], e)),
    }
}

fn success() -> Response {
    Response {
        id: 0,
        code: 0,
        stdout: String::new(),
        stderr: String::new(),
        uid: 0,
    }
}

fn failure(msg: String) -> Response {
    Response {
        id: 0,
        code: -1,
        stdout: String::new(),
        stderr: msg,
        uid: 0,
    }
}

fn denied(msg: String) -> Response {
    Response {
        id: 0,
        code: -2,
        stdout: String::new(),
        stderr: msg,
        uid: 0,
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ───────────────────────── Client (user) side ─────────────────────────

struct Channel {
    writer: File,
    responses: Receiver<Response>,
    next_id: u64,
}

pub struct PrivilegedClient {
    channel: Mutex<Option<Channel>>,
    token: String,
    dir: PathBuf,
}

impl PrivilegedClient {
    /// Create the FIFO directory and spawn the root helper. Returns only after
    /// a successful `Ping` handshake that proves the helper is running as uid 0.
    pub fn connect(prompt: &str) -> Result<Self, String> {
        let dir = make_private_dir()?;
        let rx_path = dir.join("req");
        let tx_path = dir.join("res");

        mkfifo(&rx_path)?;
        mkfifo(&tx_path)?;

        let token = random_token()?;
        let exe = std::env::current_exe()
            .map_err(|e| format!("cannot locate own executable: {}", e))?;

        spawn_root_helper(&exe, &dir, prompt).inspect_err(|_| {
            let _ = std::fs::remove_dir_all(&dir);
        })?;

        // Same open order as the helper: request FIFO first, then response.
        let mut writer = open_fifo_write_with_deadline(&rx_path, HANDSHAKE_TIMEOUT)
            .inspect_err(|_| {
                let _ = std::fs::remove_dir_all(&dir);
            })?;

        writeln!(writer, "{}", token).map_err(|e| format!("handshake write failed: {}", e))?;
        writer
            .flush()
            .map_err(|e| format!("handshake flush failed: {}", e))?;

        let reader = open_fifo_read_nonblock(&tx_path)?;

        // Dedicated reader thread: lets every request enforce a timeout instead
        // of blocking the UI forever if the helper wedges or is killed.
        let (tx, responses) = mpsc::channel();
        std::thread::spawn(move || {
            let buf = BufReader::new(reader);
            for line in buf.lines() {
                let Ok(line) = line else { break };
                if line.trim().is_empty() {
                    continue;
                }
                if let Ok(resp) = serde_json::from_str::<Response>(&line) {
                    if tx.send(resp).is_err() {
                        break;
                    }
                }
            }
        });

        let client = Self {
            channel: Mutex::new(Some(Channel {
                writer,
                responses,
                next_id: 1,
            })),
            token,
            dir,
        };

        // Prove we actually have root before reporting success.
        let pong = client.request_with_timeout(Request::Ping, HANDSHAKE_TIMEOUT)?;
        if !pong.ok() {
            return Err("privileged helper failed its handshake".into());
        }
        if pong.uid != 0 {
            return Err(format!(
                "privileged helper is running as uid {}, not root",
                pong.uid
            ));
        }

        Ok(client)
    }

    pub fn request(&self, req: Request) -> Result<Response, String> {
        self.request_with_timeout(req, REQUEST_TIMEOUT)
    }

    fn request_with_timeout(&self, req: Request, timeout: Duration) -> Result<Response, String> {
        // Mutex poisoning must not take the app down; recover the guard.
        let mut guard = self
            .channel
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let ch = guard
            .as_mut()
            .ok_or_else(|| "privileged helper is not connected".to_string())?;

        let id = ch.next_id;
        ch.next_id += 1;

        let env = Envelope {
            id,
            token: self.token.clone(),
            req,
        };
        let line = serde_json::to_string(&env).map_err(|e| e.to_string())?;

        if writeln!(ch.writer, "{}", line).is_err() || ch.writer.flush().is_err() {
            *guard = None;
            return Err("privileged helper channel closed".into());
        }

        match ch.responses.recv_timeout(timeout) {
            Ok(resp) if resp.id == id => Ok(resp),
            // Serialized by the mutex, so a mismatched id means desync.
            Ok(_) => {
                *guard = None;
                Err("privileged helper channel desynchronised".into())
            }
            Err(RecvTimeoutError::Timeout) => {
                Err("privileged helper timed out".into())
            }
            Err(RecvTimeoutError::Disconnected) => {
                *guard = None;
                Err("privileged helper exited unexpectedly".into())
            }
        }
    }

    pub fn shutdown(&self) {
        let _ = self.request_with_timeout(Request::Shutdown, Duration::from_secs(2));
        let mut guard = self
            .channel
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = None;
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Drop for PrivilegedClient {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

// ───────────────────────── plumbing ─────────────────────────

fn make_private_dir() -> Result<PathBuf, String> {
    let mut template: Vec<u8> = std::env::temp_dir()
        .join("launchfleet-XXXXXX")
        .to_string_lossy()
        .into_owned()
        .into_bytes();
    template.push(0);

    let ptr = unsafe { libc::mkdtemp(template.as_mut_ptr() as *mut libc::c_char) };
    if ptr.is_null() {
        return Err("could not create private directory".into());
    }
    // mkdtemp already creates with 0700.
    let len = template.iter().position(|&b| b == 0).unwrap_or(template.len());
    let s = String::from_utf8_lossy(&template[..len]).into_owned();
    Ok(PathBuf::from(s))
}

fn mkfifo(path: &Path) -> Result<(), String> {
    let mut c = path.to_string_lossy().into_owned().into_bytes();
    c.push(0);
    let rc = unsafe { libc::mkfifo(c.as_ptr() as *const libc::c_char, 0o600) };
    if rc != 0 {
        return Err(format!("mkfifo({}) failed", path.display()));
    }
    Ok(())
}

fn random_token() -> Result<String, String> {
    let mut f = File::open("/dev/urandom").map_err(|e| e.to_string())?;
    let mut buf = [0u8; 32];
    f.read_exact(&mut buf).map_err(|e| e.to_string())?;
    Ok(buf.iter().map(|b| format!("{:02x}", b)).collect())
}

/// Opening the write end of a FIFO blocks until a reader appears, and returns
/// ENXIO immediately under O_NONBLOCK if there is none. Poll until the root
/// helper shows up or we hit the deadline (e.g. the user cancelled auth).
fn open_fifo_write_with_deadline(path: &Path, timeout: Duration) -> Result<File, String> {
    let deadline = Instant::now() + timeout;
    loop {
        match OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)
        {
            Ok(f) => {
                clear_nonblock(&f)?;
                return Ok(f);
            }
            Err(_) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                return Err(format!(
                    "privileged helper did not start ({}). Authorization may have been cancelled.",
                    e
                ))
            }
        }
    }
}

/// Read end opens immediately even without a writer, so O_NONBLOCK is only used
/// to avoid blocking here; we switch back to blocking for the reader thread.
fn open_fifo_read_nonblock(path: &Path) -> Result<File, String> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| format!("cannot open response channel: {}", e))?;
    clear_nonblock(&f)?;
    Ok(f)
}

fn clear_nonblock(f: &File) -> Result<(), String> {
    use std::os::unix::io::AsRawFd;
    let fd = f.as_raw_fd();
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) < 0 {
            return Err("could not configure channel".into());
        }
    }
    Ok(())
}

/// Launch our own binary as root, detached, via the AppleScript authorization
/// trampoline. `do shell script` waits for stdout to close, hence the
/// redirect + `&`.
fn spawn_root_helper(exe: &Path, dir: &Path, prompt: &str) -> Result<(), String> {
    let cmd = format!(
        "{} --privileged-helper {} >/dev/null 2>&1 &",
        shell_quote(&exe.to_string_lossy()),
        shell_quote(&dir.to_string_lossy())
    );

    let script = format!(
        "do shell script {} with administrator privileges with prompt {}",
        applescript_string(&cmd),
        applescript_string(prompt)
    );

    let output = Command::new("osascript")
        .arg("-e")
        .arg(&script)
        .output()
        .map_err(|e| format!("failed to run osascript: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("-128") || stderr.contains("User canceled") {
            return Err("Authorization cancelled.".into());
        }
        return Err(format!("Authorization failed: {}", stderr.trim()));
    }

    Ok(())
}

/// Wrap in single quotes for /bin/sh, escaping embedded single quotes.
pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Encode as an AppleScript string literal.
pub fn applescript_string(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', r"\\").replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_quote_handles_spaces_and_quotes() {
        assert_eq!(shell_quote("/Applications/My App"), "'/Applications/My App'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
    }

    #[test]
    fn applescript_string_escapes() {
        assert_eq!(applescript_string(r#"a"b"#), r#""a\"b""#);
        assert_eq!(applescript_string(r"a\b"), r#""a\\b""#);
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }

    #[test]
    fn rejects_paths_outside_allowlist() {
        // /etc/hosts exists but is not a managed directory.
        let r = validate_in_allowed_dirs(Path::new("/etc/hosts"), ALLOWED_PRIVILEGED_DIRS);
        assert!(r.is_err());
    }

    #[test]
    fn rejects_traversal_out_of_allowlist() {
        let r = validate_in_allowed_dirs(
            Path::new("/Library/LaunchDaemons/../../etc/hosts"),
            ALLOWED_PRIVILEGED_DIRS,
        );
        assert!(r.is_err(), "canonicalize must defeat .. traversal");
    }

    #[test]
    fn accepts_managed_dir() {
        let r = validate_in_allowed_dirs(
            Path::new("/Library/LaunchDaemons"),
            ALLOWED_PRIVILEGED_DIRS,
        );
        assert!(r.is_ok());
    }
}
