//! End-to-end test of the privileged helper wire protocol.
//!
//! Runs the real helper binary over real FIFOs, but as the *current user*
//! rather than root, so it needs no password and is CI-safe. That is exactly
//! the interesting case: it proves the client's root assertion would reject a
//! helper that is not actually privileged — the failure mode that previously
//! let the UI show "System Mode on" while every action silently failed.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::mpsc;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(20);

struct Harness {
    dir: PathBuf,
    child: Child,
    writer: File,
    reader: BufReader<File>,
    token: String,
    next_id: u64,
}

impl Harness {
    fn start() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "lf-proto-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let req = dir.join("req");
        let res = dir.join("res");
        mkfifo(&req);
        mkfifo(&res);

        let child = Command::new(env!("CARGO_BIN_EXE_launch-fleet"))
            .arg("--privileged-helper")
            .arg(&dir)
            .spawn()
            .expect("spawn helper");

        // Same open order as the helper to rendezvous without deadlocking.
        let mut writer = OpenOptions::new().write(true).open(&req).expect("open req");
        let token = "0123456789abcdef".to_string();
        writeln!(writer, "{}", token).unwrap();
        writer.flush().unwrap();

        let reader = BufReader::new(File::open(&res).expect("open res"));

        Self {
            dir,
            child,
            writer,
            reader,
            token,
            next_id: 1,
        }
    }

    fn send_raw(&mut self, json: &str) {
        writeln!(self.writer, "{}", json).unwrap();
        self.writer.flush().unwrap();
    }

    fn request(&mut self, op_json: &str) -> serde_json::Value {
        let id = self.next_id;
        self.next_id += 1;
        let env = format!(
            r#"{{"id":{},"token":"{}","req":{}}}"#,
            id, self.token, op_json
        );
        self.send_raw(&env);
        let line = self.read_line();
        let v: serde_json::Value = serde_json::from_str(&line).expect("valid JSON response");
        assert_eq!(v["id"].as_u64(), Some(id), "response id must match request");
        v
    }

    fn read_line(&mut self) -> String {
        let mut s = String::new();
        self.reader.read_line(&mut s).expect("read response");
        s
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn mkfifo(path: &Path) {
    let status = Command::new("/usr/bin/mkfifo")
        .arg(path)
        .status()
        .expect("mkfifo");
    assert!(status.success());
}

/// Run `f` on a worker thread so a protocol hang fails the test instead of
/// blocking the suite forever.
fn with_timeout<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(TIMEOUT)
        .expect("privileged helper protocol timed out")
}

#[test]
fn ping_round_trips_and_reports_real_uid() {
    with_timeout(|| {
        let mut h = Harness::start();
        let resp = h.request(r#"{"op":"Ping"}"#);

        assert_eq!(resp["code"].as_i64(), Some(0));
        assert_eq!(resp["stdout"].as_str(), Some("pong"));

        // Spawned as the test user, so the helper must report a non-root uid.
        // PrivilegedClient::connect asserts uid == 0 and would refuse this.
        let uid = resp["uid"].as_u64().expect("uid present");
        assert_ne!(uid, 0, "test harness should not be running as root");
        assert_eq!(uid, unsafe { libc::getuid() } as u64);
    });
}

#[test]
fn rejects_requests_with_a_bad_token() {
    with_timeout(|| {
        let mut h = Harness::start();

        // Wrong token: must be ignored entirely (no response at all).
        h.send_raw(r#"{"id":99,"token":"wrongwrongwrong","req":{"op":"Ping"}}"#);

        // A subsequent valid request still works and still gets its own id,
        // proving the bad one was dropped rather than answered.
        let resp = h.request(r#"{"op":"Ping"}"#);
        assert_eq!(resp["code"].as_i64(), Some(0));
        assert_ne!(resp["id"].as_u64(), Some(99));
    });
}

#[test]
fn refuses_to_quarantine_outside_the_allowlist() {
    with_timeout(|| {
        let mut h = Harness::start();

        // /etc/hosts exists but is not a managed launchd directory.
        let resp = h.request(
            r#"{"op":"Quarantine","src":"/etc/hosts","dest":"/tmp/lf-should-not-happen"}"#,
        );

        assert_eq!(
            resp["code"].as_i64(),
            Some(-2),
            "path outside the allowlist must be denied"
        );
        assert!(
            resp["stderr"]
                .as_str()
                .unwrap_or_default()
                .contains("outside managed directories"),
            "expected an explicit refusal, got {:?}",
            resp["stderr"]
        );
        assert!(
            !Path::new("/tmp/lf-should-not-happen").exists(),
            "helper must not have moved the file"
        );
        assert!(Path::new("/etc/hosts").exists(), "source must be untouched");
    });
}

#[test]
fn refuses_traversal_escape_from_the_allowlist() {
    with_timeout(|| {
        let mut h = Harness::start();
        let resp = h.request(
            r#"{"op":"Quarantine","src":"/Library/LaunchDaemons/../../etc/hosts","dest":"/tmp/lf-nope"}"#,
        );
        assert_eq!(
            resp["code"].as_i64(),
            Some(-2),
            ".. traversal must not escape the allowlist"
        );
        assert!(!Path::new("/tmp/lf-nope").exists());
    });
}

#[test]
fn refuses_to_restore_outside_the_allowlist() {
    with_timeout(|| {
        let mut h = Harness::start();
        let resp = h.request(
            r#"{"op":"Restore","src":"/tmp/whatever","dest":"/etc/cron.d/evil"}"#,
        );
        assert_eq!(
            resp["code"].as_i64(),
            Some(-2),
            "restore destination must be inside the allowlist"
        );
    });
}

#[test]
fn shutdown_terminates_the_helper() {
    with_timeout(|| {
        let mut h = Harness::start();
        h.request(r#"{"op":"Ping"}"#);
        h.send_raw(&format!(
            r#"{{"id":999,"token":"{}","req":{{"op":"Shutdown"}}}}"#,
            h.token
        ));

        let status = h.child.wait().expect("helper should exit");
        assert!(status.success(), "helper should exit cleanly on Shutdown");
    });
}

#[test]
fn helper_exits_when_the_client_goes_away() {
    with_timeout(|| {
        let mut h = Harness::start();
        h.request(r#"{"op":"Ping"}"#);

        // Dropping the write end closes the FIFO; the helper sees EOF. This is
        // what stops a privileged process from outliving the app.
        let dummy = File::open("/dev/null").unwrap();
        let old = std::mem::replace(&mut h.writer, dummy);
        drop(old);

        let status = h.child.wait().expect("helper should exit on EOF");
        assert!(status.success());
    });
}
