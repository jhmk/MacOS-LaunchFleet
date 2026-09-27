# 🚀 LaunchFleet

A native macOS GUI tool to view and manage all the apps and services that start when you boot up your Mac.

Built with [Tauri 2](https://tauri.app/) + Rust + vanilla HTML/CSS/JS.

## Status: experimental

Please read this before running it on a machine you care about.

- **The release build is unsigned and un-notarized.** macOS will refuse to open
  it on first launch. See [Installing](#installing) below.
- **The System Mode authorization path has not been exercised end-to-end.**
  Everything up to and including the root handshake is covered by tests, but no
  automated test can click through the macOS password dialog. Treat the first
  privileged toggle on your machine as the real smoke test.
- **This app can disable services your Mac depends on.** VPNs, audio drivers,
  backup agents and filesystem extensions all install LaunchDaemons. Removals
  are reversible via the built-in quarantine, but a disabled daemon can still
  leave you without networking or sound until you restore it.
- Apple-owned items are read-only by design, and anything under `/System` is
  protected by SIP and cannot be touched at all.

Tested on macOS 27.0 (arm64). The minimum supported version is macOS 13.

## Features

- **All startup sources in one place** - Login Items, User LaunchAgents, System LaunchAgents, LaunchDaemons, Login Hooks, and Cron jobs
- **One-click toggle** - Enable/disable items with a single switch
- **Smart safety** - User-level items modifiable without password; system items show locked unless you opt in to System Mode
- **Single authorization** - System Mode asks once per session (Touch ID supported)
- **Reversible removals** - "Remove" moves the plist to a quarantine you can restore from, it never deletes
- **Live search & filters** - Filter by tab, third-party only, enabled only, orphans only, your account only
- **Orphan detection** - Highlights items whose binaries no longer exist
- **Impact estimation** - HIGH/MED/LOW/MIN ratings based on `RunAtLoad` and `KeepAlive`
- **Native macOS look** - Vibrancy material, overlay title bar, dark/light mode, native dialogs
- **Detail view** - Full plist info, program path, arguments, working directory

## Why this tool exists

macOS users frequently complain about apps starting at boot that aren't visible in **System Settings > Login Items**. These hidden auto-starters live in:

- `~/Library/LaunchAgents/` (user)
- `/Library/LaunchAgents/` (system)
- `/Library/LaunchDaemons/` (root)
- App bundle internals (`Contents/Library/LoginItems/`)
- Login/Logout Hooks
- crontabs and `/etc/periodic/`

LaunchFleet shows them all and lets you take back control.

## Installing

Download the `.dmg` or `.zip` from the
[Releases](https://github.com/jhmk/MacOS-LaunchFleet/releases) page.

Because the build is unsigned, Gatekeeper will block it. Since macOS 15 the old
Control-click → Open trick no longer works. Instead:

1. Try to open LaunchFleet once and dismiss the warning.
2. Go to **System Settings → Privacy & Security**.
3. Scroll to the Security section and click **Open Anyway** next to LaunchFleet.

Alternatively, remove the quarantine attribute yourself:

```bash
xattr -dr com.apple.quarantine /Applications/LaunchFleet.app
```

Only do that if you trust the binary — or just build from source below.

## Building

```bash
# Install Tauri CLI (one time)
cargo install tauri-cli --version "^2.0" --locked

# Run in development mode
cargo tauri dev

# Build a release .app bundle
cargo tauri build

# Universal binary (Apple Silicon + Intel)
rustup target add aarch64-apple-darwin x86_64-apple-darwin
cargo tauri build --target universal-apple-darwin

# Tests
cargo test
```

The release bundle ends up at `target/release/bundle/macos/LaunchFleet.app`.

> **Distribution:** since macOS 15 the Control-click → Open bypass for unnotarized
> apps is gone. For anything beyond local use you need a Developer ID signature,
> the hardened runtime, and notarization — otherwise users must approve the app
> under System Settings → Privacy & Security.

## Project structure

```
.
├── Cargo.toml              workspace root (+ release profile)
├── dist/                   frontend (HTML/CSS/JS)
└── src-tauri/              Rust backend
    ├── tauri.conf.json     window, CSP, bundle config
    ├── Info.plist          TCC usage strings merged into the bundle
    ├── capabilities/       webview permissions (no shell access)
    ├── tests/
    │   └── privileged_channel.rs   end-to-end helper protocol tests
    └── src/
        ├── main.rs         entry point + --privileged-helper dispatch
        ├── lib.rs          Tauri commands
        ├── models.rs       data structures
        ├── privileged.rs   root helper: protocol, client, path allowlist
        ├── sudo.rs         System Mode session
        ├── quarantine.rs   reversible removals
        ├── actions.rs      enable/disable/remove logic
        ├── sm_login.rs     SMLoginItemSetEnabled bridge
        └── collectors/
            ├── login_items.rs   sfltool dumpbtm parser
            ├── launchd_plist.rs shared plist parsing
            ├── launch_agents.rs
            ├── launch_daemons.rs
            ├── hooks.rs
            └── cron.rs
```

## How System Mode works

Click **System Mode** → one native authorization dialog (Touch ID capable) →
LaunchFleet re-executes its own binary as root as a small helper process → the
app talks to it over a pair of FIFOs in a `0700` directory.

Three properties matter:

1. **It is verified.** Activation performs a `Ping` handshake and asserts the
   helper's effective uid is `0`. If that fails, System Mode stays off rather
   than reporting success and then failing on every action.
2. **It is not a shell.** The channel carries a closed set of typed operations
   (`SetEnabled`, `Bootout`, `Bootstrap`, `PrintDomain`, `Quarantine`,
   `Restore`), never arbitrary commands. Every path is re-validated against an
   allowlist (`/Library/LaunchDaemons`, `/Library/LaunchAgents`) on the root
   side, with `canonicalize` defeating `..` traversal and symlinks.
3. **It does not outlive the app.** Closing the app closes the FIFO; the helper
   sees EOF and exits.

Without System Mode, only user-level items are modifiable, and system-domain
service state is reported as `unknown` rather than guessed.

### Why not `sudo`?

An earlier version ran `do shell script "sudo -v" with administrator
privileges` and then used `sudo -n` for later operations. That cannot work:
`do shell script ... with administrator privileges` runs the command **as
root**, so `sudo -v` refreshes the timestamp for uid 0, while the app itself
runs as the logged-in user and gets "a password is required". macOS also
defaults to `tty_tickets`, and a GUI app has no controlling tty.

## How toggling works

LaunchFleet uses `launchctl enable` / `launchctl disable` plus
`bootstrap`/`bootout`. It deliberately does **not** write a `Disabled` key into
the vendor's plist with `defaults write`, because that rewrites the file as a
binary plist, tightens its mode from `0644` to `0600`, and only sets launchd's
*initial* state — the authoritative state lives in launchd's override database.

## Removals and undo

"Remove" moves the plist into
`~/Library/Application Support/LaunchFleet/quarantine/` and records its origin
in `manifest.json`. Use the **Quarantine** button in the toolbar to restore.
Nothing is ever `rm`'d.

## Permissions

- **Automation (System Events)** — needed to disable legacy login items. macOS
  prompts on first use; if you decline, grant it under System Settings →
  Privacy & Security → Automation. Without it the Apple Event fails with
  `-1743` and LaunchFleet will tell you so explicitly.
- **Full Disk Access** — optional, improves coverage when reading launchd
  configuration outside your home directory.

## Keyboard shortcuts

- `/` - Focus search
- `Escape` - Close dialogs
- `Cmd+R` - Refresh

## License

MIT
