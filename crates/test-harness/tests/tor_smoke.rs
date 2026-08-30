//! Spawns a `tor` subprocess with `TestingTorNetwork` and waits for bootstrap.
//!
//! Without a running Chutney network this cannot reach 100%. The test **skips**
//! unless `SCHAT_REQUIRE_TOR_SMOKE=1` (CI/WSL after `run-testnet.sh`) or a
//! Chutney-generated client torrc is pointed at by `SCHAT_TOR_SMOKE_TORRC`.

use std::env;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn tor_bin() -> Option<PathBuf> {
    if let Ok(p) = env::var("SCHAT_TOR") {
        let path = PathBuf::from(p);
        if path.is_file() {
            return Some(path);
        }
    }
    let name = if cfg!(windows) { "tor.exe" } else { "tor" };
    env::var_os("PATH").and_then(|paths| {
        env::split_paths(&paths).find_map(|dir| {
            let candidate = dir.join(name);
            candidate.is_file().then_some(candidate)
        })
    })
}

/// First Chutney client `torrc` under `SCHAT_CHUTNEY_NODES` (e.g. `007c`).
fn chutney_client_torrc() -> Option<PathBuf> {
    let nodes = PathBuf::from(env::var_os("SCHAT_CHUTNEY_NODES")?);
    let mut names: Vec<_> = fs::read_dir(&nodes).ok()?.flatten().collect();
    names.sort_by_key(|e| e.file_name());
    for ent in names {
        let name = ent.file_name();
        let name = name.to_string_lossy();
        if !name.ends_with('c') {
            continue;
        }
        let torrc = ent.path().join("torrc");
        if torrc.is_file() {
            return Some(torrc);
        }
    }
    None
}

/// Copy a Chutney client torrc into `tmp` with its own data dir and
/// ports so we don't collide with the already-running mininet client.
fn torrc_joining_chutney(tmp: &Path) -> Option<PathBuf> {
    let src = chutney_client_torrc()?;
    let body = fs::read_to_string(&src).ok()?;
    let mut out = String::new();
    for line in body.lines() {
        let t = line.trim_start();
        if t.starts_with("DataDirectory")
            || t.starts_with("SocksPort")
            || t.starts_with("ControlPort")
            || t.starts_with("PidFile")
            || t.starts_with("Log ")
        {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    let data = tmp.join("data");
    fs::create_dir_all(&data).ok()?;
    out.push_str(&format!(
        "DataDirectory {}\nSocksPort auto\nControlPort auto\nLog notice stdout\nRunAsDaemon 0\n",
        data.display()
    ));
    let dest = tmp.join("torrc");
    fs::write(&dest, out).ok()?;
    Some(dest)
}

fn write_testing_torrc(dir: &Path) -> PathBuf {
    let torrc = dir.join("torrc");
    let data = dir.join("data");
    fs::create_dir_all(&data).expect("data dir");
    let body = format!(
        "TestingTorNetwork 1\n\
         DataDirectory {}\n\
         SocksPort auto\n\
         ControlPort auto\n\
         Log notice stdout\n\
         RunAsDaemon 0\n\
         PublishServerDescriptor 0\n\
         AssumeReachable 1\n",
        data.display()
    );
    fs::write(&torrc, body).expect("write torrc");
    torrc
}

fn bootstrap_reaches_100(stdout: impl BufRead, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    for line in stdout.lines() {
        if Instant::now() > deadline {
            return false;
        }
        let Ok(line) = line else { continue };
        if line.contains("Bootstrapped 100%") {
            return true;
        }
    }
    false
}

#[test]
fn tor_testing_network_bootstrap() {
    let require = env::var("SCHAT_REQUIRE_TOR_SMOKE").ok().as_deref() == Some("1");
    let Some(tor) = tor_bin() else {
        if require {
            panic!("tor binary not found (set SCHAT_TOR or PATH)");
        }
        eprintln!("skip: no tor binary (install tor or set SCHAT_TOR)");
        return;
    };

    let tmp = env::temp_dir().join(format!("schat-tor-smoke-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).expect("temp dir");

    let torrc = env::var_os("SCHAT_TOR_SMOKE_TORRC")
        .map(PathBuf::from)
        .filter(|p| p.is_file())
        .or_else(|| torrc_joining_chutney(&tmp))
        .unwrap_or_else(|| write_testing_torrc(&tmp));

    let mut child = Command::new(&tor)
        .arg("-f")
        .arg(&torrc)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {}: {e}", tor.display()));

    let stdout = child.stdout.take().expect("stdout");
    let reader = BufReader::new(stdout);
    let timeout = Duration::from_secs(90);
    let ok = bootstrap_reaches_100(reader, timeout);

    let _ = child.kill();
    let _ = child.wait();
    thread::sleep(Duration::from_millis(200));
    let _ = fs::remove_dir_all(&tmp);

    if ok {
        return;
    }
    if require {
        panic!("tor did not reach Bootstrapped 100% within {timeout:?}");
    }
    eprintln!(
        "skip: tor started but did not bootstrap to 100% (run tools/testnet/run-testnet.sh and set SCHAT_TOR_SMOKE_TORRC)"
    );
}
