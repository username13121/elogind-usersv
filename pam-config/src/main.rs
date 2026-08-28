use std::{
    env,
    fs::{self, File, OpenOptions},
    io::Write,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};

const SYSTEM_LOGIN: &str = "/etc/pam.d/system-login";
const LOCK_FILE: &str = "/run/lock/elogind-usersv-pam.lock";
const MANAGED_LINE: &str = "session    required   pam_elogind_usersv.so\n";

fn main() {
    if let Err(error) = run() {
        eprintln!("elogind-usersv-pam: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut arguments = env::args_os().skip(1);
    let command = arguments
        .next()
        .and_then(|argument| argument.into_string().ok())
        .context("usage: elogind-usersv-pam enable|disable|status")?;
    if arguments.next().is_some() {
        bail!("usage: elogind-usersv-pam enable|disable|status");
    }

    match command.as_str() {
        "enable" => {
            require_root()?;
            let _lock = Lock::acquire()?;
            update(Path::new(SYSTEM_LOGIN), Action::Enable)?;
            println!("enabled pam_elogind_usersv in {SYSTEM_LOGIN}");
        }
        "disable" => {
            require_root()?;
            let _lock = Lock::acquire()?;
            update(Path::new(SYSTEM_LOGIN), Action::Disable)?;
            println!("disabled pam_elogind_usersv in {SYSTEM_LOGIN}");
        }
        "status" => {
            let source =
                fs::read_to_string(SYSTEM_LOGIN).with_context(|| format!("read {SYSTEM_LOGIN}"))?;
            match inspect(&source)? {
                PamState::Enabled => println!("enabled"),
                PamState::Disabled => {
                    println!("disabled");
                    std::process::exit(1);
                }
            }
        }
        _ => bail!("usage: elogind-usersv-pam enable|disable|status"),
    }
    Ok(())
}

fn require_root() -> Result<()> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        bail!("enable and disable must be run as root");
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Action {
    Enable,
    Disable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PamState {
    Enabled,
    Disabled,
}

fn update(path: &Path, action: Action) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect PAM configuration {}", path.display()))?;
    validate_target(path, &metadata)?;
    let source = fs::read_to_string(path)
        .with_context(|| format!("read PAM configuration {}", path.display()))?;
    let replacement = match action {
        Action::Enable => enable(&source)?,
        Action::Disable => disable(&source)?,
    };
    if replacement == source {
        return Ok(());
    }
    atomic_replace(path, replacement.as_bytes(), &metadata)
}

fn validate_target(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() != 1
    {
        bail!(
            "unsafe PAM configuration metadata at {}: expected a root-owned regular file not writable by group or other",
            path.display()
        );
    }
    Ok(())
}

fn atomic_replace(path: &Path, contents: &[u8], metadata: &fs::Metadata) -> Result<()> {
    let parent = path.parent().context("PAM configuration has no parent")?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("PAM configuration filename is not valid UTF-8")?;
    let temporary = parent.join(format!(".{name}.elogind-usersv-{}", std::process::id()));
    let mut cleanup = Temporary::new(temporary.clone());
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&temporary)
        .with_context(|| format!("create temporary PAM configuration {}", temporary.display()))?;
    file.write_all(contents)?;
    file.flush()?;

    // SAFETY: file is an open descriptor and the original UID/GID came from
    // trusted metadata validated above.
    if unsafe { libc::fchown(file.as_raw_fd(), metadata.uid(), metadata.gid()) } != 0 {
        return Err(std::io::Error::last_os_error()).context("preserve PAM file ownership");
    }
    file.set_permissions(fs::Permissions::from_mode(metadata.mode() & 0o7777))?;
    file.sync_all()?;
    fs::rename(&temporary, path).with_context(|| format!("replace {}", path.display()))?;
    cleanup.committed = true;
    File::open(parent)?.sync_all()?;
    Ok(())
}

struct Temporary {
    path: PathBuf,
    committed: bool,
}

impl Temporary {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            committed: false,
        }
    }
}

impl Drop for Temporary {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

struct Lock {
    _file: File,
}

impl Lock {
    fn acquire() -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(LOCK_FILE)
            .with_context(|| format!("open {LOCK_FILE}"))?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            bail!("unsafe PAM integration lock metadata at {LOCK_FILE}");
        }
        // SAFETY: file is a valid descriptor and flock has no pointers.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error()).context("lock PAM integration");
        }
        Ok(Self { _file: file })
    }
}

fn inspect(source: &str) -> Result<PamState> {
    let lines: Vec<_> = source.lines().collect();
    let usersv_lines: Vec<_> = lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| {
            (module_name(line) == Some("pam_elogind_usersv.so")).then_some((index, *line))
        })
        .collect();
    match usersv_lines.as_slice() {
        [] => Ok(PamState::Disabled),
        [(index, line)]
            if is_managed_line(line)
                && *index > 0
                && module_name(lines[index - 1]) == Some("pam_elogind.so") =>
        {
            Ok(PamState::Enabled)
        }
        _ => {
            bail!("unexpected pam_elogind_usersv configuration; refusing to modify {SYSTEM_LOGIN}")
        }
    }
}

fn enable(source: &str) -> Result<String> {
    if inspect(source)? == PamState::Enabled {
        return Ok(source.to_owned());
    }
    let anchors: Vec<_> = source
        .split_inclusive('\n')
        .enumerate()
        .filter_map(|(index, line)| (module_name(line) == Some("pam_elogind.so")).then_some(index))
        .collect();
    let [anchor] = anchors.as_slice() else {
        bail!("expected exactly one pam_elogind.so session entry in {SYSTEM_LOGIN}");
    };

    let mut replacement = String::with_capacity(source.len() + MANAGED_LINE.len() + 1);
    for (index, line) in source.split_inclusive('\n').enumerate() {
        replacement.push_str(line);
        if index == *anchor {
            if !line.ends_with('\n') {
                replacement.push('\n');
            }
            replacement.push_str(MANAGED_LINE);
        }
    }
    Ok(replacement)
}

fn disable(source: &str) -> Result<String> {
    if inspect(source)? == PamState::Disabled {
        return Ok(source.to_owned());
    }
    Ok(source
        .split_inclusive('\n')
        .filter(|line| !is_managed_line(line.trim_end_matches(['\r', '\n'])))
        .collect())
}

fn module_name(line: &str) -> Option<&str> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let fields: Vec<_> = line.split_whitespace().collect();
    (fields.len() >= 3 && matches!(fields[0], "session" | "-session")).then_some(fields[2])
}

fn is_managed_line(line: &str) -> bool {
    let fields: Vec<_> = line.split_whitespace().collect();
    fields == ["session", "required", "pam_elogind_usersv.so"]
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARTIX: &str = "#%PAM-1.0\n-session optional pam_turnstile.so\n-session optional pam_elogind.so\nsession required pam_env.so\n";

    #[test]
    fn enables_after_elogind_and_disables_exact_managed_line() {
        let enabled = enable(ARTIX).unwrap();
        assert!(enabled.contains(
            "-session optional pam_elogind.so\nsession    required   pam_elogind_usersv.so\n"
        ));
        assert_eq!(inspect(&enabled).unwrap(), PamState::Enabled);
        assert_eq!(disable(&enabled).unwrap(), ARTIX);
    }

    #[test]
    fn enable_and_disable_are_idempotent() {
        let enabled = enable(ARTIX).unwrap();
        assert_eq!(enable(&enabled).unwrap(), enabled);
        assert_eq!(disable(&disable(&enabled).unwrap()).unwrap(), ARTIX);
    }

    #[test]
    fn refuses_missing_or_ambiguous_elogind_anchor() {
        assert!(enable("session required pam_env.so\n").is_err());
        assert!(
            enable("session optional pam_elogind.so\nsession optional pam_elogind.so\n").is_err()
        );
    }

    #[test]
    fn refuses_unmanaged_usersv_configuration() {
        let source = format!("{ARTIX}session optional pam_elogind_usersv.so timeout=60\n");
        assert!(inspect(&source).is_err());
        assert!(enable(&source).is_err());
        assert!(disable(&source).is_err());

        let misplaced = format!("session required pam_elogind_usersv.so\n{ARTIX}");
        assert!(inspect(&misplaced).is_err());
    }
}
