use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use serde::Deserialize;
use thiserror::Error;

pub const DEFAULT_CONFIG_PATH: &str = "/etc/elogind-usersv/config.toml";
pub const DEFAULT_CONTROL_SOCKET: &str = "/run/elogind-usersv/control.sock";
pub const DEFAULT_RUNTIME_DIRECTORY: &str = "/run/elogind-usersv";
pub const DEFAULT_SUPERVISOR_PATH: &str = "/usr/libexec/elogind-usersv-supervisor";
pub const BACKEND_DIRECTORY: &str = "/usr/libexec/elogind-usersv/backends";
pub const INTERNAL_PAM_SERVICE: &str = "elogind-usersv-manager";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub backend: String,
    #[serde(default = "default_backend_config_dir")]
    pub backend_config_dir: PathBuf,
    #[serde(default = "default_login_readiness_timeout_seconds")]
    pub login_readiness_timeout_seconds: u64,
    #[serde(default = "default_graceful_stop_timeout_seconds")]
    pub graceful_stop_timeout_seconds: u64,
    #[serde(default = "default_forced_stop_timeout_seconds")]
    pub forced_stop_timeout_seconds: u64,
    #[serde(default = "default_restart_backoff_minimum_milliseconds")]
    pub restart_backoff_minimum_milliseconds: u64,
    #[serde(default = "default_restart_backoff_maximum_seconds")]
    pub restart_backoff_maximum_seconds: u64,
    #[serde(default)]
    pub root_eligible: bool,
    #[serde(default)]
    pub logging_verbosity: LogLevel,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let source = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?;
        let config: Self = toml::from_str(&source).map_err(|source| ConfigError::Parse {
            path: path.to_owned(),
            source,
        })?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if !valid_backend_name(&self.backend) {
            return Err(ConfigError::Invalid(
                "backend must match [a-z0-9][a-z0-9._-]*",
            ));
        }
        require_absolute("backend_config_dir", &self.backend_config_dir)?;
        if self.login_readiness_timeout_seconds == 0 {
            return Err(ConfigError::Invalid(
                "login_readiness_timeout_seconds must be nonzero",
            ));
        }
        if self.graceful_stop_timeout_seconds == 0 {
            return Err(ConfigError::Invalid(
                "graceful_stop_timeout_seconds must be nonzero",
            ));
        }
        if self.forced_stop_timeout_seconds == 0 {
            return Err(ConfigError::Invalid(
                "forced_stop_timeout_seconds must be nonzero",
            ));
        }
        if self.restart_backoff_minimum_milliseconds == 0 {
            return Err(ConfigError::Invalid(
                "restart_backoff_minimum_milliseconds must be nonzero",
            ));
        }
        if self.restart_backoff_minimum() > self.restart_backoff_maximum() {
            return Err(ConfigError::Invalid(
                "restart_backoff_minimum_milliseconds exceeds restart_backoff_maximum_seconds",
            ));
        }
        Ok(())
    }

    pub fn backend_path(&self) -> PathBuf {
        Path::new(BACKEND_DIRECTORY).join(&self.backend)
    }

    pub fn login_readiness_timeout(&self) -> Duration {
        Duration::from_secs(self.login_readiness_timeout_seconds)
    }

    pub fn graceful_stop_timeout(&self) -> Duration {
        Duration::from_secs(self.graceful_stop_timeout_seconds)
    }

    pub fn forced_stop_timeout(&self) -> Duration {
        Duration::from_secs(self.forced_stop_timeout_seconds)
    }

    pub fn restart_backoff_minimum(&self) -> Duration {
        Duration::from_millis(self.restart_backoff_minimum_milliseconds)
    }

    pub fn restart_backoff_maximum(&self) -> Duration {
        Duration::from_secs(self.restart_backoff_maximum_seconds)
    }

    pub fn restart_delay(&self, attempt: u32) -> Duration {
        let shift = attempt.saturating_sub(1).min(31);
        self.restart_backoff_minimum()
            .saturating_mul(1_u32 << shift)
            .min(self.restart_backoff_maximum())
    }
}

fn default_backend_config_dir() -> PathBuf {
    "/etc/elogind-usersv/backends".into()
}

fn default_login_readiness_timeout_seconds() -> u64 {
    30
}

fn default_graceful_stop_timeout_seconds() -> u64 {
    15
}

fn default_forced_stop_timeout_seconds() -> u64 {
    5
}

fn default_restart_backoff_minimum_milliseconds() -> u64 {
    500
}

fn default_restart_backoff_maximum_seconds() -> u64 {
    30
}

fn valid_backend_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("cannot read configuration {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot parse configuration {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("invalid configuration: {0}")]
    Invalid(&'static str),
    #[error("configuration field {field} must be an absolute path: {path}")]
    RelativePath { field: &'static str, path: PathBuf },
}

fn require_absolute(field: &'static str, path: &Path) -> Result<(), ConfigError> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(ConfigError::RelativePath {
            field,
            path: path.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config {
            backend: "test-backend".into(),
            backend_config_dir: default_backend_config_dir(),
            login_readiness_timeout_seconds: default_login_readiness_timeout_seconds(),
            graceful_stop_timeout_seconds: default_graceful_stop_timeout_seconds(),
            forced_stop_timeout_seconds: default_forced_stop_timeout_seconds(),
            restart_backoff_minimum_milliseconds: default_restart_backoff_minimum_milliseconds(),
            restart_backoff_maximum_seconds: default_restart_backoff_maximum_seconds(),
            root_eligible: false,
            logging_verbosity: LogLevel::Info,
        }
    }

    #[test]
    fn requires_an_explicit_backend() {
        let error = toml::from_str::<Config>("root_eligible = true").unwrap_err();
        assert!(error.to_string().contains("missing field `backend`"));
    }

    #[test]
    fn rejects_unknown_fields() {
        let error = toml::from_str::<Config>("backend = 'test'\nunknown = true").unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn validates_backend_names_paths_and_timeouts() {
        for backend in ["", "S6", "../s6", ".hidden", "s6/user"] {
            let mut invalid = config();
            invalid.backend = backend.into();
            assert!(matches!(invalid.validate(), Err(ConfigError::Invalid(_))));
        }

        let mut invalid = config();
        invalid.backend_config_dir = "relative".into();
        assert!(matches!(
            invalid.validate(),
            Err(ConfigError::RelativePath { .. })
        ));

        let mut invalid = config();
        invalid.login_readiness_timeout_seconds = 0;
        assert!(matches!(invalid.validate(), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn resolves_backend_names_beneath_the_fixed_directory() {
        let config = config();
        assert_eq!(
            config.backend_path(),
            Path::new(BACKEND_DIRECTORY).join("test-backend")
        );
    }

    #[test]
    fn backoff_is_bounded() {
        let config = config();
        assert_eq!(config.restart_delay(1), Duration::from_millis(500));
        assert_eq!(config.restart_delay(2), Duration::from_secs(1));
        assert_eq!(config.restart_delay(100), Duration::from_secs(30));
    }

    #[test]
    fn loads_partial_config_with_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "backend = 's6-user'\nroot_eligible = true\n").unwrap();
        let config = Config::load(path).unwrap();
        assert_eq!(config.backend, "s6-user");
        assert!(config.root_eligible);
        assert_eq!(config.graceful_stop_timeout_seconds, 15);
    }
}
