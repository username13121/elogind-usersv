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
pub const INTERNAL_PAM_SERVICE: &str = "elogind-usersv-manager";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub backend: PathBuf,
    pub backend_config_dir: PathBuf,
    pub login_readiness_timeout_seconds: u64,
    pub graceful_stop_timeout_seconds: u64,
    pub forced_stop_timeout_seconds: u64,
    pub restart_backoff_minimum_milliseconds: u64,
    pub restart_backoff_maximum_seconds: u64,
    pub root_eligible: bool,
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

    pub fn load_or_default(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        match Self::load(path) {
            Ok(config) => Ok(config),
            Err(ConfigError::Read { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                let config = Self::default();
                config.validate()?;
                Ok(config)
            }
            Err(error) => Err(error),
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        require_absolute("backend", &self.backend)?;
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

impl Default for Config {
    fn default() -> Self {
        Self {
            backend: "/usr/libexec/elogind-usersv/backends/s6".into(),
            backend_config_dir: "/etc/elogind-usersv/backends".into(),
            login_readiness_timeout_seconds: 30,
            graceful_stop_timeout_seconds: 15,
            forced_stop_timeout_seconds: 5,
            restart_backoff_minimum_milliseconds: 500,
            restart_backoff_maximum_seconds: 30,
            root_eligible: false,
            logging_verbosity: LogLevel::Info,
        }
    }
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

    #[test]
    fn defaults_are_valid() {
        Config::default().validate().unwrap();
    }

    #[test]
    fn rejects_unknown_fields() {
        let error = toml::from_str::<Config>("unknown = true").unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn validates_paths_and_timeouts() {
        let config = Config {
            backend: "relative".into(),
            ..Config::default()
        };
        assert!(matches!(
            config.validate(),
            Err(ConfigError::RelativePath { .. })
        ));

        let config = Config {
            login_readiness_timeout_seconds: 0,
            ..Config::default()
        };
        assert!(matches!(config.validate(), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn backoff_is_bounded() {
        let config = Config::default();
        assert_eq!(config.restart_delay(1), Duration::from_millis(500));
        assert_eq!(config.restart_delay(2), Duration::from_secs(1));
        assert_eq!(config.restart_delay(100), Duration::from_secs(30));
    }

    #[test]
    fn loads_partial_config_with_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(
            &path,
            "backend = '/opt/usersv/backend'\nroot_eligible = true\n",
        )
        .unwrap();
        let config = Config::load(path).unwrap();
        assert_eq!(config.backend, Path::new("/opt/usersv/backend"));
        assert!(config.root_eligible);
        assert_eq!(config.graceful_stop_timeout_seconds, 15);
    }
}
