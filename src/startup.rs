use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use anyhow::{Context, Result, bail};
use serde::Serialize;

const SERVICE_NAME: &str = "sing-box-ser-mini";

#[derive(Clone)]
pub struct StartupInputs {
    pub config_path: PathBuf,
    pub credentials_path: PathBuf,
    pub token_file: Option<PathBuf>,
    pub webui_listen: String,
    pub worker_threads: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ServiceManager {
    OpenRc,
    Systemd,
}

#[derive(Serialize)]
pub struct StartupStatus {
    pub supported: bool,
    pub manager: &'static str,
    pub installed: bool,
    pub enabled: bool,
    pub current: bool,
    pub service_name: &'static str,
    pub service_path: String,
    pub executable_path: String,
    pub config_path: String,
}

struct InstallSpec {
    manager: ServiceManager,
    service_path: PathBuf,
    contents: String,
    executable_path: PathBuf,
    config_path: PathBuf,
}

pub fn inspect(inputs: &StartupInputs) -> Result<StartupStatus> {
    let Some(manager) = detect_manager() else {
        return Ok(unsupported_status(inputs));
    };
    status_for_spec(&build_spec(manager, inputs)?)
}

pub fn install(inputs: &StartupInputs) -> Result<StartupStatus> {
    let manager = detect_manager()
        .ok_or_else(|| anyhow::anyhow!("unsupported init system; OpenRC or systemd is required"))?;
    let spec = build_spec(manager, inputs)?;
    let temporary = env::temp_dir().join(format!(".{SERVICE_NAME}-startup-{}", std::process::id()));
    fs::write(&temporary, &spec.contents)
        .with_context(|| format!("write temporary startup file {}", temporary.display()))?;

    let result = (|| {
        let install_program = find_program(&["/usr/bin/install", "/bin/install", "install"])
            .ok_or_else(|| anyhow::anyhow!("install command was not found"))?;
        let mode = if manager == ServiceManager::OpenRc {
            "0755"
        } else {
            "0644"
        };
        run_privileged(
            &install_program,
            &[
                "-m".into(),
                mode.into(),
                temporary.as_os_str().to_owned(),
                spec.service_path.as_os_str().to_owned(),
            ],
        )?;

        match manager {
            ServiceManager::OpenRc => {
                let rc_update =
                    find_program(&["/sbin/rc-update", "/usr/sbin/rc-update", "rc-update"])
                        .ok_or_else(|| anyhow::anyhow!("rc-update command was not found"))?;
                run_privileged(
                    &rc_update,
                    &["add".into(), SERVICE_NAME.into(), "default".into()],
                )?;
            }
            ServiceManager::Systemd => {
                let systemctl = find_program(&[
                    "/usr/bin/systemctl",
                    "/bin/systemctl",
                    "/usr/sbin/systemctl",
                    "systemctl",
                ])
                .ok_or_else(|| anyhow::anyhow!("systemctl command was not found"))?;
                run_privileged(&systemctl, &["daemon-reload".into()])?;
                run_privileged(
                    &systemctl,
                    &["enable".into(), format!("{SERVICE_NAME}.service").into()],
                )?;
            }
        }
        status_for_spec(&spec)
    })();
    let _ = fs::remove_file(&temporary);
    result
}

pub fn uninstall(inputs: &StartupInputs) -> Result<StartupStatus> {
    let manager = detect_manager()
        .ok_or_else(|| anyhow::anyhow!("unsupported init system; OpenRC or systemd is required"))?;
    let spec = build_spec(manager, inputs)?;
    let status = status_for_spec(&spec)?;

    match manager {
        ServiceManager::OpenRc => {
            if status.enabled {
                let rc_update =
                    find_program(&["/sbin/rc-update", "/usr/sbin/rc-update", "rc-update"])
                        .ok_or_else(|| anyhow::anyhow!("rc-update command was not found"))?;
                run_privileged(
                    &rc_update,
                    &["del".into(), SERVICE_NAME.into(), "default".into()],
                )?;
            }
        }
        ServiceManager::Systemd => {
            let systemctl = find_program(&[
                "/usr/bin/systemctl",
                "/bin/systemctl",
                "/usr/sbin/systemctl",
                "systemctl",
            ])
            .ok_or_else(|| anyhow::anyhow!("systemctl command was not found"))?;
            if status.enabled {
                run_privileged(
                    &systemctl,
                    &["disable".into(), format!("{SERVICE_NAME}.service").into()],
                )?;
            }
        }
    }

    if status.installed {
        let remove_program = find_program(&["/bin/rm", "/usr/bin/rm", "rm"])
            .ok_or_else(|| anyhow::anyhow!("rm command was not found"))?;
        run_privileged(
            &remove_program,
            &["-f".into(), spec.service_path.as_os_str().to_owned()],
        )?;
    }

    if manager == ServiceManager::Systemd {
        let systemctl = find_program(&[
            "/usr/bin/systemctl",
            "/bin/systemctl",
            "/usr/sbin/systemctl",
            "systemctl",
        ])
        .ok_or_else(|| anyhow::anyhow!("systemctl command was not found"))?;
        run_privileged(&systemctl, &["daemon-reload".into()])?;
    }
    status_for_spec(&spec)
}

fn unsupported_status(inputs: &StartupInputs) -> StartupStatus {
    StartupStatus {
        supported: false,
        manager: "unsupported",
        installed: false,
        enabled: false,
        current: false,
        service_name: SERVICE_NAME,
        service_path: String::new(),
        executable_path: env::current_exe().unwrap_or_default().display().to_string(),
        config_path: absolute_path(&inputs.config_path)
            .unwrap_or_else(|_| inputs.config_path.clone())
            .display()
            .to_string(),
    }
}

fn detect_manager() -> Option<ServiceManager> {
    if Path::new("/sbin/openrc-run").exists() && Path::new("/etc/init.d").is_dir() {
        Some(ServiceManager::OpenRc)
    } else if Path::new("/run/systemd/system").is_dir()
        && find_program(&[
            "/usr/bin/systemctl",
            "/bin/systemctl",
            "/usr/sbin/systemctl",
            "systemctl",
        ])
        .is_some()
    {
        Some(ServiceManager::Systemd)
    } else {
        None
    }
}

fn build_spec(manager: ServiceManager, inputs: &StartupInputs) -> Result<InstallSpec> {
    let executable_path =
        fs::canonicalize(env::current_exe()?).context("resolve the current executable path")?;
    let config_path = absolute_path(&inputs.config_path)?;
    let credentials_path = absolute_path(&inputs.credentials_path)?;
    let token_file = inputs
        .token_file
        .as_deref()
        .map(absolute_path)
        .transpose()?;
    let working_directory = env::current_dir().context("resolve the current working directory")?;
    let log_file = executable_path
        .parent()
        .and_then(Path::parent)
        .map(|root| root.join("log/server.log"))
        .filter(|path| path.parent().is_some_and(Path::is_dir));
    let user = command_text(
        &find_program(&["/usr/bin/id", "/bin/id", "id"])
            .ok_or_else(|| anyhow::anyhow!("id command was not found"))?,
        &["-un"],
    )?;
    let group = command_text(
        &find_program(&["/usr/bin/id", "/bin/id", "id"])
            .ok_or_else(|| anyhow::anyhow!("id command was not found"))?,
        &["-gn"],
    )?;
    let arguments = service_arguments(
        inputs,
        &config_path,
        &credentials_path,
        token_file.as_deref(),
    );

    let (service_path, contents) = match manager {
        ServiceManager::OpenRc => (
            PathBuf::from(format!("/etc/init.d/{SERVICE_NAME}")),
            render_openrc(
                &executable_path,
                &working_directory,
                &user,
                &group,
                &arguments,
                log_file.as_deref(),
            ),
        ),
        ServiceManager::Systemd => (
            PathBuf::from(format!("/etc/systemd/system/{SERVICE_NAME}.service")),
            render_systemd(&executable_path, &working_directory, &user, &arguments),
        ),
    };
    Ok(InstallSpec {
        manager,
        service_path,
        contents,
        executable_path,
        config_path,
    })
}

fn service_arguments(
    inputs: &StartupInputs,
    config_path: &Path,
    credentials_path: &Path,
    token_file: Option<&Path>,
) -> Vec<String> {
    let mut arguments = vec![
        "--config".to_owned(),
        config_path.display().to_string(),
        "--admin-listen".to_owned(),
        inputs.webui_listen.clone(),
        "--admin-credentials-file".to_owned(),
        credentials_path.display().to_string(),
        "--worker-threads".to_owned(),
        inputs.worker_threads.to_string(),
    ];
    if let Some(token_file) = token_file {
        arguments.push("--admin-token-file".to_owned());
        arguments.push(token_file.display().to_string());
    }
    arguments
}

fn render_openrc(
    executable: &Path,
    working_directory: &Path,
    user: &str,
    group: &str,
    arguments: &[String],
    log_file: Option<&Path>,
) -> String {
    let command_arguments = arguments
        .iter()
        .map(|argument| shell_quote(argument))
        .collect::<Vec<_>>()
        .join(" ");
    let logging = log_file.map_or_else(String::new, |path| {
        let path = shell_quote(&path.display().to_string());
        format!("output_log={path}\nerror_log={path}\n")
    });
    format!(
        "#!/sbin/openrc-run\n\n\
description=\"Rust Hysteria 2 server and management UI\"\n\
export RUST_LOG=sing_box_ser_mini=info\n\
command={}\n\
command_args={}\n\
command_user={}\n\
directory={}\n\
supervisor=\"supervise-daemon\"\n\
respawn_delay=5\n\
respawn_max=0\n\n\
{logging}\
depend() {{\n    need net\n    after firewall\n}}\n",
        shell_quote(&executable.display().to_string()),
        shell_quote(&command_arguments),
        shell_quote(&format!("{user}:{group}")),
        shell_quote(&working_directory.display().to_string()),
    )
}

fn render_systemd(
    executable: &Path,
    working_directory: &Path,
    user: &str,
    arguments: &[String],
) -> String {
    let command = std::iter::once(executable.display().to_string())
        .chain(arguments.iter().cloned())
        .map(|argument| systemd_quote(&argument))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "[Unit]\n\
Description=Rust Hysteria 2 server and management UI\n\
After=network-online.target\n\
Wants=network-online.target\n\n\
[Service]\n\
Type=simple\n\
User={}\n\
WorkingDirectory={}\n\
Environment=RUST_LOG=sing_box_ser_mini=info\n\
ExecStart={command}\n\
Restart=on-failure\n\
RestartSec=5s\n\
NoNewPrivileges=true\n\n\
[Install]\n\
WantedBy=multi-user.target\n",
        systemd_value(user),
        systemd_value(&working_directory.display().to_string()),
    )
}

fn status_for_spec(spec: &InstallSpec) -> Result<StartupStatus> {
    let installed_contents = fs::read_to_string(&spec.service_path).ok();
    let installed = installed_contents.is_some();
    let current = installed_contents.is_some_and(|contents| contents == spec.contents);
    let enabled = match spec.manager {
        ServiceManager::OpenRc => Path::new("/etc/runlevels/default")
            .join(SERVICE_NAME)
            .exists(),
        ServiceManager::Systemd => find_program(&[
            "/usr/bin/systemctl",
            "/bin/systemctl",
            "/usr/sbin/systemctl",
            "systemctl",
        ])
        .and_then(|program| {
            Command::new(program)
                .args(["is-enabled", "--quiet", SERVICE_NAME])
                .status()
                .ok()
        })
        .is_some_and(|status| status.success()),
    };
    Ok(StartupStatus {
        supported: true,
        manager: match spec.manager {
            ServiceManager::OpenRc => "openrc",
            ServiceManager::Systemd => "systemd",
        },
        installed,
        enabled,
        current,
        service_name: SERVICE_NAME,
        service_path: spec.service_path.display().to_string(),
        executable_path: spec.executable_path.display().to_string(),
        config_path: spec.config_path.display().to_string(),
    })
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_owned())
    } else {
        Ok(env::current_dir()?.join(path))
    }
}

fn command_text(program: &Path, arguments: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(arguments)
        .output()
        .with_context(|| format!("run {}", program.display()))?;
    if !output.status.success() {
        bail!(
            "{} failed: {}",
            program.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let value = String::from_utf8(output.stdout)?.trim().to_owned();
    if value.is_empty() {
        bail!("{} returned an empty value", program.display());
    }
    Ok(value)
}

fn run_privileged(program: &Path, arguments: &[std::ffi::OsString]) -> Result<()> {
    if command_text(
        &find_program(&["/usr/bin/id", "/bin/id", "id"])
            .ok_or_else(|| anyhow::anyhow!("id command was not found"))?,
        &["-u"],
    )? == "0"
    {
        return ensure_success(program, Command::new(program).args(arguments).output());
    }

    let mut errors = Vec::new();
    for (helper, extra) in [
        (find_program(&["/usr/bin/doas", "/bin/doas", "doas"]), None),
        (
            find_program(&["/usr/bin/sudo", "/bin/sudo", "sudo"]),
            Some("-n"),
        ),
    ] {
        let Some(helper) = helper else { continue };
        let mut command = Command::new(&helper);
        if let Some(extra) = extra {
            command.arg(extra);
        }
        command.arg(program).args(arguments);
        match command.output() {
            Ok(output) if output.status.success() => return Ok(()),
            Ok(output) => errors.push(format!(
                "{}: {}",
                helper.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            )),
            Err(error) => errors.push(format!("{}: {error}", helper.display())),
        }
    }
    bail!(
        "administrator permission is required{}",
        if errors.is_empty() {
            String::new()
        } else {
            format!(": {}", errors.join("; "))
        }
    )
}

fn ensure_success(program: &Path, output: std::io::Result<Output>) -> Result<()> {
    let output = output.with_context(|| format!("run {}", program.display()))?;
    if output.status.success() {
        Ok(())
    } else {
        bail!(
            "{} failed: {}",
            program.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }
}

fn find_program(candidates: &[&str]) -> Option<PathBuf> {
    for candidate in candidates {
        let path = Path::new(candidate);
        if path.is_absolute() && path.is_file() {
            return Some(path.to_owned());
        }
        if path.components().count() == 1 {
            for directory in env::split_paths(&env::var_os("PATH").unwrap_or_default()) {
                let path = directory.join(path);
                if path.is_file() {
                    return Some(path);
                }
            }
        }
    }
    None
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn systemd_quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn systemd_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace(' ', "\\x20")
        .replace('\t', "\\t")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_openrc_service_with_quoted_paths() {
        let contents = render_openrc(
            Path::new("/opt/sing box/bin/server"),
            Path::new("/opt/sing box"),
            "service-user",
            "service-group",
            &["--config".into(), "/opt/sing box/etc/config.toml".into()],
            Some(Path::new("/opt/sing box/log/server.log")),
        );
        assert!(contents.starts_with("#!/sbin/openrc-run"));
        assert!(contents.contains("supervisor=\"supervise-daemon\""));
        assert!(contents.contains("service-user:service-group"));
        assert!(contents.contains("/opt/sing box/etc/config.toml"));
        assert!(contents.contains("output_log="));
        assert!(contents.contains("/opt/sing box/log/server.log"));
    }

    #[test]
    fn renders_systemd_service_without_a_shell() {
        let contents = render_systemd(
            Path::new("/opt/server"),
            Path::new("/opt/service data"),
            "service-user",
            &["--config".into(), "/opt/config.toml".into()],
        );
        assert!(contents.contains("User=service-user"));
        assert!(contents.contains("WorkingDirectory=/opt/service\\x20data"));
        assert!(contents.contains("ExecStart=\"/opt/server\" \"--config\" \"/opt/config.toml\""));
        assert!(!contents.contains("/bin/sh"));
    }

    #[test]
    fn shell_quotes_single_quotes() {
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
    }
}
