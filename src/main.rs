mod audit;
mod cli;
mod complete;
mod crypto;
mod dotenv_import;
mod guard;
mod keychain;
mod manifest;
mod paths;
mod scan;
mod store;
mod vault;

use anyhow::{bail, Context, Result};
use clap::Parser;
use cli::{AliasAction, Cli, Commands, GuardAction, ProjectCommand, SecretInput};
use std::env;
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("nerdovault: {error:#}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<u8> {
    let cli = Cli::parse();

    if !cli.passthrough.is_empty() {
        let project = cli
            .project
            .as_deref()
            .context("use -p/--project when running a command")?;
        return run_project_command(project, &cli.passthrough);
    }

    let Some(command) = cli.command else {
        Cli::command().print_help()?;
        println!();
        return Ok(0);
    };

    match command {
        Commands::Init {
            biometry_current_set,
        } => {
            let vault = vault::Vault::open()?;
            vault.init(biometry_current_set)?;
            let manifest_path = manifest::write_default_manifest(env::current_dir()?)?;
            println!("Initialized Nerdovault.");
            println!("Manifest: {}", manifest_path.display());
            Ok(0)
        }
        Commands::Project { command } => handle_project(command),
        Commands::Set {
            project,
            key,
            input,
        } => {
            let project = require_project(cli.project.as_deref(), project.as_deref())?;
            let value = read_secret_value(input.into(), &format!("{key}: "))?;
            vault::Vault::open()?.set_project_secret(&project, &key, value)?;
            println!("Set {key} for project {project}.");
            Ok(0)
        }
        Commands::List { project } => {
            let project = require_project(cli.project.as_deref(), project.as_deref())?;
            let rows = vault::Vault::open()?.list_project_secrets(&project)?;
            if rows.is_empty() {
                println!("No secrets for project {project}.");
            } else {
                for row in rows {
                    match row.alias_name {
                        Some(alias) => println!("{} -> alias:{alias}", row.key),
                        None => println!("{} = {}", row.key, crypto::redact()),
                    }
                }
            }
            Ok(0)
        }
        Commands::Get { project, key } => {
            let project = require_project(cli.project.as_deref(), project.as_deref())?;
            vault::Vault::open()?.ensure_project_secret_exists(&project, &key)?;
            println!("{key}={}", crypto::redact());
            Ok(0)
        }
        Commands::Reveal { project, key } => {
            let project = require_project(cli.project.as_deref(), project.as_deref())?;
            let value = vault::Vault::open()?.reveal_project_secret(&project, &key)?;
            println!("{key}={value}");
            Ok(0)
        }
        Commands::Delete { project, key } => {
            let project = require_project(cli.project.as_deref(), project.as_deref())?;
            vault::Vault::open()?.delete_project_secret(&project, &key)?;
            println!("Deleted {key} from project {project}.");
            Ok(0)
        }
        Commands::Run { project, command } => {
            let project = require_project(cli.project.as_deref(), project.as_deref())?;
            run_project_command(&project, &command)
        }
        Commands::Shell { project, shell } => {
            let project = require_project(cli.project.as_deref(), project.as_deref())?;
            let shell = shell
                .or_else(|| env::var("SHELL").ok())
                .unwrap_or_else(|| "/bin/zsh".to_string());
            run_project_command(&project, &[shell])
        }
        Commands::Import { project, path, yes } => {
            let project = require_project(cli.project.as_deref(), project.as_deref())?;
            let imported = vault::Vault::open()?.import_env_file(&project, &path, yes)?;
            println!("Imported {imported} values into project {project}.");
            println!("Source file was not deleted: {}", path.display());
            println!("Next: run `nerdovault scan` and remove committed .env files manually.");
            Ok(0)
        }
        Commands::Alias { action } => handle_alias(action),
        Commands::Link {
            project,
            key,
            alias,
        } => {
            let project = require_project(cli.project.as_deref(), project.as_deref())?;
            vault::Vault::open()?.link_alias(&project, &key, &alias)?;
            println!("Linked {project}.{key} -> alias:{alias}.");
            Ok(0)
        }
        Commands::Scan { path } => {
            let findings = scan::scan_path(&path)?;
            if findings.is_empty() {
                println!("No .env files or obvious secret patterns found.");
            } else {
                for finding in &findings {
                    println!("{finding}");
                }
                println!("Found {} potential issue(s).", findings.len());
            }
            Ok(0)
        }
        Commands::Guard { action } => {
            let GuardAction::Install = action;
            let path = guard::install_pre_commit_hook(env::current_dir()?)?;
            println!("Installed guard hook at {}.", path.display());
            Ok(0)
        }
        Commands::Doctor => {
            vault::Vault::open()?.doctor()?;
            Ok(0)
        }
        Commands::Completions { shell } => {
            complete::print_completion(shell);
            Ok(0)
        }
        Commands::Complete { kind, project } => {
            complete::print_dynamic(kind, project.as_deref())?;
            Ok(0)
        }
        Commands::Audit { limit } => {
            for event in vault::Vault::open()?.audit_events(limit)? {
                println!(
                    "{} {} {} {} {}",
                    event.ts,
                    event.event,
                    event.project.unwrap_or_default(),
                    event.key_name.unwrap_or_default(),
                    event.detail.unwrap_or_default()
                );
            }
            Ok(0)
        }
    }
}

fn handle_project(command: ProjectCommand) -> Result<u8> {
    match command {
        ProjectCommand::Create { name } => {
            vault::Vault::open()?.create_project(&name)?;
            println!("Created project {name}.");
        }
        ProjectCommand::List => {
            let projects = vault::Vault::open()?.list_projects()?;
            if projects.is_empty() {
                println!("No projects yet.");
            } else {
                for project in projects {
                    println!("{project}");
                }
            }
        }
        ProjectCommand::Delete { name } => {
            vault::Vault::open()?.delete_project(&name)?;
            println!("Deleted project {name}.");
        }
        ProjectCommand::AddEnv { name, path, yes } => {
            let imported = vault::Vault::open()?.import_env_file(&name, &path, yes)?;
            println!("Imported {imported} values into project {name}.");
        }
        ProjectCommand::External(args) => {
            let args = args
                .into_iter()
                .map(|arg| arg.to_string_lossy().to_string())
                .collect::<Vec<_>>();
            match args.as_slice() {
                [name, action, path] if action == "add" => {
                    let path = std::path::PathBuf::from(path);
                    let imported = vault::Vault::open()?.import_env_file(name, &path, false)?;
                    println!("Imported {imported} values into project {name}.");
                }
                [name, action, path, yes] if action == "add" && yes == "--yes" => {
                    let path = std::path::PathBuf::from(path);
                    let imported = vault::Vault::open()?.import_env_file(name, &path, true)?;
                    println!("Imported {imported} values into project {name}.");
                }
                _ => bail!("use `nerdovault project create/list/delete` or `nerdovault project myapp add .env`"),
            }
        }
    }
    Ok(0)
}

fn handle_alias(action: AliasAction) -> Result<u8> {
    match action {
        AliasAction::Create { name } => {
            vault::Vault::open()?.create_alias(&name)?;
            println!("Created alias {name}.");
        }
        AliasAction::Set { name, input } => {
            let value = read_secret_value(input.into(), &format!("{name}: "))?;
            vault::Vault::open()?.set_alias_secret(&name, value)?;
            println!("Set alias {name}.");
        }
        AliasAction::List => {
            let aliases = vault::Vault::open()?.list_aliases()?;
            if aliases.is_empty() {
                println!("No aliases yet.");
            } else {
                for alias in aliases {
                    println!("{alias}");
                }
            }
        }
        AliasAction::Delete { name } => {
            vault::Vault::open()?.delete_alias(&name)?;
            println!("Deleted alias {name}.");
        }
    }
    Ok(0)
}

fn require_project(global: Option<&str>, local: Option<&str>) -> Result<String> {
    local
        .or(global)
        .map(str::to_string)
        .context("project is required; pass -p/--project")
}

fn read_secret_value(input: SecretInput, prompt: &str) -> Result<String> {
    match input {
        SecretInput::Prompt => rpassword::prompt_password(prompt).context("failed to read secret"),
        SecretInput::Value(value) => Ok(value),
        SecretInput::Stdin => {
            use std::io::Read;
            let mut value = String::new();
            std::io::stdin()
                .read_to_string(&mut value)
                .context("failed to read secret from stdin")?;
            Ok(value.trim_end_matches(['\r', '\n']).to_string())
        }
    }
}

fn run_project_command(project: &str, command: &[String]) -> Result<u8> {
    if command.is_empty() {
        bail!("missing command after --");
    }

    let envs = vault::Vault::open()?.resolve_project_env(project)?;
    let mut child = Command::new(&command[0]);
    child.args(&command[1..]);
    child.envs(envs);

    let status = child
        .status()
        .with_context(|| format!("failed to run {}", command[0]))?;
    Ok(status.code().unwrap_or(1) as u8)
}
