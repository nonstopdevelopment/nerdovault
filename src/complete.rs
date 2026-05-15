use crate::cli::{Cli, CompletionShell, DynamicCompletionKind};
use crate::vault::Vault;
use anyhow::Result;
use clap_complete::{generate, Shell};

pub fn print_completion(shell: CompletionShell) {
    let mut command = Cli::command();
    let shell: Shell = shell.into();
    generate(shell, &mut command, "nerdovault", &mut std::io::stdout());
}

pub fn print_dynamic(kind: DynamicCompletionKind, project: Option<&str>) -> Result<()> {
    let vault = Vault::open()?;
    match kind {
        DynamicCompletionKind::Projects => {
            for project in vault.list_projects()? {
                println!("{project}");
            }
        }
        DynamicCompletionKind::Aliases => {
            for alias in vault.list_aliases()? {
                println!("{alias}");
            }
        }
        DynamicCompletionKind::Keys => {
            if let Some(project) = project {
                for secret in vault.list_project_secrets(project)? {
                    println!("{}", secret.key);
                }
            }
        }
    }
    Ok(())
}

impl From<CompletionShell> for Shell {
    fn from(shell: CompletionShell) -> Self {
        match shell {
            CompletionShell::Bash => Shell::Bash,
            CompletionShell::Elvish => Shell::Elvish,
            CompletionShell::Fish => Shell::Fish,
            CompletionShell::PowerShell => Shell::PowerShell,
            CompletionShell::Zsh => Shell::Zsh,
        }
    }
}
