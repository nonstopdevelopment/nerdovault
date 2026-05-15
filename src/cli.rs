use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use std::ffi::OsString;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "nerdovault")]
#[command(author, version, about)]
pub struct Cli {
    #[arg(short = 'p', long = "project", global = true)]
    pub project: Option<String>,

    #[command(subcommand)]
    pub command: Option<Commands>,

    #[arg(last = true)]
    pub passthrough: Vec<String>,
}

impl Cli {
    pub fn command() -> clap::Command {
        <Self as CommandFactory>::command()
    }
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Init {
        #[arg(long)]
        biometry_current_set: bool,
    },
    Project {
        #[command(subcommand)]
        command: ProjectCommand,
    },
    Set {
        #[arg(short = 'p', long = "project")]
        project: Option<String>,
        key: String,
        #[command(flatten)]
        input: SecretInputArgs,
    },
    List {
        #[arg(short = 'p', long = "project")]
        project: Option<String>,
    },
    Get {
        #[arg(short = 'p', long = "project")]
        project: Option<String>,
        key: String,
    },
    Reveal {
        #[arg(short = 'p', long = "project")]
        project: Option<String>,
        key: String,
    },
    Delete {
        #[arg(short = 'p', long = "project")]
        project: Option<String>,
        key: String,
    },
    Run {
        #[arg(short = 'p', long = "project")]
        project: Option<String>,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    Shell {
        #[arg(short = 'p', long = "project")]
        project: Option<String>,
        #[arg(long)]
        shell: Option<String>,
    },
    Import {
        #[arg(short = 'p', long = "project")]
        project: Option<String>,
        path: PathBuf,
        #[arg(short = 'y', long)]
        yes: bool,
    },
    Alias {
        #[command(subcommand)]
        action: AliasAction,
    },
    Link {
        #[arg(short = 'p', long = "project")]
        project: Option<String>,
        key: String,
        #[arg(long = "alias")]
        alias: String,
    },
    Scan {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    Guard {
        #[command(subcommand)]
        action: GuardAction,
    },
    Doctor,
    Completions {
        shell: CompletionShell,
    },
    #[command(hide = true)]
    Complete {
        kind: DynamicCompletionKind,
        #[arg(short = 'p', long = "project")]
        project: Option<String>,
    },
    Audit {
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
}

#[derive(Subcommand, Debug)]
pub enum ProjectCommand {
    Create {
        name: String,
    },
    List,
    Delete {
        name: String,
    },
    #[command(name = "add")]
    AddEnv {
        name: String,
        path: PathBuf,
        #[arg(short = 'y', long)]
        yes: bool,
    },
    #[command(external_subcommand)]
    External(Vec<OsString>),
}

#[derive(Subcommand, Debug)]
pub enum GuardAction {
    Install,
}

#[derive(Subcommand, Debug)]
pub enum AliasAction {
    Create {
        name: String,
    },
    Set {
        name: String,
        #[command(flatten)]
        input: SecretInputArgs,
    },
    List,
    Delete {
        name: String,
    },
}

#[derive(Args, Debug, Clone)]
pub struct SecretInputArgs {
    #[arg(long, conflicts_with = "stdin")]
    value: Option<String>,
    #[arg(long)]
    stdin: bool,
}

#[derive(Debug, Clone)]
pub enum SecretInput {
    Prompt,
    Value(String),
    Stdin,
}

impl From<SecretInputArgs> for SecretInput {
    fn from(args: SecretInputArgs) -> Self {
        if let Some(value) = args.value {
            Self::Value(value)
        } else if args.stdin {
            Self::Stdin
        } else {
            Self::Prompt
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum CompletionShell {
    Bash,
    Elvish,
    Fish,
    PowerShell,
    Zsh,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum DynamicCompletionKind {
    Projects,
    Keys,
    Aliases,
}
