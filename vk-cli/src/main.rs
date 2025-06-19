use clap::{Parser, Subcommand};
use vk_core::scan::scan_project;

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a project directory
    Scan {
        /// Target directory
        #[arg(short, long, default_value = ".")]
        target: String,

        /// Output format: console | json
        #[arg(short, long, default_value = "console")]
        output: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Scan { target, output } => {
            scan_project(target, output);
        }
    }
}
