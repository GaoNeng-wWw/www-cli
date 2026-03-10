pub mod bazi;
pub mod file;
pub mod utils;

use crate::{bazi::commands::BaziArgs, file::commands::{FileSubCommand, decrypt_file, encrypt_file}};
use clap::{Parser, Subcommand};
#[derive(Parser)]
#[command(version, author, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Subcommand)]
pub enum Commands {
  #[command(subcommand)]
  File(FileSubCommand),
  /// 八字排盘
  Bazi(BaziArgs),
}

fn handle_file_command(cli: &Cli, cmd: &FileSubCommand) {
    match cmd {
        FileSubCommand::Encrypt(opts) => {
            return encrypt_file(cli, &opts);
        }
        FileSubCommand::Decrypt(opts) => {
            return decrypt_file(cli, &opts);
        }
    }
}

fn main() -> () {
    let cli = Cli::parse();
    match &cli.command {
        Commands::File(cmd) => handle_file_command(&cli, &cmd),
        Commands::Bazi(opts) => bazi::commands::bazi(&cli, &opts),
    }
}
