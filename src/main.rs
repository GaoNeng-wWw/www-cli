pub mod utils;
pub mod file;

use clap::{Parser, Subcommand};
use crate::{file::commands::{decrypt_file, encrypt_file, FileSubCommand}};
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
  /// File operation related
  #[command(subcommand)]
  File(FileSubCommand)
}

fn handle_file_command(
  cli:&Cli,
  cmd:&FileSubCommand
){
  match cmd {
    FileSubCommand::Encrypt(opts) => {
      return encrypt_file(cli, &opts);
    },
    FileSubCommand::Decrypt(opts) => {
      return decrypt_file(cli, &opts);
    }
  }
}

fn main() -> () {
    let cli = Cli::parse();
    match &cli.command {
      Commands::File(cmd) => handle_file_command(&cli, &cmd),
    }
}
