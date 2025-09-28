use std::fs::exists;

use clap::{arg, Args, Subcommand};
use rpassword::{prompt_password, read_password};
use crate::{utils::log::{err, warn}, utils::file_aes::FileEncryptor, Cli};

#[derive(Args)]
pub struct Encrypt {
  #[arg(short, long)]
  /// Password for encryption. Must match the password used during decryption
  password: Option<String>,
  /// Input file path. Creates an encrypted file with '.encrypt' extension in the same directory
  path: String,
}

#[derive(Args)]
pub struct Decrypt {
  #[arg(short, long)]
  /// Password for decryption. Must match the password used during encryption
  password: Option<String>,
  /// Encrypted file path. Creates a decrypted file with '.decrypt' extension in the same directory
  path: String,
}

#[derive(Subcommand)]
pub enum FileSubCommand {
  Encrypt(Encrypt),
  Decrypt(Decrypt)
}

pub fn encrypt_file(
  cli: &Cli,
  arg: &Encrypt
){
  let Encrypt { password, path } = arg;
  let password = if password.is_none() {
    prompt_password("Enter your password: ").unwrap()
  } else {
    password.clone().unwrap()
  };
  let pwd= password.clone();
  if let Err(error) = exists(&path) {
    if cli.verbose {
      err(&error.to_string());
    }
    warn("File not found");
    return;
  }
  let file_handle = FileEncryptor::new(pwd);
  let output_path = format!("{0}.encrypt", path.to_string());
  let res = file_handle.encrypt_file(&path, &output_path);
  if let Err(error) = res {
    let err_str = error.to_string();
    err(&err_str);
    return;
  }
}

pub fn decrypt_file(
  cli: &Cli,
  opts: &Decrypt
){
  let Decrypt { password, path } = opts;
  let password = if password.is_none() {
    prompt_password("Enter your password: ").unwrap()
  } else {
    password.clone().unwrap()
  };
  let pwd= password.clone();
  if let Err(error) = exists(&path) {
    if cli.verbose {
      err(&error.to_string());
    }
    warn("File not found");
    return;
  }
  let file_handle = FileEncryptor::new(pwd);
  let res = file_handle.decrypt_file(
    &path,
    &format!("{0}.decrypt", path.to_string())
  );
  if let Err(error) = res {
    let err_str = error.to_string();
    err(&err_str);
    return;
  }
}