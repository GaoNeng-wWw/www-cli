pub fn warn(
  msg: &str
){
  println!("{}",ansi_term::Color::Yellow.paint(format!("WARNING: {}", msg)));
}
pub fn err(
  msg: &str
){
  println!("{}",ansi_term::Color::Red.paint(format!("ERR: {}", msg)));
}

pub fn vebose(
  msg: &str
){
  println!("{}",ansi_term::Color::Cyan.paint(format!("Vebose: {}", msg)));
}

pub fn success(
  msg: &str
){
  println!("{}",ansi_term::Color::Green.paint(format!("Success: {}", msg)));
}