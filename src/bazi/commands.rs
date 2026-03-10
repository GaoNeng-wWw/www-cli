use chrono::{Datelike, NaiveDate, NaiveDateTime, Timelike};
use tabled::{builder::Builder, settings::{Alignment, Modify, Span, object::Cell}};
use tyme4rs::tyme::{Culture, sixtycycle::SixtyCycle, solar::SolarTime};
use clap::Args;
use crate::Cli;

#[derive(Args)]
pub struct BaziArgs {
  /// 出生日期时间 (格式: YYYY-MM-DD HH:MM:SS)
  #[arg(short, long, value_parser = parse_date)]
  date: NaiveDateTime,
}

pub struct DateObject {
  pub year: i64,
  pub month: i64,
  pub day: i64,
  pub hour: i64,
  pub minute: i64,
  pub second: i64,
}

fn parse_date(s: &str) -> Result<NaiveDateTime, String> {
    if let Ok(dt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
        return Ok(dt);
    }
    if let Ok(dt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M") {
        return Ok(dt);
    }
    if let Ok(d) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return Ok(d.and_hms_opt(12, 0, 0).expect("Invalid time"));
    }

    Err(format!(
        "日期格式错误: '{}'。请使用 'YYYY-MM-DD HH:MM:SS'", 
        s
    ))
}

struct Nayin {
  year: String,
  month: String,
  day: String,
  time: String,
}

struct EarthBranch {
  year: String,
  month: String,
  day: String,
  time: String,
}
struct Terrain {
  year: String,
  month: String,
  day: String,
  time: String,
}
struct TenStar {
  year: String,
  month: String,
  day: String,
  time: String,
}

impl TenStar {
  fn new(
    year: &SixtyCycle,
    month: &SixtyCycle,
    day: &SixtyCycle,
    hour: &SixtyCycle
  ) -> Self {
      Self { year: year.get_ten().get_name(), month: month.get_ten().get_name(), day: day.get_ten().get_name(), time: hour.get_ten().get_name() }
  }
  pub fn to_table(&self, builder: &mut Builder){
    builder.push_record(vec![
      "十神",
      &self.year,
      &self.month,
      &self.day,
      &self.time,
    ]);
  }
}

impl Terrain {
  fn new(
    year: &SixtyCycle,
    month: &SixtyCycle,
    day: &SixtyCycle,
    hour: &SixtyCycle
  ) -> Self {
    Self { 
      year: year.get_heaven_stem().get_terrain(year.get_earth_branch()).get_name(),
      month: month.get_heaven_stem().get_terrain(month.get_earth_branch()).get_name(),
      day: day.get_heaven_stem().get_terrain(day.get_earth_branch()).get_name(),
      time: hour.get_heaven_stem().get_terrain(hour.get_earth_branch()).get_name(),
    }
  }
  pub fn to_table(&self, builder: &mut Builder){
    builder.push_record(vec![
      "地势",
      &self.year,
      &self.month,
      &self.day,
      &self.time,
    ]);
  }
}



impl EarthBranch {
  fn new(
    year: &SixtyCycle,
    month: &SixtyCycle,
    day: &SixtyCycle,
    hour: &SixtyCycle,
  ) -> Self {
      Self { year: year.get_earth_branch().get_name(), month: month.get_earth_branch().get_name(), day: day.get_earth_branch().get_name(), time: hour.get_earth_branch().get_name() }
  }
  pub fn to_table(&self, builder: &mut Builder){
    builder.push_record(vec![
      "地支",
      &self.year,
      &self.month,
      &self.day,
      &self.time 
    ]);
  }
}

impl Nayin {
  fn new(
    year: &SixtyCycle,
    month: &SixtyCycle,
    day: &SixtyCycle,
    hour: &SixtyCycle,
  ) -> Self {
    Self {
      year: year.get_sound().get_name(),
      month: month.get_sound().get_name(),
      day: day.get_sound().get_name(),
      time: hour.get_sound().get_name(),
    }
  }
  pub fn to_table(&self, builder: &mut Builder){
    builder.push_record(vec![
      "纳音",
      &self.year,
      &self.month,
      &self.day,
      &self.time,
    ]);
  }
}


pub fn bazi(
  cli: &Cli,
  opts: &BaziArgs,
) {
  let date_obj = opts.date;
  let solar_time = SolarTime::from_ymd_hms(
    date_obj.year() as isize,
    date_obj.month() as usize,
    date_obj.day() as usize,
    date_obj.hour() as usize,
    date_obj.minute() as usize,
    date_obj.second() as usize,
  );
  let lunar_time = solar_time.get_lunar_hour();
  let sixty_cycle_hour = lunar_time.get_sixty_cycle_hour();
  let ec = sixty_cycle_hour.get_eight_char();

  let year = ec.get_year();
  let month = ec.get_month();
  let day = ec.get_day();
  let hour = ec.get_hour();

  let fetal_origin = ec.get_fetal_origin();
  let fetal_breath  = ec.get_fetal_breath();
  let own_sign = ec.get_own_sign();
  let body_sign = ec.get_body_sign();

  let mut builder = Builder::default();

  builder.push_record(vec!["属性", "年柱", "月柱", "日柱", "时柱"]);

  let earth_branch = EarthBranch::new(&year, &month, &day, &hour);
  let terrain = Terrain::new(&year, &month, &day, &hour);
  let nayin = Nayin::new(&year, &month, &day, &hour);
  let ten_star = TenStar::new(&year, &month, &day, &hour);

  let year_heaven_stem = year.get_heaven_stem();
  let month_heaven_stem = month.get_heaven_stem();
  let day_heaven_stem = day.get_heaven_stem();
  let hour_heaven_stem = hour.get_heaven_stem();
  builder.push_record(vec!["天干", &year_heaven_stem.get_name(), &month_heaven_stem.get_name(), &day_heaven_stem.get_name(), &hour_heaven_stem.get_name()]);

  earth_branch.to_table(&mut builder);
  terrain.to_table(&mut builder);
  ten_star.to_table(&mut builder);
  nayin.to_table(&mut builder);

  builder.push_record(vec!["胎元", &fetal_origin.get_name(), "", "", ""]);
  builder.push_record(vec!["胎息", &fetal_breath.get_name(), "", "", ""]);
  builder.push_record(vec!["命宫", &own_sign.get_name(), "", "", ""]);
  builder.push_record(vec!["身宫", &body_sign.get_name(), "", "", ""]);

  let mut table = builder.build();
  let rows_count = table.count_rows();
  let cols_count = table.count_columns();

  for i in (rows_count - 4)..rows_count {
    table
    .with(Modify::new(Cell::new(i, 1)).with(Span::column((cols_count - 1) as isize)))
    .with(Alignment::center());
  }

  println!("{}", table.to_string());

}
