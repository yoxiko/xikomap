use colored::Colorize;

pub fn print_logo() {
    let logo = r#"
 __  ___   __       __  __                   __
 \ \/ (_)_/ /_____  /  |/  /___  ____  _____/ /__
  \  / / // //_  / / /|_/ / __ \/ __ \/ ___/ //_/
  / / / ,<  / /_/ / / /  / / /_/ / /_/ (__  ) ,<
 /_/_/_/|_| \__,_/ /_/  /_/\____/\____/____/_/|_|
"#;

    println!("{}", logo.cyan().bold());
    println!(
        "    {} {}\n",
        "Network Reconnaissance Tool".bold(),
        "v0.1.0".dimmed()
    );
}