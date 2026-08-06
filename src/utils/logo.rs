use colored::Colorize;

pub fn print_logo() {
    let logo = r#"
      ▀▀  ▄▄                                
██ ██ ██  ██ ▄█▀ ▄███▄ ███▄███▄  ▀▀█▄ ████▄ 
 ███  ██  ████   ██ ██ ██ ██ ██ ▄█▀██ ██ ██ 
██ ██ ██▄ ██ ▀█▄ ▀███▀ ██ ██ ██ ▀█▄██ ████▀ 
                                      ██    
                                      ▀▀    
"#;

    println!("{}", logo.cyan().bold());
    println!(
        "    {} {}\n",
        "Network Reconnaissance Tool".bold(),
        "v0.1.0".dimmed()
    );
}