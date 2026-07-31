use regex::Regex;

pub fn detect_mail(banner: &str, port: u16) -> Option<String> {
    if port != 25 && port != 110 && port != 143 && port != 465 && port != 587 && port != 993 && port != 995 {
        return None;
    }

    let postfix_re = Regex::new(r"(?i)Postfix").unwrap();
    if postfix_re.is_match(banner) {
        return Some("Postfix SMTP".to_string());
    }

    let exim_re = Regex::new(r"(?i)Exim").unwrap();
    if exim_re.is_match(banner) {
        return Some("Exim SMTP".to_string());
    }

    let dovecot_re = Regex::new(r"(?i)Dovecot").unwrap();
    if dovecot_re.is_match(banner) {
        return Some("Dovecot".to_string());
    }

    let exchange_re = Regex::new(r"(?i)Microsoft ESMTP").unwrap();
    if exchange_re.is_match(banner) {
        return Some("Microsoft Exchange".to_string());
    }

    if port == 25 || port == 587 {
        return Some("SMTP".to_string());
    }
    if port == 110 || port == 995 {
        return Some("POP3".to_string());
    }
    if port == 143 || port == 993 {
        return Some("IMAP".to_string());
    }

    None
}