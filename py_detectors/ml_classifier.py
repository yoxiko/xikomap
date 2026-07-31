def classify_service(target: str, port: int, banner: str) -> str:
    if port == 22:
        return "ssh"
    if port == 21:
        return "ftp"
    if port == 23:
        return "telnet"
    if port == 25:
        return "smtp"
    if port == 53:
        return "dns"
    if port == 110:
        return "pop3"
    if port == 143:
        return "imap"
    if port == 443:
        return "https"
    if port == 3306:
        return "mysql"
    if port == 5432:
        return "postgresql"
    if port == 6379:
        return "redis"
    if port == 27017:
        return "mongodb"
    if port in [80, 8080, 8000, 8888]:
        return "http"
        
    if banner:
        if banner.startswith("SSH-"):
            return "ssh"
        if banner.startswith("220 "):
            return "ftp"
        if "HTTP/" in banner:
            return "http"
        if "SMTP" in banner or "220 " in banner:
            return "smtp"
            
    return "unknown"