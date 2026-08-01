def classify_service(port, banner):
    banner_lower = banner.lower()
    
    if port == 22 or "ssh" in banner_lower:
        return "SSH"
    if port == 21 or "ftp" in banner_lower:
        return "FTP"
    if port == 23 or "telnet" in banner_lower:
        return "Telnet"
    if port == 25 or port == 587 or "smtp" in banner_lower:
        return "SMTP"
    if port == 53 or "dns" in banner_lower:
        return "DNS"
    if port == 80 or port == 443 or port == 8080 or "http" in banner_lower:
        return "HTTP"
    if port == 3306 or "mysql" in banner_lower:
        return "MySQL"
    if port == 5432 or "postgres" in banner_lower:
        return "PostgreSQL"
    if port == 1433 or "mssql" in banner_lower:
        return "MSSQL"
    if port == 6379 or "redis" in banner_lower:
        return "Redis"
    if port == 27017 or "mongodb" in banner_lower:
        return "MongoDB"
        
    return "Unknown"