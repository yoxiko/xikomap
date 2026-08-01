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
    if port == 111 or "rpc" in banner_lower:
        return "RPC"
    if port == 135 or "msrpc" in banner_lower:
        return "MSRPC"
    if port == 139 or "netbios" in banner_lower:
        return "NetBIOS"
    if port == 445 or "smb" in banner_lower:
        return "SMB"
    if port == 143 or "imap" in banner_lower:
        return "IMAP"
    if port == 110 or "pop3" in banner_lower:
        return "POP3"
    if port == 993 or "imaps" in banner_lower:
        return "IMAPS"
    if port == 995 or "pop3s" in banner_lower:
        return "POP3S"
    if port == 2049 or "nfs" in banner_lower:
        return "NFS"
    if port == 3389 or "rdp" in banner_lower:
        return "RDP"
    if port == 5900 or "vnc" in banner_lower:
        return "VNC"
    if port == 8080 or "http-proxy" in banner_lower:
        return "HTTP-Proxy"
    if port == 8443 or "https-alt" in banner_lower:
        return "HTTPS-Alt"
        
    return "Unknown"