def detect_cms(port, banner, http_body, http_headers):
    if port not in (80, 443, 8080, 8000, 8443):
        return None
        
    text_to_search = (http_body + http_headers + banner).lower()
    
    if "wordpress" in text_to_search or "wp-content" in text_to_search or "wp-includes" in text_to_search:
        return "WordPress"
    if "drupal" in text_to_search or "drupal.js" in text_to_search:
        return "Drupal"
    if "joomla" in text_to_search or "mosconfig" in text_to_search:
        return "Joomla"
    if "magento" in text_to_search or "mage/" in text_to_search:
        return "Magento"
    if "x-powered-by: asp.net" in text_to_search or ".aspx" in text_to_search:
        return "ASP.NET"
    if "x-powered-by: php" in text_to_search or "phpsessid" in text_to_search:
        return "PHP"
    if "nginx" in text_to_search:
        return "Nginx"
    if "apache" in text_to_search:
        return "Apache"
        
    return None