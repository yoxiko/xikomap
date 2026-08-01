def detect_cms(port: int, banner: str, http_body: str, http_headers: str) -> str | None:
    if port not in (80, 443, 8080, 8000, 8443, 3000, 5000, 9090):
        return None
        
    text_to_search = (http_body + http_headers + banner).lower()
    
    if "wordpress" in text_to_search or "wp-content" in text_to_search or "wp-includes" in text_to_search or "wp-json" in text_to_search:
        return "WordPress"
    if "drupal" in text_to_search or "drupal.js" in text_to_search or "sites/default" in text_to_search:
        return "Drupal"
    if "joomla" in text_to_search or "mosconfig" in text_to_search or "index.php?option=" in text_to_search:
        return "Joomla"
    if "magento" in text_to_search or "mage/" in text_to_search or "static/version" in text_to_search:
        return "Magento"
    if "shopify" in text_to_search or "cdn.shopify.com" in text_to_search:
        return "Shopify"
    if "wix" in text_to_search or "wixstatic.com" in text_to_search:
        return "Wix"
    if "x-powered-by: asp.net" in text_to_search or ".aspx" in text_to_search:
        return "ASP.NET"
    if "x-powered-by: php" in text_to_search or "phpsessid" in text_to_search:
        return "PHP"
    if "x-powered-by: express" in text_to_search or "node.js" in text_to_search:
        return "Node.js"
    if "server: nginx" in text_to_search:
        return "Nginx"
    if "server: apache" in text_to_search:
        return "Apache"
    if "server: cloudflare" in text_to_search or "cf-ray" in text_to_search:
        return "Cloudflare"
        
    return None