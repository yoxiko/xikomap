import re

def detect_cms(target: str, port: int, banner: str) -> str:
    if not banner:
        return "unknown"
    
    banner_lower = banner.lower()
    
    if "wordpress" in banner_lower or "wp-content" in banner_lower or "wp-includes" in banner_lower:
        return "wordpress"
    
    if "joomla" in banner_lower or "joomla!" in banner_lower:
        return "joomla"
    
    if "drupal" in banner_lower or "x-drupal" in banner_lower:
        return "drupal"
    
    if "magento" in banner_lower or "x-magento" in banner_lower:
        return "magento"
    
    if "shopify" in banner_lower or "myshopify" in banner_lower:
        return "shopify"
    
    if re.search(r"x-powered-by:\s*php", banner_lower):
        return "php_backend"
        
    if re.search(r"x-powered-by:\s*asp\.net", banner_lower):
        return "aspnet_backend"

    return "unknown"