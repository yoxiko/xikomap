import re
import requests
import json
import sys
from typing import Dict, List

class FingerprintingDetector:
    def __init__(self):
        self.technologies = {
            "jQuery": {
                "patterns": [
                    r"jquery[.-]([\d.]+)\.js",
                    r"jquery/([\d.]+)",
                ],
                "headers": {
                    "X-Powered-By": ["jQuery"],
                },
            },
            "React": {
                "patterns": [
                    r"react(?:\.production|\.development)?\.min\.js",
                    r"__REACT",
                ],
                "html": [r"data-reactroot", r"__NEXT_DATA__"],
            },
            "WordPress": {
                "patterns": [r"/wp-content/", r"/wp-includes/"],
                "meta": [r'<meta name="generator" content="WordPress ([\d.]+)"'],
                "paths": ["/wp-login.php", "/wp-admin/"],
            },
            "Bootstrap": {
                "patterns": [
                    r"bootstrap[.-]([\d.]+)\.min\.css",
                    r"bootstrap/([\d.]+)",
                ]
            },
            "Vue.js": {
                "html": [r"__vue__", r'<div id="app">'],
                "patterns": [r"vue[.-]([\d.]+)\.js"],
            },
            "Angular": {
                "html": [r"ng-version=", r"ng-app"],
                "patterns": [r"angular[.-]([\d.]+)\.js"],
            },
            "Django": {
                "headers": {"Set-Cookie": ["csrftoken"]},
                "html": [r"csrfmiddlewaretoken"],
            },
            "Express": {
                "headers": {"X-Powered-By": ["Express"]},
            },
            "Nginx": {
                "headers": {"Server": ["nginx"]},
            },
            "Apache": {
                "headers": {"Server": ["Apache"]},
            },
        }

    def detect(self, url, timeout=5):
        results = {"detected": [], "versions": {}}

        try:
            response = requests.get(
                url,
                timeout=timeout,
                verify=False,
                headers={"User-Agent": "xikomap/0.1.0"},
            )
            html = response.text
            headers = dict(response.headers)

            for tech_name, tech_config in self.technologies.items():
                detected = False
                version = None

                if "patterns" in tech_config:
                    for pattern in tech_config["patterns"]:
                        match = re.search(pattern, html, re.IGNORECASE)
                        if match:
                            detected = True
                            if match.groups():
                                version = match.group(1)
                            break

                if "meta" in tech_config and not detected:
                    for pattern in tech_config["meta"]:
                        match = re.search(pattern, html, re.IGNORECASE)
                        if match:
                            detected = True
                            if match.groups():
                                version = match.group(1)
                            break

                if "html" in tech_config and not detected:
                    for pattern in tech_config["html"]:
                        if re.search(pattern, html, re.IGNORECASE):
                            detected = True
                            break

                if "headers" in tech_config and not detected:
                    for header, values in tech_config["headers"].items():
                        if header in headers:
                            for value in values:
                                if value.lower() in headers[header].lower():
                                    detected = True
                                    break

                if "paths" in tech_config and not detected:
                    for path in tech_config["paths"]:
                        try:
                            path_response = requests.get(
                                f"{url.rstrip('/')}{path}",
                                timeout=2,
                                verify=False,
                                headers={"User-Agent": "xikomap/0.1.0"},
                            )
                            if path_response.status_code < 400:
                                detected = True
                                break
                        except Exception:
                            pass

                if detected:
                    results["detected"].append(tech_name)
                    if version:
                        results["versions"][tech_name] = version

        except Exception as e:
            results["error"] = str(e)

        return results


if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore")
    if len(sys.argv) > 1:
        detector = FingerprintingDetector()
        result = detector.detect(sys.argv[1])
        print(json.dumps(result, indent=2))