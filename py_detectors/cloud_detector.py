import requests
import re
import sys
import socket
import json
from typing import Dict, List

class CloudDetector:
    def __init__(self):
        self.cloud_patterns = {
            "AWS S3": [
                r"s3\.amazonaws\.com",
                r"s3-[a-z]{2}-[a-z]+-\d\.amazonaws\.com",
                r"bucket\.s3\.amazonaws\.com",
            ],
            "AWS EC2": [
                r"ec2-\d+-\d+-\d+-\d+\.[a-z]+-compute-\d+\.amazonaws\.com",
                r"\.compute\.amazonaws\.com",
            ],
            "AWS CloudFront": [r"\.cloudfront\.net"],
            "GCP Storage": [r"\.storage\.googleapis\.com", r"\.appspot\.com"],
            "GCP Compute": [r"\.c\.[a-z]+-cloud\.google\.com"],
            "Azure Blob": [r"\.blob\.core\.windows\.net"],
            "Azure Web Apps": [r"\.azurewebsites\.net"],
            "Azure CDN": [r"\.azureedge\.net"],
            "Heroku": [r"\.herokuapp\.com"],
            "Vercel": [r"\.vercel\.app"],
            "Netlify": [r"\.netlify\.app"],
        }

    def detect(self, target, timeout=5):
        results = {
            "services": [],
            "cdn": None,
            "hosting": None,
            "buckets": [],
            "ip": None,
            "hostname": None,
        }

        try:
            ip = socket.gethostbyname(target)
            results["ip"] = ip

            try:
                hostname = socket.gethostbyaddr(ip)[0]
                results["hostname"] = hostname

                for service, patterns in self.cloud_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, hostname, re.IGNORECASE):
                            results["services"].append(
                                {"type": service, "evidence": hostname}
                            )
                            break
            except Exception:
                pass

        except Exception as e:
            results["dns_error"] = str(e)

        try:
            response = requests.get(
                f"http://{target}",
                timeout=timeout,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": "xikomap/0.1.0"},
            )

            headers = dict(response.headers)

            if "x-amz-cf-id" in headers or "x-amz-cf-pop" in headers:
                results["cdn"] = "AWS CloudFront"

            if "cf-ray" in headers or "cf-cache-status" in headers:
                results["cdn"] = "Cloudflare"

            if any("x-goog-" in k.lower() for k in headers.keys()):
                results["hosting"] = "Google Cloud"

            if any("x-ms-" in k.lower() for k in headers.keys()):
                results["hosting"] = "Azure"

            if "x-vercel-id" in headers:
                results["hosting"] = "Vercel"

            if "x-nf-request-id" in headers:
                results["hosting"] = "Netlify"

            s3_pattern = r"https?://([^/]+\.s3\.amazonaws\.com|s3\.amazonaws\.com/[^/]+)"
            buckets = re.findall(s3_pattern, response.text, re.IGNORECASE)
            if buckets:
                results["buckets"] = list(set(buckets))[:5]

        except Exception as e:
            results["http_error"] = str(e)

        return results


if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore")
    if len(sys.argv) > 1:
        detector = CloudDetector()
        result = detector.detect(sys.argv[1])
        print(json.dumps(result, indent=2))