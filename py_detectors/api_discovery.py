import requests
import json
import sys
import re
from typing import Dict

class APIDiscovery:
    def __init__(self):
        self.common_paths = [
            "/api",
            "/api/v1",
            "/api/v2",
            "/graphql",
            "/openapi.json",
            "/swagger.json",
            "/swagger.yaml",
            "/api-docs",
            "/docs",
            "/api/swagger.json",
            "/api/openapi.json",
            "/redoc",
        ]

        self.graphql_queries = [
            "{ __schema { types { name } } }",
            '{ __type(name: "Query") { fields { name } } }',
        ]

    def discover(self, base_url, timeout=5):
        results = {
            "openapi": None,
            "graphql": None,
            "endpoints": [],
            "api_versions": [],
        }

        base_url = base_url.rstrip("/")

        for path in self.common_paths:
            url = f"{base_url}{path}"
            try:
                response = requests.get(
                    url,
                    timeout=timeout,
                    verify=False,
                    headers={"User-Agent": "xikomap/0.1.0"},
                )

                if response.status_code == 200:
                    if "openapi" in path or "swagger" in path:
                        try:
                            spec = response.json()
                            if "openapi" in spec or "swagger" in spec:
                                results["openapi"] = {
                                    "url": url,
                                    "version": spec.get("openapi", spec.get("swagger")),
                                    "title": spec.get("info", {}).get("title", "Unknown"),
                                }
                                if "paths" in spec:
                                    for path_name, methods in spec["paths"].items():
                                        for method in methods.keys():
                                            results["endpoints"].append(
                                                {"method": method.upper(), "path": path_name}
                                            )
                        except Exception:
                            pass

                    if "graphql" in path:
                        try:
                            graphql_response = requests.post(
                                url,
                                json={"query": self.graphql_queries[0]},
                                headers={
                                    "Content-Type": "application/json",
                                    "User-Agent": "xikomap/0.1.0",
                                },
                                timeout=timeout,
                                verify=False,
                            )

                            if graphql_response.status_code == 200:
                                data = graphql_response.json()
                                if "data" in data:
                                    results["graphql"] = {
                                        "url": url,
                                        "types": [
                                            t["name"]
                                            for t in data.get("data", {})
                                            .get("__schema", {})
                                            .get("types", [])
                                            if not t["name"].startswith("__")
                                        ][:10],
                                    }
                        except Exception:
                            pass

            except Exception:
                continue

        for v in ["v1", "v2", "v3"]:
            url = f"{base_url}/api/{v}"
            try:
                response = requests.get(
                    url,
                    timeout=timeout,
                    verify=False,
                    headers={"User-Agent": "xikomap/0.1.0"},
                )
                if response.status_code < 400:
                    results["api_versions"].append(v)
            except Exception:
                pass

        return results


if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore")
    if len(sys.argv) > 1:
        discovery = APIDiscovery()
        result = discovery.discover(sys.argv[1])
        print(json.dumps(result, indent=2))