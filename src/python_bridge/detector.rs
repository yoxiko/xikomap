use pyo3::prelude::*;
use pyo3::types::PyDict;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize, Default)]
pub struct FingerprintingResults {
    #[serde(default)]
    pub detected: Vec<String>,
    #[serde(default)]
    pub versions: HashMap<String, String>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct OpenAPIInfo {
    pub url: Option<String>,
    pub version: Option<String>,
    pub title: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct GraphQLInfo {
    pub url: Option<String>,
    #[serde(default)]
    pub types: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct APIDiscoveryResults {
    pub openapi: Option<OpenAPIInfo>,
    pub graphql: Option<GraphQLInfo>,
    #[serde(default)]
    pub endpoints: Vec<HashMap<String, String>>,
    #[serde(default)]
    pub api_versions: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct CloudService {
    #[serde(rename = "type")]
    pub service_type: Option<String>,
    pub evidence: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct CloudDetectionResults {
    #[serde(default)]
    pub services: Vec<CloudService>,
    pub cdn: Option<String>,
    pub hosting: Option<String>,
    #[serde(default)]
    pub buckets: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct IoTDetectionResults {
    #[serde(default)]
    pub iot_devices: Vec<String>,
    pub mqtt: Option<HashMap<String, serde_json::Value>>,
    pub coap: Option<HashMap<String, serde_json::Value>>,
}

pub struct PythonDetectorBridge;

impl PythonDetectorBridge {
    pub fn new() -> Result<Self, PyErr> {
        Python::with_gil(|py| -> PyResult<()> {
            let sys = py.import_bound("sys")?;
            let path = sys.getattr("path")?;
            path.call_method1(
                "insert",
                (0i32, std::env::current_dir()?.join("py_detectors")),
            )?;
            Ok(())
        })?;
        Ok(PythonDetectorBridge)
    }

    pub fn run_fingerprinting(&self, target: &str, port: u16) -> Result<FingerprintingResults, PyErr> {
        Python::with_gil(|py| {
            let module = py.import_bound("fingerprinting_detector")?;
            let detector_cls = module.getattr("FingerprintingDetector")?;
            let detector = detector_cls.call0()?;

            let scheme = if port == 80 || port == 8080 || port == 3000 {
                "http"
            } else {
                "https"
            };
            let url = format!("{}://{}:{}", scheme, target, port);

            let result = detector.call_method1("detect", (url,))?;
            let result_dict: &PyDict = result.downcast()?;

            let json_str = py.import_bound("json")?.call_method1("dumps", (result_dict,))?;
            let json_str: String = json_str.extract()?;

            let parsed: FingerprintingResults =
                serde_json::from_str(&json_str).unwrap_or_default();
            Ok(parsed)
        })
    }

    pub fn run_api_discovery(&self, target: &str, port: u16) -> Result<APIDiscoveryResults, PyErr> {
        Python::with_gil(|py| {
            let module = py.import_bound("api_discovery")?;
            let discovery_cls = module.getattr("APIDiscovery")?;
            let discovery = discovery_cls.call0()?;

            let scheme = if port == 80 || port == 8080 || port == 3000 {
                "http"
            } else {
                "https"
            };
            let url = format!("{}://{}:{}", scheme, target, port);

            let result = discovery.call_method1("discover", (url,))?;
            let result_dict: &PyDict = result.downcast()?;

            let json_str = py.import_bound("json")?.call_method1("dumps", (result_dict,))?;
            let json_str: String = json_str.extract()?;

            let parsed: APIDiscoveryResults = serde_json::from_str(&json_str).unwrap_or_default();
            Ok(parsed)
        })
    }

    pub fn run_cloud_detection(&self, target: &str) -> Result<CloudDetectionResults, PyErr> {
        Python::with_gil(|py| {
            let module = py.import_bound("cloud_detector")?;
            let detector_cls = module.getattr("CloudDetector")?;
            let detector = detector_cls.call0()?;

            let result = detector.call_method1("detect", (target,))?;
            let result_dict: &PyDict = result.downcast()?;

            let json_str = py.import_bound("json")?.call_method1("dumps", (result_dict,))?;
            let json_str: String = json_str.extract()?;

            let parsed: CloudDetectionResults = serde_json::from_str(&json_str).unwrap_or_default();
            Ok(parsed)
        })
    }

    pub fn run_iot_detection(
        &self,
        target: &str,
        ports: &[u16],
    ) -> Result<IoTDetectionResults, PyErr> {
        Python::with_gil(|py| {
            let module = py.import_bound("iot_detector")?;
            let detector_cls = module.getattr("IoTDetector")?;
            let detector = detector_cls.call0()?;

            let ports_vec: Vec<u16> = ports.to_vec();
            let result = detector.call_method1("detect", (target, ports_vec))?;
            let result_dict: &PyDict = result.downcast()?;

            let json_str = py.import_bound("json")?.call_method1("dumps", (result_dict,))?;
            let json_str: String = json_str.extract()?;

            let parsed: IoTDetectionResults = serde_json::from_str(&json_str).unwrap_or_default();
            Ok(parsed)
        })
    }
}