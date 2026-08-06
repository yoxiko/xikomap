use pyo3::prelude::*;
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
            let detectors_path = std::env::current_dir()
                .unwrap()
                .join("py_detectors")
                .to_str()
                .unwrap()
                .to_string();
            path.call_method1("insert", (0i32, detectors_path))?;
            Ok(())
        })?;
        Ok(PythonDetectorBridge)
    }

    fn call_python_detector(
        py: Python<'_>,
        module_name: &str,
        class_name: &str,
        args: impl IntoPy<Py<pyo3::types::PyTuple>>,
    ) -> PyResult<String> {
        let module = py.import_bound(module_name)?;
        let detector_cls = module.getattr(class_name)?;
        let detector = detector_cls.call0()?;
        let result = detector.call_method1("detect", args)?;
        let json_mod = py.import_bound("json")?;
        let json_str = json_mod.call_method1("dumps", (&result,))?;
        json_str.extract()
    }

    pub fn run_fingerprinting(
        &self,
        target: &str,
        port: u16,
    ) -> Result<FingerprintingResults, PyErr> {
        Python::with_gil(|py| {
            let scheme = if port == 80 || port == 8080 || port == 3000 {
                "http"
            } else {
                "https"
            };
            let url = format!("{}://{}:{}", scheme, target, port);
            let json_str = Self::call_python_detector(
                py,
                "fingerprinting_detector",
                "FingerprintingDetector",
                (url,),
            )?;
            let parsed: FingerprintingResults =
                serde_json::from_str(&json_str).unwrap_or_default();
            Ok(parsed)
        })
    }

    pub fn run_api_discovery(
        &self,
        target: &str,
        port: u16,
    ) -> Result<APIDiscoveryResults, PyErr> {
        Python::with_gil(|py| {
            let scheme = if port == 80 || port == 8080 || port == 3000 {
                "http"
            } else {
                "https"
            };
            let url = format!("{}://{}:{}", scheme, target, port);
            let json_str = Self::call_python_detector(
                py,
                "api_discovery",
                "APIDiscovery",
                (url,),
            )?;
            let parsed: APIDiscoveryResults =
                serde_json::from_str(&json_str).unwrap_or_default();
            Ok(parsed)
        })
    }

    pub fn run_cloud_detection(&self, target: &str) -> Result<CloudDetectionResults, PyErr> {
        Python::with_gil(|py| {
            let json_str = Self::call_python_detector(
                py,
                "cloud_detector",
                "CloudDetector",
                (target,),
            )?;
            let parsed: CloudDetectionResults =
                serde_json::from_str(&json_str).unwrap_or_default();
            Ok(parsed)
        })
    }

    pub fn run_iot_detection(
        &self,
        target: &str,
        ports: &[u16],
    ) -> Result<IoTDetectionResults, PyErr> {
        Python::with_gil(|py| {
            let ports_vec: Vec<u16> = ports.to_vec();
            let json_str = Self::call_python_detector(
                py,
                "iot_detector",
                "IoTDetector",
                (target, ports_vec),
            )?;
            let parsed: IoTDetectionResults =
                serde_json::from_str(&json_str).unwrap_or_default();
            Ok(parsed)
        })
    }
}