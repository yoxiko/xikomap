use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::path::PathBuf;

fn get_detectors_path() -> PathBuf {
    let mut path = std::env::current_exe().expect("Failed to get current exe path");
    path.pop();
    path.push("py_detectors");
    path
}

pub fn run_python_detectors(target: &str, port: u16, banner: Option<&str>) -> String {
    Python::with_gil(|py| {
        let sys = py.import("sys").unwrap();
        let detectors_path = get_detectors_path();
        let path_str = detectors_path.to_str().unwrap();
        sys.getattr("path").unwrap().call_method1("append", (path_str,)).unwrap();
        
        let cms_module = py.import("cms_framework_detector").unwrap();
        let ml_module = py.import("ml_classifier").unwrap();

        let kwargs = PyDict::new(py);
        kwargs.set_item("target", target).unwrap();
        kwargs.set_item("port", port).unwrap();
        kwargs.set_item("banner", banner.unwrap_or("")).unwrap();

        let cms_result = cms_module.call_method("detect_cms", (), Some(kwargs)).unwrap();
        let cms_name: String = cms_result.extract().unwrap();

        if cms_name != "unknown" {
            return cms_name;
        }

        let ml_result = ml_module.call_method("classify_service", (), Some(kwargs)).unwrap();
        let service_name: String = ml_result.extract().unwrap();

        service_name
    })
}