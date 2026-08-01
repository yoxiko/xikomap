use pyo3::prelude::*;
use serde_json::Value;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PythonBridgeError {
    #[error("Python execution failed: {0}")]
    ExecutionFailed(String),
    #[error("JSON parsing error: {0}")]
    JsonError(#[from] serde_json::Error),
}

#[pyfunction]
fn process_batch_py(json_payload: String) -> PyResult<String> {
    Python::with_gil(|py| {
        let current_dir = std::env::current_dir().map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyOSError, _>(format!("Failed to get current dir: {}", e))
        })?;

        let py_detectors_path = current_dir.join("py_detectors");

        if !py_detectors_path.exists() {
            return Err(PyErr::new::<pyo3::exceptions::PyFileNotFoundError, _>(
                "py_detectors directory not found",
            ));
        }

        let sys = py.import("sys")?;
        let py_path = sys.getattr("path")?;

        if let Ok(path_list) = py_path.downcast::<pyo3::types::PyList>() {
            let path_str = py_detectors_path.to_string_lossy().to_string();
            path_list.insert(0, path_str)?;
        }

        let batch_processor = py.import("batch_processor")?;
        let result = batch_processor.call_method1("process_batch", (json_payload,))?;
        result.extract::<String>()
    })
}

pub fn run_python_detectors_batch(json_payload: &str) -> Result<Value, PythonBridgeError> {
    let result_str = process_batch_py(json_payload.to_string())
        .map_err(|e| PythonBridgeError::ExecutionFailed(e.to_string()))?;
    let parsed: Value = serde_json::from_str(&result_str)?;
    Ok(parsed)
}