use pyo3::prelude::*;
use serde_json::Value;

#[pyfunction]
fn process_batch_py(json_payload: String) -> PyResult<String> {
    Python::with_gil(|py| {
        let batch_processor = py.import("py_detectors.batch_processor")?;
        let result = batch_processor.call_method1("process_batch", (json_payload,))?;
        result.extract::<String>()
    })
}

pub fn run_python_detectors_batch(json_payload: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let result_str = process_batch_py(json_payload.to_string())
        .map_err(|e| format!("Python execution failed: {}", e))?;
    let parsed: Value = serde_json::from_str(&result_str)?;
    Ok(parsed)
}