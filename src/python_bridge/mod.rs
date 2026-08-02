use pyo3::prelude::*;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PythonBridgeError {
    #[error("Python execution failed: {0}")]
    ExecutionFailed(String),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl From<PythonBridgeError> for PyErr {
    fn from(err: PythonBridgeError) -> Self {
        pyo3::exceptions::PyRuntimeError::new_err(err.to_string())
    }
}

#[pyfunction]
fn analyze_technologies(graph_json: String) -> PyResult<String> {
    Python::with_gil(|py| {
        let sys = py.import_bound("sys").map_err(|e| PythonBridgeError::ExecutionFailed(e.to_string()))?;
        let path = sys.getattr("path").map_err(|e| PythonBridgeError::ExecutionFailed(e.to_string()))?;
        path.call_method1("append", ("./py_detectors",)).map_err(|e| PythonBridgeError::ExecutionFailed(e.to_string()))?;

        let module = py.import_bound("py_detectors.technology_detector")
            .map_err(|e| PythonBridgeError::ExecutionFailed(e.to_string()))?;
        
        let result = module.call_method1("analyze", (graph_json,))
            .map_err(|e| PythonBridgeError::ExecutionFailed(e.to_string()))?;
        
        result.extract::<String>()
            .map_err(|e| PythonBridgeError::ExecutionFailed(e.to_string()))
            .map_err(Into::into)
    })
}

pub fn register_python_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(analyze_technologies, m)?)?;
    Ok(())
}