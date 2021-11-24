use std::fmt;

#[derive(Debug, Clone)]
pub enum AgentErrorCode {
    // errors in c/s communication
    ResponseReadError = 100_001,
    JsonDecodeError = 100_002,
    ResponseEmptyError = 100_003,
    UnexpectedResponseFormat = 100_004,
    RequestEmptyError = 100_005,
    // errors in task executing
    _StartExecutionError = 101_001,
    // other error types
    ClientNotInitialized = 102_001,
    MaxRetryFailures = 102_002,
}

#[derive(Debug, Clone)]
pub struct AgentError<T: fmt::Debug> {
    pub code: AgentErrorCode,
    pub message: String,
    pub original_error: T,
}

impl<T: std::fmt::Debug> AgentError<T> {
    pub fn wrap(code: AgentErrorCode, message: &str, original_error: T) -> Self {
        AgentError {
            code: code,
            message: String::from(message),
            original_error: original_error,
        }
    }
}

impl AgentError<String> {
    pub fn new(code: AgentErrorCode, message: &str) -> Self {
        AgentError {
            code: code,
            message: String::from(message),
            original_error: String::from("None"),
        }
    }
}
