use reqwest::header::InvalidHeaderName as HttpInvalidHeaderNameError;
use reqwest::header::InvalidHeaderValue as HttpInvalidHeaderValueError;
use reqwest::Error as ReqwestError;
use std::io::Error as IoError;
use std::string::FromUtf8Error;

#[derive(Debug)]
pub enum Error {
    Object(ObjectError),
    Io(IoError),
    String(FromUtf8Error),
    Reqwest(ReqwestError),
    Http(HttpError),
}

#[derive(Debug)]
pub enum HttpError {
    HttpInvalidHeaderValue(HttpInvalidHeaderValueError),
    HttpInvalidHeaderName(HttpInvalidHeaderNameError),
}

impl From<IoError> for Error {
    fn from(e: IoError) -> Error {
        Error::Io(e)
    }
}

impl From<ReqwestError> for Error {
    fn from(e: ReqwestError) -> Error {
        Error::Reqwest(e)
    }
}

impl From<HttpInvalidHeaderValueError> for Error {
    fn from(e: HttpInvalidHeaderValueError) -> Error {
        Error::Http(HttpError::HttpInvalidHeaderValue(e))
    }
}

impl From<HttpInvalidHeaderNameError> for Error {
    fn from(e: HttpInvalidHeaderNameError) -> Error {
        Error::Http(HttpError::HttpInvalidHeaderName(e))
    }
}

impl From<FromUtf8Error> for Error {
    fn from(e: FromUtf8Error) -> Error {
        Error::String(e)
    }
}

#[derive(Debug)]
pub enum ObjectError {
    PutError { msg: String },
}
