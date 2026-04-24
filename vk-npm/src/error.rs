use std::fmt;

#[derive(Debug)]
pub enum NpmError {
    Io(String),
    Network(String),
    Extract(String),
    Parse(String),
}

impl fmt::Display for NpmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NpmError::Io(s)      => write!(f, "IO error: {}", s),
            NpmError::Network(s) => write!(f, "Network error: {}", s),
            NpmError::Extract(s) => write!(f, "Extraction error: {}", s),
            NpmError::Parse(s)   => write!(f, "Parse error: {}", s),
        }
    }
}

impl std::error::Error for NpmError {}
