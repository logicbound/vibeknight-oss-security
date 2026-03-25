//! Language-specific pattern providers
//!
//! Each language has its own pattern provider implementation that
//! provides language-specific taint analysis patterns.

mod js;

pub use js::JavaScriptPatternProvider;

