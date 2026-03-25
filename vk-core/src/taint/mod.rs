//! Taint analysis engine
//! 
//! This module provides comprehensive taint analysis capabilities including:
//! - Source/sink/sanitizer definitions
//! - Dataflow graph construction
//! - Forward taint propagation
//! - Inter-procedural analysis
//! - Reachability checks

pub mod model;
pub mod graph;
pub mod propagation;
pub mod interprocedural;
pub mod reachability;
pub mod pattern_provider;

pub use model::{Source, Sink, Sanitizer, SourceDef, SinkDef, SanitizerDef};
pub use graph::DataflowGraph;
pub use propagation::TaintPropagator;
pub use interprocedural::InterProceduralAnalyzer;
pub use reachability::ReachabilityAnalyzer;
pub use pattern_provider::{PatternProvider, DefaultPatternProvider};

