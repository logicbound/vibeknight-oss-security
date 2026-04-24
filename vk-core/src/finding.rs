use serde::{Deserialize, Serialize};
use vk_ir::SCHEMA_VERSION;

use crate::flow::ExecutionChain;
use crate::signals::{compute_risk_score, Signal};

/// The top-level finding contract — what downstream systems and humans consume.
///
/// `risk_score` is in [0.0, 1.0].  It is computed from signal weights and
/// the highest execution-chain confidence seen in this package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub schema_version: String,
    pub package: String,
    pub version: String,
    /// SHA-256 integrity hash of the tarball for dedup and reproducibility.
    pub integrity_hash: String,
    /// Composite risk score in [0.0, 1.0] derived from signal severity and
    /// execution-chain confidence.  Higher → more suspicious.
    pub risk_score: f32,
    /// Semantic signals derived from the behavioural IR.
    pub signals: Vec<Signal>,
    /// Execution chains rooted at entry points.
    pub execution_chains: Vec<ExecutionChain>,
    /// Highest-confidence evidence nodes.
    pub evidence: Vec<Evidence>,
}

impl Finding {
    pub fn new(
        package: String,
        version: String,
        integrity_hash: String,
        signals: Vec<Signal>,
        execution_chains: Vec<ExecutionChain>,
        evidence: Vec<Evidence>,
    ) -> Self {
        let max_confidence = execution_chains
            .iter()
            .map(|c| c.confidence)
            .fold(0.0f32, f32::max);
        let risk_score = compute_risk_score(&signals, max_confidence);

        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            package,
            version,
            integrity_hash,
            risk_score,
            signals,
            execution_chains,
            evidence,
        }
    }
}

/// A single piece of forensic evidence pointing to a specific node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub file: String,
    pub line: u32,
}
