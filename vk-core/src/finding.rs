use serde::{Deserialize, Serialize};
use vk_ir::SCHEMA_VERSION;

use crate::attacker_control::AttackerControlReport;
use crate::benign_patterns::BenignMatch;
use crate::flow::ExecutionChain;
use crate::package_type::PackageClassification;
use crate::scoring::{FeatureVector, ScoreBreakdown};
use crate::signals::Signal;

/// The top-level finding contract — what downstream systems and humans consume.
///
/// `risk_score` is in [0.0, 1.0] and is produced by
/// [`crate::scoring::compute_risk_score`]. It is intentionally surrounded by
/// a rich feature set (classification, attacker-control, benign matches,
/// feature vector, per-score breakdown) so the downstream AI/OSINT layer
/// can reproduce or override the verdict without the engine having to
/// commit to a single hard-coded policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub schema_version: String,
    pub package: String,
    pub version: String,
    /// SHA-256 integrity hash of the tarball for dedup and reproducibility.
    pub integrity_hash: String,
    /// Composite risk score in [0.0, 1.0] derived from signal severity,
    /// benign dampeners, package-type adjustment, and attacker-control gate.
    pub risk_score: f32,
    /// Breakdown of positive / negative / gate contributions for debuggability.
    pub score_breakdown: ScoreBreakdown,
    /// Coarse package classification (DevTool / Cli / RuntimeLib / Unknown)
    /// plus the evidence that led there.
    pub classification: PackageClassification,
    /// Attacker-controllability report — the single biggest driver of the
    /// score under the new model.
    pub attacker_control: AttackerControlReport,
    /// Benign pattern matches (e.g. `node-gyp rebuild`) that acted as
    /// dampeners in scoring.
    pub benign_matches: Vec<BenignMatch>,
    /// Raw feature vector (sink counts, data-source counts) for the
    /// downstream AI layer.
    pub features: FeatureVector,
    /// Semantic signals derived from the behavioural IR.
    pub signals: Vec<Signal>,
    /// Execution chains rooted at entry points.
    pub execution_chains: Vec<ExecutionChain>,
    /// Highest-confidence evidence nodes.
    pub evidence: Vec<Evidence>,
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

/// Builder-style constructor that wires together all the score inputs.
pub fn build_finding(
    package: String,
    version: String,
    integrity_hash: String,
    signals: Vec<Signal>,
    execution_chains: Vec<ExecutionChain>,
    evidence: Vec<Evidence>,
    classification: PackageClassification,
    attacker_control: AttackerControlReport,
    benign_matches: Vec<BenignMatch>,
    features: FeatureVector,
    score_breakdown: ScoreBreakdown,
) -> Finding {
    Finding {
        schema_version: SCHEMA_VERSION.to_string(),
        package,
        version,
        integrity_hash,
        risk_score: score_breakdown.final_score,
        score_breakdown,
        classification,
        attacker_control,
        benign_matches,
        features,
        signals,
        execution_chains,
        evidence,
    }
}
