//! The graded findings layer.
//!
//! Findings are derived, never collected. They are computed by the viewer over a
//! finished case and stored in a regenerable table, which buys three things: the
//! collector stays neutral and small, detection logic can be corrected and
//! re-run without touching the evidence, and a finding can always be deleted
//! without damaging the case.
//!
//! A finding that cannot name the events it rests on is an opinion, so
//! [`Finding::evidence`] is not optional.

use serde::{Deserialize, Serialize};

/// How much the analyst should care, if the finding is true.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Context worth showing, not itself suspicious.
    Info,
    Low,
    Medium,
    High,
    /// Consistent with active compromise.
    Critical,
}

impl Severity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn from_str_lossy(s: &str) -> Option<Self> {
        Some(match s {
            "info" => Severity::Info,
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            _ => return None,
        })
    }

    /// Rank for sorting and threshold filters.
    pub const fn rank(self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }
}

/// How sure the rule is that it read the evidence correctly.
///
/// Kept separate from [`Severity`] on purpose. "Critical if true, but I am
/// guessing" and "certainly true, but harmless" are different situations, and
/// collapsing them into one number is how triage tools end up crying wolf.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Circumstantial; the analyst should verify before acting.
    Low,
    Medium,
    /// The artifact says so directly.
    High,
}

impl Confidence {
    pub const fn as_str(self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }

    pub fn from_str_lossy(s: &str) -> Option<Self> {
        Some(match s {
            "low" => Confidence::Low,
            "medium" => Confidence::Medium,
            "high" => Confidence::High,
            _ => return None,
        })
    }
}

/// A derived observation about the case.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable rule identifier, for suppression and for tracking a rule's
    /// behaviour across cases. For example `mem.private_rwx_unbacked`.
    pub rule: String,
    pub severity: Severity,
    pub confidence: Confidence,
    /// One line, written for a responder under time pressure.
    pub title: String,
    /// What was observed and why the rule fired.
    pub detail: String,
    /// Row ids of the events supporting this finding. Never empty.
    pub evidence: Vec<i64>,
    /// Natural key of the entity the finding is about, when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_key: Option<String>,
}

impl Finding {
    pub fn new(
        rule: impl Into<String>,
        severity: Severity,
        confidence: Confidence,
        title: impl Into<String>,
        detail: impl Into<String>,
        evidence: Vec<i64>,
    ) -> Self {
        Self {
            rule: rule.into(),
            severity,
            confidence,
            title: title.into(),
            detail: detail.into(),
            evidence,
            entity_key: None,
        }
    }

    pub fn about(mut self, entity_key: impl Into<String>) -> Self {
        self.entity_key = Some(entity_key.into());
        self
    }

    /// A finding with no evidence is not publishable.
    pub fn is_supported(&self) -> bool {
        !self.evidence.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ranks_are_ordered() {
        assert!(Severity::Critical.rank() > Severity::High.rank());
        assert!(Severity::Info.rank() < Severity::Low.rank());
    }

    #[test]
    fn severity_and_confidence_roundtrip() {
        for s in [Severity::Info, Severity::High, Severity::Critical] {
            assert_eq!(Severity::from_str_lossy(s.as_str()), Some(s));
        }
        for c in [Confidence::Low, Confidence::Medium, Confidence::High] {
            assert_eq!(Confidence::from_str_lossy(c.as_str()), Some(c));
        }
    }

    #[test]
    fn finding_without_evidence_is_unsupported() {
        let f = Finding::new(
            "test.rule",
            Severity::High,
            Confidence::High,
            "t",
            "d",
            vec![],
        );
        assert!(!f.is_supported());
        assert!(f.evidence.is_empty());
    }
}
