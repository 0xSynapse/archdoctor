use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Needs action now.
    Action,
    /// Worth watching, not necessarily broken.
    Watch,
    /// Informational / trend.
    Info,
}

impl Severity {
    pub fn label_zh(self) -> &'static str {
        match self {
            Severity::Action => "需要处理",
            Severity::Watch => "值得关注",
            Severity::Info => "提示",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    Low,
    Medium,
    High,
}

impl Risk {
    pub fn label_zh(self) -> &'static str {
        match self {
            Risk::Low => "低",
            Risk::Medium => "中",
            Risk::High => "高",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fix {
    pub description: String,
    pub commands: Vec<String>,
    pub risk: Risk,
    /// Manual fixes are printed but never executed by `archdoctor fix`.
    #[serde(default)]
    pub manual: bool,
}

impl Fix {
    pub fn new(description: impl Into<String>, commands: Vec<String>, risk: Risk) -> Self {
        Self {
            description: description.into(),
            commands,
            risk,
            manual: false,
        }
    }

    pub fn manual(mut self) -> Self {
        self.manual = true;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TimeKind {
    /// Many messages in a short window, usually one boot.
    Burst,
    /// Repeated over days or across boots.
    Chronic,
    /// Not enough signal to classify.
    Normal,
}

impl TimeKind {
    pub fn label_zh(self) -> &'static str {
        match self {
            TimeKind::Burst => "一次性爆发",
            TimeKind::Chronic => "持续出现",
            TimeKind::Normal => "偶发",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeProfile {
    pub kind: TimeKind,
    pub count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last: Option<String>,
    #[serde(default)]
    pub days: usize,
    #[serde(default)]
    pub boots: usize,
    #[serde(default)]
    pub is_new: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub summary: String,
    #[serde(default)]
    pub evidence: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<Fix>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<TimeProfile>,
}

impl Finding {
    pub fn new(
        id: impl Into<String>,
        severity: Severity,
        title: impl Into<String>,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            severity,
            title: title.into(),
            summary: summary.into(),
            evidence: Vec::new(),
            fix: None,
            tags: Vec::new(),
            time: None,
        }
    }

    pub fn evidence(mut self, line: impl Into<String>) -> Self {
        self.evidence.push(line.into());
        self
    }

    pub fn evidence_many<I, S>(mut self, lines: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.evidence.extend(lines.into_iter().map(Into::into));
        self
    }

    pub fn fix(mut self, fix: Fix) -> Self {
        self.fix = Some(fix);
        self
    }

    pub fn tag(mut self, tag: &str) -> Self {
        if !self.tags.iter().any(|t| t == tag) {
            self.tags.push(tag.to_string());
        }
        self
    }

    pub fn time(mut self, time: TimeProfile) -> Self {
        self.time = Some(time);
        self
    }
}
