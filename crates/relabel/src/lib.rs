// Copyright 2026 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Prometheus-compatible target and metric relabeling (`relabel_configs` and
//! `metric_relabel_configs`), ported from Prometheus `model/relabel` and `scrape/target.go`.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::sync::OnceLock;

use regex::{CaptureLocations, Regex};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Reserved Prometheus label holding the metric name (`"__name__"`).
pub const METRIC_NAME_LABEL: &str = "__name__";
/// Reserved Prometheus label holding the `<host>:<port>` scrape target address.
pub const ADDRESS_LABEL: &str = "__address__";
/// Reserved Prometheus label holding the scrape HTTP scheme (`"http"` or `"https"`).
pub const SCHEME_LABEL: &str = "__scheme__";
/// Reserved Prometheus label holding the scrape HTTP request path (e.g. `"/metrics"`).
pub const METRICS_PATH_LABEL: &str = "__metrics_path__";
/// Reserved Prometheus label holding the target scrape interval duration string.
pub const SCRAPE_INTERVAL_LABEL: &str = "__scrape_interval__";
/// Reserved Prometheus label holding the target scrape timeout duration string.
pub const SCRAPE_TIMEOUT_LABEL: &str = "__scrape_timeout__";
/// Prefix for reserved Prometheus labels mapping to URL query parameters (`"__param_"`).
pub const PARAM_LABEL_PREFIX: &str = "__param_";
/// Prefix for service-discovery metadata labels (`"__meta_"`).
pub const META_LABEL_PREFIX: &str = "__meta_";
/// Prefix for temporary labels used during relabeling (`"__tmp_"`).
pub const TMP_LABEL_PREFIX: &str = "__tmp_";
/// Prefix for all internal/reserved Prometheus labels (`"__"`).
pub const RESERVED_LABEL_PREFIX: &str = "__";
/// Standard Prometheus job label (`"job"`).
pub const JOB_LABEL: &str = "job";
/// Standard Prometheus instance label (`"instance"`).
pub const INSTANCE_LABEL: &str = "instance";
/// Prefix prepended to conflicting metric labels when `honor_labels` is `false` (`"exported_"`).
pub const EXPORTED_LABEL_PREFIX: &str = "exported_";

/// Default `separator` in a Prometheus relabel configuration (`";"`).
pub const DEFAULT_SEPARATOR: &str = ";";
/// Default `replacement` in a Prometheus relabel configuration (`"$1"`).
pub const DEFAULT_REPLACEMENT: &str = "$1";
/// Default unanchored `regex` pattern in a Prometheus relabel configuration (`"(.*)"`).
pub const DEFAULT_REGEX_PATTERN: &str = "(.*)";

/// Ordered map of label names to label values matching Prometheus `model.LabelSet`.
pub type LabelSet = BTreeMap<String, String>;

/// Error returned when parsing, validating, or applying relabel configurations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RelabelError {
    /// Relabel configuration validation error.
    #[error("{0}")]
    InvalidConfig(String),
    /// Invalid regular expression pattern.
    #[error("invalid regex: {0}")]
    InvalidRegex(String),
    /// Target population error after relabeling.
    #[error("{0}")]
    TargetError(String),
}

/// Relabeling action matching Prometheus `relabel.Action`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Action {
    /// Performs a regular expression replacement on `target_label` (default).
    #[default]
    Replace,
    /// Drops targets/samples for which the concatenated source labels do not match `regex`.
    Keep,
    /// Drops targets/samples for which the concatenated source labels match `regex`.
    Drop,
    /// Drops targets/samples for which the concatenated source labels do not equal `target_label`.
    KeepEqual,
    /// Drops targets/samples for which the concatenated source labels equal `target_label`.
    DropEqual,
    /// Sets `target_label` to the MD5 hash modulus of the concatenated source labels.
    HashMod,
    /// Copies labels whose names match `regex` to new label names computed via `replacement`.
    LabelMap,
    /// Drops any label whose name matches `regex`.
    LabelDrop,
    /// Drops any label whose name does not match `regex`.
    LabelKeep,
    /// Maps the concatenated source labels to lowercase and stores the result in `target_label`.
    Lowercase,
    /// Maps the concatenated source labels to uppercase and stores the result in `target_label`.
    Uppercase,
}

impl Action {
    /// Returns the lowercase Prometheus string representation of this action.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Replace => "replace",
            Self::Keep => "keep",
            Self::Drop => "drop",
            Self::KeepEqual => "keepequal",
            Self::DropEqual => "dropequal",
            Self::HashMod => "hashmod",
            Self::LabelMap => "labelmap",
            Self::LabelDrop => "labeldrop",
            Self::LabelKeep => "labelkeep",
            Self::Lowercase => "lowercase",
            Self::Uppercase => "uppercase",
        }
    }

    /// Parses a case-insensitive relabel action name matching Prometheus `Action.UnmarshalYAML`.
    pub fn parse(s: &str) -> Result<Self, RelabelError> {
        match s.to_ascii_lowercase().as_str() {
            "replace" => Ok(Self::Replace),
            "keep" => Ok(Self::Keep),
            "drop" => Ok(Self::Drop),
            "keepequal" => Ok(Self::KeepEqual),
            "dropequal" => Ok(Self::DropEqual),
            "hashmod" => Ok(Self::HashMod),
            "labelmap" => Ok(Self::LabelMap),
            "labeldrop" => Ok(Self::LabelDrop),
            "labelkeep" => Ok(Self::LabelKeep),
            "lowercase" => Ok(Self::Lowercase),
            "uppercase" => Ok(Self::Uppercase),
            _ => Err(RelabelError::InvalidConfig(format!(
                "unknown relabel action {s:?}"
            ))),
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Action {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Action {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = Option::<String>::deserialize(deserializer)?;
        match s {
            None => Ok(Self::Replace),
            Some(val) => Self::parse(&val).map_err(serde::de::Error::custom),
        }
    }
}

/// Label name validation scheme matching Prometheus `model.ValidationScheme`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ValidationScheme {
    /// Unset scheme; inherits the global validation scheme passed to [`Config::validate`].
    #[default]
    Unset,
    /// UTF-8 label name validation (`model.UTF8Validation`, default in Prometheus v3+).
    Utf8,
    /// Legacy ASCII `[a-zA-Z_][a-zA-Z0-9_]*` label name validation (`model.LegacyValidation`).
    Legacy,
}

impl ValidationScheme {
    /// Returns `true` if `name` is a valid Prometheus label name under this scheme.
    pub fn is_valid_label_name(self, name: &str) -> bool {
        if name.is_empty() {
            return false;
        }
        match self {
            Self::Utf8 | Self::Unset => true,
            Self::Legacy => is_valid_legacy_label_name(name),
        }
    }
}

/// Returns `true` if `name` matches legacy Prometheus label name syntax `[a-zA-Z_][a-zA-Z0-9_]*`.
pub fn is_valid_legacy_label_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    let Some(&first) = bytes.first() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Returns `true` if `target` matches Prometheus `relabelTargetLegacy`
/// (`^(?:(?:[a-zA-Z_]|\$(?:\{\w+\}|\w+))+\w*)+$`), which permits `$1` / `${var}` expansions
/// within legacy ASCII label names.
pub fn is_valid_legacy_target_label(target: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"^(?:(?:[a-zA-Z_]|\$(?:\{[0-9A-Za-z_]+\}|[0-9A-Za-z_]+))+[0-9A-Za-z_]*)+$")
            .expect("valid relabelTargetLegacy regex")
    });
    re.is_match(target)
}

/// Anchored regular expression matching Prometheus `relabel.Regexp` (`^(?s:<pattern>)$`).
#[derive(Clone, Debug)]
pub struct Regexp {
    raw: String,
    compiled: Regex,
    named_groups: Box<[(Box<str>, usize)]>,
    is_implicit_default: bool,
}

impl PartialEq for Regexp {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}

impl Eq for Regexp {}

impl Default for Regexp {
    fn default() -> Self {
        Self::default_regexp()
    }
}

impl Regexp {
    /// Compiles a new anchored regular expression `^(?s:<pattern>)$` matching Prometheus
    /// `relabel.NewRegexp` (including Go RE2 ASCII semantics for `\d`, `\D`, `\w`, `\W`, `\s`,
    /// `\S`, `\b`, and `\B`).
    pub fn new(pattern: &str) -> Result<Self, RelabelError> {
        let normalized = rewrite_re2_ascii_perl_escapes(pattern);
        let anchored = format!("^(?s:{normalized})$");
        let compiled =
            Regex::new(&anchored).map_err(|e| RelabelError::InvalidRegex(e.to_string()))?;
        let named_groups = compiled
            .capture_names()
            .enumerate()
            .filter_map(|(idx, name)| name.map(|n| (n.into(), idx)))
            .collect();
        Ok(Self {
            raw: pattern.to_owned(),
            compiled,
            named_groups,
            is_implicit_default: false,
        })
    }

    /// Compiles a new anchored regular expression or panics if invalid, matching
    /// Prometheus `relabel.MustNewRegexp`.
    pub fn must_new(pattern: &str) -> Self {
        Self::new(pattern).unwrap_or_else(|e| panic!("invalid relabel regex {pattern:?}: {e}"))
    }

    /// Returns the default Prometheus relabel regex (`"(.*)"`).
    pub fn default_regexp() -> Self {
        let mut r = Self::must_new(DEFAULT_REGEX_PATTERN);
        r.is_implicit_default = true;
        r
    }

    /// Returns an empty anchored regex (`""` -> `^(?s:)$`).
    pub fn empty() -> Self {
        Self::must_new("")
    }

    /// Returns the unanchored source pattern string, matching `relabel.Regexp.String()`.
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Returns `true` if `text` matches the anchored regular expression.
    pub fn is_match(&self, text: &str) -> bool {
        self.compiled.is_match(text)
    }

    /// Returns `true` if this regex has the default `"(.*)"` pattern.
    pub fn is_default(&self) -> bool {
        self.raw == DEFAULT_REGEX_PATTERN
    }

    const fn is_implicit_default(&self) -> bool {
        self.is_implicit_default
    }
}

impl Serialize for Regexp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.raw)
    }
}

impl<'de> Deserialize<'de> for Regexp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let opt = Option::<String>::deserialize(deserializer)?;
        let pattern = opt.unwrap_or_default();
        Self::new(&pattern).map_err(serde::de::Error::custom)
    }
}

/// Rewrites Go RE2 ASCII Perl escapes (`\d`, `\D`, `\w`, `\W`, `\s`, `\S`, `\b`, `\B`) so
/// `regex::Regex` keeps `.` and `\p{...}` Unicode-aware while matching ASCII-only Perl classes
/// like Go `regexp/syntax`.
fn rewrite_re2_ascii_perl_escapes(pattern: &str) -> Cow<'_, str> {
    if !pattern.contains('\\') {
        return Cow::Borrowed(pattern);
    }

    let mut out = String::with_capacity(pattern.len() + 8);
    let mut chars = pattern.chars().peekable();
    let mut bracket_depth = 0usize;

    while let Some(ch) = chars.next() {
        match ch {
            '\\' => match chars.next() {
                None => out.push('\\'),
                Some('Q') => {
                    let mut quoted = String::new();
                    while let Some(qch) = chars.next() {
                        if qch == '\\' && chars.peek() == Some(&'E') {
                            chars.next();
                            break;
                        }
                        quoted.push(qch);
                    }
                    out.push_str(&regex::escape(&quoted));
                }
                Some('d') => out.push_str("[0-9]"),
                Some('D') => out.push_str("[^0-9]"),
                Some('w') => out.push_str("[0-9A-Za-z_]"),
                Some('W') => out.push_str("[^0-9A-Za-z_]"),
                Some('s') => out.push_str("[\t\n\x0c\r ]"),
                Some('S') => out.push_str("[^\t\n\x0c\r ]"),
                Some('b') if bracket_depth == 0 => out.push_str(r"(?-u:\b)"),
                Some('B') if bracket_depth == 0 => out.push_str(r"(?-u:\B)"),
                Some(esc) => {
                    out.push('\\');
                    out.push(esc);
                }
            },
            '[' => {
                out.push('[');
                if bracket_depth > 0 && chars.peek() == Some(&':') {
                    chars.next();
                    out.push(':');
                    while let Some(pch) = chars.next() {
                        out.push(pch);
                        if pch == ':' && chars.peek() == Some(&']') {
                            chars.next();
                            out.push(']');
                            break;
                        }
                    }
                } else {
                    bracket_depth += 1;
                    if chars.peek() == Some(&'^') {
                        chars.next();
                        out.push('^');
                    }
                    if chars.peek() == Some(&']') {
                        chars.next();
                        out.push(']');
                    }
                }
            }
            ']' if bracket_depth > 0 => {
                bracket_depth -= 1;
                out.push(']');
            }
            other => out.push(other),
        }
    }

    Cow::Owned(out)
}

fn default_separator() -> String {
    DEFAULT_SEPARATOR.to_owned()
}

fn default_replacement() -> String {
    DEFAULT_REPLACEMENT.to_owned()
}

const fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

/// Configuration for a single relabeling step matching Prometheus `relabel.Config`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// List of source label names whose values are concatenated with `separator` in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_labels: Vec<String>,
    /// Separator placed between concatenated source label values (defaults to `";"`).
    #[serde(default = "default_separator")]
    pub separator: String,
    /// Anchored regular expression against which the concatenated value is matched
    /// (defaults to `"(.*)"`).
    #[serde(
        default = "Regexp::default_regexp",
        skip_serializing_if = "Regexp::is_implicit_default"
    )]
    pub regex: Regexp,
    /// Modulus to take of the MD5 hash of the concatenated source label values (`hashmod`).
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub modulus: u64,
    /// Target label name to which the resulting string is written (`replace`, `hashmod`,
    /// `lowercase`, `uppercase`) or compared (`keepequal`, `dropequal`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub target_label: String,
    /// Regex replacement template (defaults to `"$1"`).
    #[serde(default = "default_replacement")]
    pub replacement: String,
    /// Relabeling action to perform (defaults to [`Action::Replace`]).
    #[serde(default)]
    pub action: Action,
    /// Label name validation scheme (not serialized in YAML/JSON, matching Prometheus).
    #[serde(skip)]
    pub name_validation_scheme: ValidationScheme,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            source_labels: Vec::new(),
            separator: default_separator(),
            regex: Regexp::default_regexp(),
            modulus: 0,
            target_label: String::new(),
            replacement: default_replacement(),
            action: Action::Replace,
            name_validation_scheme: ValidationScheme::Unset,
        }
    }
}

impl Config {
    /// Validates this relabel configuration according to Prometheus `relabel.Config.Validate`.
    pub fn validate(&mut self, default_scheme: ValidationScheme) -> Result<(), RelabelError> {
        if self.modulus == 0 && self.action == Action::HashMod {
            return Err(RelabelError::InvalidConfig(
                "relabel configuration for hashmod requires non-zero modulus".to_owned(),
            ));
        }
        if matches!(
            self.action,
            Action::Replace
                | Action::HashMod
                | Action::Lowercase
                | Action::Uppercase
                | Action::KeepEqual
                | Action::DropEqual
        ) && self.target_label.is_empty()
        {
            return Err(RelabelError::InvalidConfig(format!(
                "relabel configuration for {} action requires 'target_label' value",
                self.action
            )));
        }

        if self.name_validation_scheme == ValidationScheme::Unset {
            self.name_validation_scheme = match default_scheme {
                ValidationScheme::Unset => ValidationScheme::Utf8,
                other => other,
            };
        }

        let scheme = self.name_validation_scheme;
        let is_valid_with_regex_var = |value: &str| match scheme {
            ValidationScheme::Utf8 | ValidationScheme::Unset => scheme.is_valid_label_name(value),
            ValidationScheme::Legacy => is_valid_legacy_target_label(value),
        };

        if self.action == Action::Replace
            && !var_in_regex_template(&self.target_label)
            && !scheme.is_valid_label_name(&self.target_label)
        {
            return Err(RelabelError::InvalidConfig(format!(
                "{:?} is invalid 'target_label' for {} action",
                self.target_label, self.action
            )));
        }
        if self.action == Action::Replace
            && var_in_regex_template(&self.target_label)
            && !is_valid_with_regex_var(&self.target_label)
        {
            return Err(RelabelError::InvalidConfig(format!(
                "{:?} is invalid 'target_label' for {} action",
                self.target_label, self.action
            )));
        }
        if matches!(
            self.action,
            Action::Lowercase | Action::Uppercase | Action::KeepEqual | Action::DropEqual
        ) && !scheme.is_valid_label_name(&self.target_label)
        {
            return Err(RelabelError::InvalidConfig(format!(
                "{:?} is invalid 'target_label' for {} action",
                self.target_label, self.action
            )));
        }
        if matches!(
            self.action,
            Action::Lowercase | Action::Uppercase | Action::KeepEqual | Action::DropEqual
        ) && self.replacement != DEFAULT_REPLACEMENT
        {
            return Err(RelabelError::InvalidConfig(format!(
                "'replacement' can not be set for {} action",
                self.action
            )));
        }
        if self.action == Action::LabelMap && !is_valid_with_regex_var(&self.replacement) {
            return Err(RelabelError::InvalidConfig(format!(
                "{:?} is invalid 'replacement' for {} action",
                self.replacement, self.action
            )));
        }
        if self.action == Action::HashMod && !scheme.is_valid_label_name(&self.target_label) {
            return Err(RelabelError::InvalidConfig(format!(
                "{:?} is invalid 'target_label' for {} action",
                self.target_label, self.action
            )));
        }

        if matches!(self.action, Action::DropEqual | Action::KeepEqual)
            && (!self.regex.is_implicit_default
                || self.modulus != 0
                || self.separator != DEFAULT_SEPARATOR
                || self.replacement != DEFAULT_REPLACEMENT)
        {
            return Err(RelabelError::InvalidConfig(format!(
                "{} action requires only 'source_labels' and `target_label`, and no other fields",
                self.action
            )));
        }

        if matches!(self.action, Action::LabelDrop | Action::LabelKeep)
            && (!self.source_labels.is_empty()
                || !self.target_label.is_empty()
                || self.modulus != 0
                || self.separator != DEFAULT_SEPARATOR
                || self.replacement != DEFAULT_REPLACEMENT)
        {
            return Err(RelabelError::InvalidConfig(format!(
                "{} action requires only 'regex', and no other fields",
                self.action
            )));
        }

        Ok(())
    }
}

fn var_in_regex_template(template: &str) -> bool {
    template.contains('$')
}

/// Returns the replacement slice without running regex captures when `cfg.regex` is the default
/// `(.*)` pattern (where `$0` and `$1` always equal `val`) and `cfg.replacement` is either static
/// or a direct `$0`/`$1` capture reference.
fn direct_replacement<'a>(cfg: &'a Config, val: &'a str) -> Option<&'a str> {
    if !cfg.regex.is_default() {
        return None;
    }
    if !var_in_regex_template(&cfg.replacement) {
        Some(cfg.replacement.as_str())
    } else if matches!(cfg.replacement.as_str(), "$1" | "${1}" | "$0" | "${0}") {
        Some(val)
    } else {
        None
    }
}

/// Applies a slice of relabel [`Config`] rules in order to a cloned [`LabelSet`].
///
/// Returns `Some(labels)` if the target/sample is kept, or `None` if a rule drops it.
pub fn process(labels: &LabelSet, cfgs: &[Config]) -> Option<LabelSet> {
    let mut out = labels.clone();
    if process_in_place(&mut out, cfgs) {
        Some(out)
    } else {
        None
    }
}

/// Applies a slice of relabel [`Config`] rules in-place to `labels`, matching
/// Prometheus `relabel.ProcessBuilder`.
///
/// Any label whose value is set to `""` is removed from `labels`.
/// Returns `true` if the target/sample is kept, or `false` if dropped.
pub fn process_in_place(labels: &mut LabelSet, cfgs: &[Config]) -> bool {
    // Strip any incoming empty-valued labels to match Prometheus `labels.Builder` invariants.
    labels.retain(|_, v| !v.is_empty());

    let mut val_buf = String::new();
    for cfg in cfgs {
        if !apply_single(cfg, labels, &mut val_buf) {
            return false;
        }
    }
    true
}

fn apply_single(cfg: &Config, labels: &mut LabelSet, val: &mut String) -> bool {
    val.clear();
    for (idx, ln) in cfg.source_labels.iter().enumerate() {
        if idx > 0 {
            val.push_str(&cfg.separator);
        }
        if let Some(v) = labels.get(ln.as_str()) {
            val.push_str(v);
        }
    }

    match cfg.action {
        Action::Drop => {
            if cfg.regex.is_match(val) {
                return false;
            }
        }
        Action::Keep => {
            if !cfg.regex.is_match(val) {
                return false;
            }
        }
        Action::DropEqual => {
            let target_val = labels
                .get(cfg.target_label.as_str())
                .map_or("", String::as_str);
            if target_val == val {
                return false;
            }
        }
        Action::KeepEqual => {
            let target_val = labels
                .get(cfg.target_label.as_str())
                .map_or("", String::as_str);
            if target_val != val {
                return false;
            }
        }
        Action::Replace => {
            if !var_in_regex_template(&cfg.target_label)
                && let Some(res) = direct_replacement(cfg, val)
            {
                if cfg
                    .name_validation_scheme
                    .is_valid_label_name(&cfg.target_label)
                {
                    set_or_del(labels, Cow::Borrowed(&cfg.target_label), Cow::Borrowed(res));
                }
                return true;
            }

            let mut locs = cfg.regex.compiled.capture_locations();
            if cfg.regex.compiled.captures_read(&mut locs, val).is_none() {
                return true;
            }
            let target = expand_template(&cfg.target_label, val, &locs, &cfg.regex.named_groups);
            if !cfg.name_validation_scheme.is_valid_label_name(&target) {
                return true;
            }
            let res = expand_template(&cfg.replacement, val, &locs, &cfg.regex.named_groups);
            set_or_del(labels, target, res);
        }
        Action::Lowercase => {
            if cfg
                .name_validation_scheme
                .is_valid_label_name(&cfg.target_label)
            {
                let lower = go_to_lowercase(val);
                set_or_del(labels, Cow::Borrowed(&cfg.target_label), lower);
            }
        }
        Action::Uppercase => {
            if cfg
                .name_validation_scheme
                .is_valid_label_name(&cfg.target_label)
            {
                let upper = go_to_uppercase(val);
                set_or_del(labels, Cow::Borrowed(&cfg.target_label), upper);
            }
        }
        Action::HashMod => {
            if cfg.modulus > 0
                && cfg
                    .name_validation_scheme
                    .is_valid_label_name(&cfg.target_label)
            {
                let modulo = hashmod_value(val, cfg.modulus);
                set_or_del(labels, Cow::Borrowed(&cfg.target_label), Cow::Owned(modulo));
            }
        }
        Action::LabelMap => {
            let mut locs = cfg.regex.compiled.capture_locations();
            let mut mapped = Vec::new();
            for (name, value) in labels.iter() {
                if cfg.regex.compiled.captures_read(&mut locs, name).is_some() {
                    let res =
                        expand_template(&cfg.replacement, name, &locs, &cfg.regex.named_groups);
                    if cfg.name_validation_scheme.is_valid_label_name(&res) {
                        mapped.push((res.into_owned(), value.clone()));
                    }
                }
            }
            for (res, value) in mapped {
                set_or_del(labels, Cow::Owned(res), Cow::Owned(value));
            }
        }
        Action::LabelDrop => {
            labels.retain(|name, _| !cfg.regex.is_match(name));
        }
        Action::LabelKeep => {
            labels.retain(|name, _| cfg.regex.is_match(name));
        }
    }

    true
}

fn set_or_del(labels: &mut LabelSet, key: Cow<'_, str>, value: Cow<'_, str>) {
    if key.is_empty() {
        return;
    }
    if value.is_empty() {
        labels.remove(key.as_ref());
    } else if let Some(existing) = labels.get_mut(key.as_ref()) {
        match value {
            Cow::Borrowed(s) => {
                existing.clear();
                existing.push_str(s);
            }
            Cow::Owned(s) => *existing = s,
        }
    } else {
        labels.insert(key.into_owned(), value.into_owned());
    }
}

/// Expands Go `regexp.ExpandString`-compatible `$1`, `${1}`, `$name`, `${name}`, and `$$`
/// references against `locs` captured from `haystack`.
fn expand_template<'a>(
    template: &'a str,
    haystack: &'a str,
    locs: &CaptureLocations,
    named_groups: &[(Box<str>, usize)],
) -> Cow<'a, str> {
    if !template.contains('$') {
        return Cow::Borrowed(template);
    }
    if matches!(template, "$1" | "${1}" | "$0" | "${0}") {
        let idx = usize::from(matches!(template, "$1" | "${1}"));
        return Cow::Borrowed(locs.get(idx).map_or("", |(s, e)| &haystack[s..e]));
    }

    let mut out = String::with_capacity(template.len());
    let mut rest = template;

    while let Some(dollar_idx) = rest.find('$') {
        out.push_str(&rest[..dollar_idx]);
        let after_dollar = &rest[dollar_idx + 1..];
        if let Some(stripped) = after_dollar.strip_prefix('$') {
            out.push('$');
            rest = stripped;
            continue;
        }
        if let Some((name, num, remaining)) = extract_template_var(after_dollar) {
            append_capture(&mut out, name, num, haystack, locs, named_groups);
            rest = remaining;
        } else {
            out.push('$');
            rest = after_dollar;
        }
    }
    out.push_str(rest);

    Cow::Owned(out)
}

/// Parses a variable reference after `'$'` matching Go `regexp.extract`.
fn extract_template_var(str_after_dollar: &str) -> Option<(&str, Option<usize>, &str)> {
    if str_after_dollar.is_empty() {
        return None;
    }
    let (brace, body) = if let Some(stripped) = str_after_dollar.strip_prefix('{') {
        (true, stripped)
    } else {
        (false, str_after_dollar)
    };

    let body_bytes = body.as_bytes();
    let mut end = 0;
    while end < body_bytes.len() {
        let b = body_bytes[end];
        if b.is_ascii_alphanumeric() || b == b'_' {
            end += 1;
        } else if b >= 0x80 {
            // Fall back to Unicode General Categories `L` (`unicode.IsLetter`) and `Nd`
            // (`unicode.IsDigit`) so non-decimal numbers such as `'²'` (`No`) terminate `$1²`
            // just like Go `regexp.extract`.
            if let Some(m) = ident_tail_regex().find(&body[end..]) {
                end += m.end();
            }
            break;
        } else {
            break;
        }
    }
    if end == 0 {
        return None;
    }

    let remaining = if brace {
        let after_name = &body[end..];
        if !after_name.starts_with('}') {
            return None;
        }
        &after_name[1..]
    } else {
        &body[end..]
    };

    let name = &body[..end];
    let name_bytes = name.as_bytes();
    // Go `regexp.extract` rejects leading zeros on multi-digit group numbers and numbers >= 1e8.
    let num = if name_bytes.len() > 1 && name_bytes[0] == b'0' {
        None
    } else {
        let mut parsed: usize = 0;
        let mut ok = true;
        for &b in name_bytes {
            if !b.is_ascii_digit() || parsed >= 100_000_000 {
                ok = false;
                break;
            }
            parsed = parsed * 10 + usize::from(b - b'0');
        }
        ok.then_some(parsed)
    };

    Some((name, num, remaining))
}

fn ident_tail_regex() -> &'static Regex {
    static IDENT_TAIL_RE: OnceLock<Regex> = OnceLock::new();
    IDENT_TAIL_RE.get_or_init(|| {
        Regex::new(r"^[\p{L}\p{Nd}_]+").expect("valid template var identifier regex")
    })
}

fn append_capture(
    out: &mut String,
    name: &str,
    num: Option<usize>,
    haystack: &str,
    locs: &CaptureLocations,
    named_groups: &[(Box<str>, usize)],
) {
    let group_idx = num.or_else(|| {
        named_groups
            .iter()
            .find(|(n, _)| n.as_ref() == name)
            .map(|&(_, idx)| idx)
    });
    if let Some(idx) = group_idx
        && let Some((start, end)) = locs.get(idx)
    {
        out.push_str(&haystack[start..end]);
    }
}

/// Scrape job defaults used to populate pre-relabel discovered target labels,
/// matching the scrape configuration fields consumed by Prometheus `scrape.PopulateLabels`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetPopulateConfig {
    /// Scrape `job_name`.
    pub job_name: String,
    /// Scrape interval duration string (for example `"15s"`).
    pub scrape_interval: String,
    /// Scrape timeout duration string (for example `"10s"`).
    pub scrape_timeout: String,
    /// Default metrics path (defaults to `"/metrics"`).
    pub metrics_path: String,
    /// Default URL scheme (defaults to `"http"`).
    pub scheme: String,
    /// Optional HTTP query parameters mapped to `__param_<name>` (first value).
    pub params: BTreeMap<String, Vec<String>>,
}

impl Default for TargetPopulateConfig {
    fn default() -> Self {
        Self {
            job_name: String::new(),
            scrape_interval: "1m".to_owned(),
            scrape_timeout: "10s".to_owned(),
            metrics_path: "/metrics".to_owned(),
            scheme: "http".to_owned(),
            params: BTreeMap::new(),
        }
    }
}

/// Result of populating and relabeling a discovered target via [`populate_labels`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PopulatedTarget {
    /// Final target labels after `relabel_configs` and `__meta_*` removal (includes `job`,
    /// `instance`, `__address__`, `__scheme__`, `__metrics_path__`, and any `__param_*` labels).
    pub labels: LabelSet,
    /// Pre-relabel discovered labels produced by [`populate_discovered_labels`].
    pub discovered_labels: LabelSet,
}

impl PopulatedTarget {
    /// Returns the public (non-`__`-prefixed) target labels emitted onto scraped samples or
    /// resource attributes (`job`, `instance`, and user labels).
    pub fn public_labels(&self) -> LabelSet {
        self.labels
            .iter()
            .filter(|(k, _)| !k.starts_with(RESERVED_LABEL_PREFIX))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

/// Builds the pre-relabel discovered label set from a target label set, common target-group
/// label set, and [`TargetPopulateConfig`], matching Prometheus `scrape.PopulateDiscoveredLabels`.
pub fn populate_discovered_labels(
    target: &LabelSet,
    group_labels: &LabelSet,
    cfg: &TargetPopulateConfig,
) -> LabelSet {
    let mut out = LabelSet::new();
    for (k, v) in target {
        if !v.is_empty() {
            out.insert(k.clone(), v.clone());
        }
    }
    for (k, v) in group_labels {
        if !v.is_empty() && !target.contains_key(k) {
            out.insert(k.clone(), v.clone());
        }
    }

    let defaults = [
        (JOB_LABEL, cfg.job_name.as_str()),
        (SCRAPE_INTERVAL_LABEL, cfg.scrape_interval.as_str()),
        (SCRAPE_TIMEOUT_LABEL, cfg.scrape_timeout.as_str()),
        (METRICS_PATH_LABEL, cfg.metrics_path.as_str()),
        (SCHEME_LABEL, cfg.scheme.as_str()),
    ];
    for (k, v) in defaults {
        if !v.is_empty() && !out.contains_key(k) {
            out.insert(k.to_owned(), v.to_owned());
        }
    }

    // Encode scrape query parameters into `__param_<name>` labels using the first value.
    for (k, vals) in &cfg.params {
        if let Some(first) = vals.first()
            && !first.is_empty()
        {
            let param_key = format!("{PARAM_LABEL_PREFIX}{k}");
            out.entry(param_key).or_insert_with(|| first.clone());
        }
    }

    out
}

/// Populates discovered labels, applies `relabel_configs`, validates `__address__`,
/// `__scrape_interval__`, and `__scrape_timeout__`, strips `__meta_*` labels, and sets the default
/// `instance` label, matching Prometheus `scrape.PopulateLabels`.
///
/// Returns `Ok(Some(PopulatedTarget))` if the target is kept, `Ok(None)` if dropped by
/// `relabel_configs`, or `Err(RelabelError::TargetError)` if `__address__`, `__scrape_interval__`,
/// or `__scrape_timeout__` is missing or invalid.
pub fn populate_labels(
    target: &LabelSet,
    group_labels: &LabelSet,
    cfg: &TargetPopulateConfig,
    relabel_configs: &[Config],
) -> Result<Option<PopulatedTarget>, RelabelError> {
    let discovered_labels = populate_discovered_labels(target, group_labels, cfg);
    let mut labels = discovered_labels.clone();
    if !process_in_place(&mut labels, relabel_configs) {
        return Ok(None);
    }

    let Some(addr) = labels.get(ADDRESS_LABEL).cloned() else {
        return Err(RelabelError::TargetError("no address".to_owned()));
    };
    if addr.is_empty() {
        return Err(RelabelError::TargetError("no address".to_owned()));
    }
    if addr.contains('/') {
        return Err(RelabelError::TargetError(format!(
            "{addr:?} is not a valid hostname"
        )));
    }

    let interval_str = labels.get(SCRAPE_INTERVAL_LABEL).map_or("", String::as_str);
    let interval_ns = parse_prometheus_duration(interval_str)
        .map_err(|e| RelabelError::TargetError(format!("error parsing scrape interval: {e}")))?;
    if interval_ns == 0 {
        return Err(RelabelError::TargetError(
            "scrape interval cannot be 0".to_owned(),
        ));
    }

    let timeout_str = labels.get(SCRAPE_TIMEOUT_LABEL).map_or("", String::as_str);
    let timeout_ns = parse_prometheus_duration(timeout_str)
        .map_err(|e| RelabelError::TargetError(format!("error parsing scrape timeout: {e}")))?;
    if timeout_ns == 0 {
        return Err(RelabelError::TargetError(
            "scrape timeout cannot be 0".to_owned(),
        ));
    }

    if timeout_ns > interval_ns {
        return Err(RelabelError::TargetError(format!(
            "scrape timeout cannot be greater than scrape interval ({timeout_str:?} > {interval_str:?})"
        )));
    }

    for (label_name, desc) in [
        (
            "__convert_classic_histograms_to_nhcb__",
            "convert classic histograms to nhcb",
        ),
        (
            "__always_scrape_classic_histograms__",
            "always scrape classic histograms",
        ),
        ("__scrape_native_histograms__", "scrape native histograms"),
    ] {
        if let Some(val) = labels.get(label_name)
            && !val.is_empty()
            && !is_valid_go_bool(val)
        {
            return Err(RelabelError::TargetError(format!(
                "error parsing {desc}: invalid syntax {val:?}"
            )));
        }
    }

    // Remove all `__meta_*` labels after target relabeling.
    labels.retain(|k, _| !k.starts_with(META_LABEL_PREFIX));

    // Default `instance` to `__address__` if not set by relabeling.
    if !labels.contains_key(INSTANCE_LABEL) {
        labels.insert(INSTANCE_LABEL.to_owned(), addr);
    }

    Ok(Some(PopulatedTarget {
        labels,
        discovered_labels,
    }))
}

/// Parses a non-negative Prometheus duration string into nanoseconds matching
/// `github.com/prometheus/common/model.ParseDuration` (`y`, `w`, `d`, `h`, `m`, `s`, `ms` in
/// strictly decreasing unit order, plus `"0"`).
pub fn parse_prometheus_duration(s: &str) -> Result<u64, String> {
    if s == "0" {
        return Ok(0);
    }
    if s.is_empty() {
        return Err("empty duration string".to_owned());
    }

    const MS_NS: u64 = 1_000_000;
    const SEC_NS: u64 = 1_000 * MS_NS;
    const MIN_NS: u64 = 60 * SEC_NS;
    const HOUR_NS: u64 = 60 * MIN_NS;
    const DAY_NS: u64 = 24 * HOUR_NS;
    const WEEK_NS: u64 = 7 * DAY_NS;
    const YEAR_NS: u64 = 365 * DAY_NS;
    const MAX_DURATION_NS: u64 = i64::MAX as u64;

    let orig = s;
    let mut rest = s;
    let mut total_ns = 0u64;
    let mut last_unit_pos = 0u8;

    while !rest.is_empty() {
        let digit_len = rest.bytes().take_while(|b| b.is_ascii_digit()).count();
        if digit_len == 0 {
            return Err(format!("not a valid duration string: {orig:?}"));
        }
        let val: u64 = rest[..digit_len]
            .parse()
            .map_err(|_| format!("not a valid duration string: {orig:?}"))?;
        rest = &rest[digit_len..];

        let unit_len = rest.bytes().take_while(|b| !b.is_ascii_digit()).count();
        if unit_len == 0 {
            return Err(format!("not a valid duration string: {orig:?}"));
        }
        let unit = &rest[..unit_len];
        rest = &rest[unit_len..];

        let (pos, mult) = match unit {
            "y" => (1u8, YEAR_NS),
            "w" => (2, WEEK_NS),
            "d" => (3, DAY_NS),
            "h" => (4, HOUR_NS),
            "m" => (5, MIN_NS),
            "s" => (6, SEC_NS),
            "ms" => (7, MS_NS),
            _ => return Err(format!("unknown unit {unit:?} in duration {orig:?}")),
        };
        if pos <= last_unit_pos {
            return Err(format!("not a valid duration string: {orig:?}"));
        }
        last_unit_pos = pos;

        if val > (1u64 << 63) / mult {
            return Err("duration out of range".to_owned());
        }
        total_ns = total_ns
            .checked_add(val * mult)
            .filter(|&d| d <= MAX_DURATION_NS)
            .ok_or_else(|| "duration out of range".to_owned())?;
    }

    Ok(total_ns)
}

fn is_valid_go_bool(s: &str) -> bool {
    matches!(
        s,
        "1" | "t" | "T" | "true" | "TRUE" | "True" | "0" | "f" | "F" | "false" | "FALSE" | "False"
    )
}

/// Merges non-reserved target labels onto a scraped sample's `metric_labels` according to
/// Prometheus `honor_labels` semantics (`scrape/scrape.go`):
///
/// - Internal target labels starting with `"__"` are never copied onto samples.
/// - If `honor_labels` is `true`, existing sample labels take precedence over target labels.
/// - If `honor_labels` is `false`, conflicting sample labels are renamed to
///   `"exported_<label>"` (iteratively prefixing `"exported_"` if `"exported_<label>"` also
///   exists) before inserting the target label.
pub fn merge_target_and_metric_labels(
    metric_labels: &mut LabelSet,
    target_labels: &LabelSet,
    honor_labels: bool,
) {
    metric_labels.retain(|_, v| !v.is_empty());

    if honor_labels {
        for (tk, tv) in target_labels {
            if tk.starts_with(RESERVED_LABEL_PREFIX) || tv.is_empty() {
                continue;
            }
            if !metric_labels.contains_key(tk) {
                metric_labels.insert(tk.clone(), tv.clone());
            }
        }
        return;
    }

    let mut conflicting = Vec::new();
    for (tk, tv) in target_labels {
        if tk.starts_with(RESERVED_LABEL_PREFIX) || tv.is_empty() {
            continue;
        }
        if let Some(prev_val) = metric_labels.insert(tk.clone(), tv.clone()) {
            conflicting.push((tk.clone(), prev_val));
        }
    }

    if !conflicting.is_empty() {
        // Resolve shorter conflicting sample names (`foo`) before longer already-prefixed
        // names (`exported_foo`), matching Prometheus `resolveConflictingExposedLabels`.
        conflicting.sort_by_key(|(name, _)| name.len());
        for (mut name, val) in conflicting {
            name.insert_str(0, EXPORTED_LABEL_PREFIX);
            while metric_labels.contains_key(&name) {
                name.insert_str(0, EXPORTED_LABEL_PREFIX);
            }
            metric_labels.insert(name, val);
        }
    }
}

fn is_metric_name_pushdown_filter(cfg: &Config) -> bool {
    match cfg.action {
        Action::Keep | Action::Drop => cfg
            .source_labels
            .iter()
            .all(|label| label == METRIC_NAME_LABEL),
        Action::KeepEqual | Action::DropEqual => {
            cfg.target_label == METRIC_NAME_LABEL
                && cfg
                    .source_labels
                    .iter()
                    .all(|label| label == METRIC_NAME_LABEL)
        }
        _ => false,
    }
}

/// Splits `cfgs` into `(name_pushdown_prefix, remaining_cfgs)` for Stage 1 wire-series
/// `__name__` filtering in Layer 1 decoders.
///
/// `name_pushdown_prefix` is the longest leading prefix of rules that perform [`Action::Keep`],
/// [`Action::Drop`], [`Action::KeepEqual`], or [`Action::DropEqual`] exclusively over
/// [`METRIC_NAME_LABEL`] (`"__name__"`). Because those rules neither read non-`__name__` sample
/// labels nor mutate any label, callers can evaluate [`keep_metric_name`] once per contiguous
/// wire series-name transition (e.g. `foo_bucket`, `foo_count`) and skip float parsing, label
/// unescaping, string interning, and histogram/summary assembly whenever a series run is dropped.
#[must_use]
pub fn split_metric_name_pushdown(cfgs: &[Config]) -> (&[Config], &[Config]) {
    let prefix_len = cfgs
        .iter()
        .take_while(|cfg| is_metric_name_pushdown_filter(cfg))
        .count();
    cfgs.split_at(prefix_len)
}

/// Evaluates the leading `__name__`-only filter prefix returned by
/// [`split_metric_name_pushdown`] against `metric_name` with zero heap allocations in the standard
/// single-`__name__` case.
///
/// Returns `true` if `metric_name` passes all `__name__`-only filter rules in `cfgs`, or `false`
/// if a rule drops the metric family. Stops at the first rule in `cfgs` that is not a
/// `__name__`-only filter.
#[must_use]
pub fn keep_metric_name(metric_name: &str, cfgs: &[Config]) -> bool {
    let mut scratch = String::new();
    for cfg in cfgs {
        if !is_metric_name_pushdown_filter(cfg) {
            break;
        }
        let val: &str = match cfg.source_labels.len() {
            0 => "",
            1 => metric_name,
            _ => {
                scratch.clear();
                for idx in 0..cfg.source_labels.len() {
                    if idx > 0 {
                        scratch.push_str(&cfg.separator);
                    }
                    scratch.push_str(metric_name);
                }
                scratch.as_str()
            }
        };
        match cfg.action {
            Action::Drop => {
                if cfg.regex.is_match(val) {
                    return false;
                }
            }
            Action::Keep => {
                if !cfg.regex.is_match(val) {
                    return false;
                }
            }
            Action::DropEqual => {
                if val == metric_name {
                    return false;
                }
            }
            Action::KeepEqual => {
                if val != metric_name {
                    return false;
                }
            }
            _ => unreachable!(),
        }
    }
    true
}

/// Resolves `honor_labels = false` key collisions across a deduplicated key dictionary
/// `metric_keys` against `target_labels` in `O(unique_keys)` instead of per sample.
///
/// When `honor_labels` is `true`, or when no entry in `metric_keys` collides with a non-reserved,
/// non-empty label in `target_labels` (the common case), `renamed_keys` is cleared and `false` is
/// returned with zero heap allocations.
///
/// When `honor_labels` is `false` and at least one key in `metric_keys` collides with a public
/// target label, `renamed_keys` is resized to `metric_keys.len()`, populating
/// `Some(exported_name)` for each renamed dictionary entry (resolved in ascending key-length
/// order) and `None` for unchanged entries, and `true` is returned. Unlike Go
/// [`resolveConflictingExposedLabels`](https://github.com/prometheus/prometheus/blob/236a2b1fe8e0471586ff29cb8fd8929372643650/scrape/scrape.go#L682-L697)
/// (and per-sample [`merge_target_and_metric_labels`]), which check `exported_<name>` occupancy per
/// series, `resolve_conflicting_exposed_keys` intentionally treats any `exported_<name>` key
/// present in the batch-wide `metric_keys` dictionary as occupied across the batch so dictionary
/// key IDs remain uniform across series.
pub fn resolve_conflicting_exposed_keys<K: AsRef<str>>(
    metric_keys: &[K],
    target_labels: &LabelSet,
    honor_labels: bool,
    renamed_keys: &mut Vec<Option<String>>,
) -> bool {
    renamed_keys.clear();
    if honor_labels || metric_keys.is_empty() || target_labels.is_empty() {
        return false;
    }

    let is_public_target_key = |key: &str| -> bool {
        !key.starts_with(RESERVED_LABEL_PREFIX)
            && target_labels.get(key).is_some_and(|v| !v.is_empty())
    };

    if !metric_keys.iter().any(|k| is_public_target_key(k.as_ref())) {
        return false;
    }

    renamed_keys.resize(metric_keys.len(), None);
    let mut occupied: HashSet<String> = target_labels
        .iter()
        .filter(|(tk, tv)| !tk.starts_with(RESERVED_LABEL_PREFIX) && !tv.is_empty())
        .map(|(tk, _)| tk.clone())
        .collect();

    let mut conflicting: Vec<(usize, &str)> = Vec::new();
    for (idx, key) in metric_keys.iter().enumerate() {
        let key_str = key.as_ref();
        if is_public_target_key(key_str) {
            conflicting.push((idx, key_str));
        } else {
            occupied.insert(key_str.to_owned());
        }
    }

    // Resolve shorter conflicting sample names (`foo`) before longer already-prefixed
    // names (`exported_foo`), matching Prometheus `resolveConflictingExposedLabels`.
    conflicting.sort_by_key(|&(idx, name)| (name.len(), idx));
    for (idx, name) in conflicting {
        let mut candidate = String::with_capacity(EXPORTED_LABEL_PREFIX.len() + name.len());
        candidate.push_str(EXPORTED_LABEL_PREFIX);
        candidate.push_str(name);
        while occupied.contains(&candidate) {
            candidate.insert_str(0, EXPORTED_LABEL_PREFIX);
        }
        occupied.insert(candidate.clone());
        renamed_keys[idx] = Some(candidate);
    }

    true
}

/// Evaluates a [`Action::LabelDrop`] or [`Action::LabelKeep`] rule once per unique key in
/// `metric_keys`, writing per-key retention decisions into `keep_mask` (`true` to retain the key,
/// `false` to drop it) and returning the number of dropped keys.
///
/// Returns `None` if `cfg.action` is neither [`Action::LabelDrop`] nor [`Action::LabelKeep`].
pub fn eval_key_keep_mask<K: AsRef<str>>(
    metric_keys: &[K],
    cfg: &Config,
    keep_mask: &mut Vec<bool>,
) -> Option<usize> {
    if !matches!(cfg.action, Action::LabelDrop | Action::LabelKeep) {
        return None;
    }
    keep_mask.clear();
    keep_mask.reserve(metric_keys.len());
    let mut dropped = 0usize;
    for key in metric_keys {
        let keep = match cfg.action {
            Action::LabelDrop => !cfg.regex.is_match(key.as_ref()),
            Action::LabelKeep => cfg.regex.is_match(key.as_ref()),
            _ => unreachable!(),
        };
        if !keep {
            dropped += 1;
        }
        keep_mask.push(keep);
    }
    Some(dropped)
}

/// Summary of evaluating a single-source-label [`Action::Keep`] or [`Action::Drop`] rule across a
/// deduplicated value dictionary via [`eval_single_label_keep_mask`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SingleLabelFilterSummary {
    /// Whether a series that omits `source_labels[0]` (empty source value `""`) is kept.
    pub keep_when_absent: bool,
    /// Number of unique entries in `metric_values` that are kept (`keep_val_mask[val_id] == true`).
    pub kept_values: usize,
}

/// Evaluates a single-source-label (`source_labels.len() == 1`) [`Action::Keep`] or
/// [`Action::Drop`] rule once per unique value in `metric_values`, writing per-value keep
/// decisions into `keep_val_mask`.
///
/// Returns `None` if `cfg.source_labels.len() != 1` or `cfg.action` is neither [`Action::Keep`]
/// nor [`Action::Drop`].
pub fn eval_single_label_keep_mask<V: AsRef<str>>(
    metric_values: &[V],
    cfg: &Config,
    keep_val_mask: &mut Vec<bool>,
) -> Option<SingleLabelFilterSummary> {
    if cfg.source_labels.len() != 1 || !matches!(cfg.action, Action::Keep | Action::Drop) {
        return None;
    }
    let eval_keep = |val: &str| match cfg.action {
        Action::Keep => cfg.regex.is_match(val),
        Action::Drop => !cfg.regex.is_match(val),
        _ => unreachable!(),
    };

    let keep_when_absent = eval_keep("");
    keep_val_mask.clear();
    keep_val_mask.reserve(metric_values.len());
    let mut kept_values = 0usize;
    for val in metric_values {
        let keep = eval_keep(val.as_ref());
        if keep {
            kept_values += 1;
        }
        keep_val_mask.push(keep);
    }
    Some(SingleLabelFilterSummary {
        keep_when_absent,
        kept_values,
    })
}

/// Reusable on-demand memoization table for evaluating a single-source-label [`Action::Keep`] or
/// [`Action::Drop`] rule across a shared batch value dictionary (`val_interner`) without running
/// the regex on dictionary entries that only appear under other label keys or on already-dropped
/// series.
#[derive(Clone, Debug, Default)]
pub struct SingleLabelKeepCache {
    /// `0` = unvisited, `1` = drop, `2` = keep.
    states: Vec<u8>,
    keep_when_absent: bool,
}

impl SingleLabelKeepCache {
    /// Creates an empty [`SingleLabelKeepCache`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Resets the memoization table for `dict_len` dictionary values and `cfg`, reusing heap
    /// capacity across scrapes. Returns `false` if `cfg` is not a single-source-label
    /// [`Action::Keep`] or [`Action::Drop`] rule.
    pub fn prepare(&mut self, dict_len: usize, cfg: &Config) -> bool {
        if cfg.source_labels.len() != 1 || !matches!(cfg.action, Action::Keep | Action::Drop) {
            self.states.clear();
            return false;
        }
        self.keep_when_absent = match cfg.action {
            Action::Keep => cfg.regex.is_match(""),
            Action::Drop => !cfg.regex.is_match(""),
            _ => unreachable!(),
        };
        self.states.clear();
        self.states.resize(dict_len, 0);
        true
    }

    /// Returns whether a series that omits `cfg.source_labels[0]` (`""`) is kept.
    #[must_use]
    pub const fn keep_when_absent(&self) -> bool {
        self.keep_when_absent
    }

    /// Evaluates or returns the memoized keep decision for `metric_values[val_id]`.
    pub fn keep_value<V: AsRef<str>>(
        &mut self,
        val_id: usize,
        metric_values: &[V],
        cfg: &Config,
    ) -> bool {
        let cached = self.states[val_id];
        if cached != 0 {
            return cached == 2;
        }
        let val_str = metric_values[val_id].as_ref();
        let keep = match cfg.action {
            Action::Keep => cfg.regex.is_match(val_str),
            Action::Drop => !cfg.regex.is_match(val_str),
            _ => unreachable!(),
        };
        self.states[val_id] = if keep { 2 } else { 1 };
        keep
    }
}

/// Effect on `cfg.target_label` produced by a single-source-label value transformation rule for
/// one dictionary entry in [`eval_single_label_value_transform`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DictionaryValueTransform {
    /// `cfg.target_label` is left as-is on the series (either the regex did not match, the target
    /// label name is invalid under the active validation scheme, or an in-place transformation
    /// produced the same value as the input).
    KeepExisting,
    /// `cfg.target_label` must be removed from the series because the replacement expanded to
    /// `""`.
    DeleteTarget,
    /// `cfg.target_label` must be set to `&source_value[start..end]` without allocating a new
    /// `String` (produced when `replacement` selects a single capture group such as `"$1"`).
    SetTargetSlice {
        /// Inclusive start byte offset in the input dictionary value.
        start: usize,
        /// Exclusive end byte offset in the input dictionary value.
        end: usize,
    },
    /// `cfg.target_label` must be set to this synthesized non-empty string value.
    SetTarget(String),
}

impl DictionaryValueTransform {
    /// Resolves the replacement value against `source_value` (`""` when absent), returning
    /// `Some(value)` for [`Self::SetTargetSlice`] and [`Self::SetTarget`] or `None` for
    /// [`Self::KeepExisting`] and [`Self::DeleteTarget`].
    #[must_use]
    pub fn target_value<'a>(&'a self, source_value: &'a str) -> Option<&'a str> {
        match self {
            Self::KeepExisting | Self::DeleteTarget => None,
            Self::SetTargetSlice { start, end } => Some(&source_value[*start..*end]),
            Self::SetTarget(s) => Some(s.as_str()),
        }
    }
}

/// Evaluates a single-source-label (`source_labels.len() == 1`) value transformation rule
/// ([`Action::Replace`], [`Action::Lowercase`], [`Action::Uppercase`], or [`Action::HashMod`])
/// with a static `target_label` (`!target_label.contains('$')`) once per unique value in
/// `metric_values`.
///
/// Populates `transforms` with one [`DictionaryValueTransform`] per entry in `metric_values` and
/// returns `Some(when_absent)` describing the effect on `cfg.target_label` when a series omits
/// `source_labels[0]` (empty source value `""`). Returns `None` if `cfg` is not a
/// single-source-label static-target value transformation.
pub fn eval_single_label_value_transform<V: AsRef<str>>(
    metric_values: &[V],
    cfg: &Config,
    transforms: &mut Vec<DictionaryValueTransform>,
) -> Option<DictionaryValueTransform> {
    if cfg.source_labels.len() != 1
        || !matches!(
            cfg.action,
            Action::Replace | Action::Lowercase | Action::Uppercase | Action::HashMod
        )
        || var_in_regex_template(&cfg.target_label)
    {
        return None;
    }

    let in_place = cfg.target_label == cfg.source_labels[0];
    let target_valid = cfg
        .name_validation_scheme
        .is_valid_label_name(&cfg.target_label);
    let single_capture_group = (cfg.action == Action::Replace)
        .then(|| resolve_single_capture_replacement(&cfg.replacement, &cfg.regex))
        .flatten();
    let mut locs = (cfg.action == Action::Replace && target_valid)
        .then(|| cfg.regex.compiled.capture_locations());

    let mut eval_one = |val_str: &str, is_present: bool| -> DictionaryValueTransform {
        eval_value_transform_one(
            val_str,
            is_present,
            cfg,
            in_place,
            target_valid,
            single_capture_group,
            &mut locs,
        )
    };

    let when_absent = eval_one("", false);
    transforms.clear();
    transforms.reserve(metric_values.len());
    for val in metric_values {
        transforms.push(eval_one(val.as_ref(), true));
    }
    Some(when_absent)
}

/// Reusable on-demand memoization table for evaluating a single-source-label static-target value
/// transformation ([`Action::Replace`], [`Action::Lowercase`], [`Action::Uppercase`], or
/// [`Action::HashMod`]) only on dictionary `val_id`s actually referenced by `source_labels[0]` on
/// surviving series.
#[derive(Clone, Debug, Default)]
pub struct SingleLabelTransformCache {
    entries: Vec<Option<DictionaryValueTransform>>,
    when_absent: Option<DictionaryValueTransform>,
    locs: Option<CaptureLocations>,
    single_capture_group: Option<Option<usize>>,
    in_place: bool,
    target_valid: bool,
}

impl SingleLabelTransformCache {
    /// Creates an empty [`SingleLabelTransformCache`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Resets the memoization table for `dict_len` dictionary values and `cfg`, reusing heap
    /// capacity across scrapes. Returns `false` if `cfg` is not a single-source-label
    /// static-target value transformation.
    pub fn prepare(&mut self, dict_len: usize, cfg: &Config) -> bool {
        if cfg.source_labels.len() != 1
            || !matches!(
                cfg.action,
                Action::Replace | Action::Lowercase | Action::Uppercase | Action::HashMod
            )
            || var_in_regex_template(&cfg.target_label)
        {
            self.entries.clear();
            self.when_absent = None;
            return false;
        }

        self.in_place = cfg.target_label == cfg.source_labels[0];
        self.target_valid = cfg
            .name_validation_scheme
            .is_valid_label_name(&cfg.target_label);
        self.single_capture_group = (cfg.action == Action::Replace)
            .then(|| resolve_single_capture_replacement(&cfg.replacement, &cfg.regex))
            .flatten();
        self.locs = (cfg.action == Action::Replace && self.target_valid)
            .then(|| cfg.regex.compiled.capture_locations());
        self.when_absent = Some(eval_value_transform_one(
            "",
            false,
            cfg,
            self.in_place,
            self.target_valid,
            self.single_capture_group,
            &mut self.locs,
        ));
        self.entries.clear();
        self.entries.resize(dict_len, None);
        true
    }

    /// Returns the transformation applied when a series omits `cfg.source_labels[0]` (`""`).
    #[must_use]
    pub fn when_absent(&self) -> &DictionaryValueTransform {
        self.when_absent
            .as_ref()
            .expect("SingleLabelTransformCache::prepare must succeed before calling when_absent")
    }

    /// Evaluates or returns the memoized transformation for `metric_values[val_id]`.
    pub fn transform_value<V: AsRef<str>>(
        &mut self,
        val_id: usize,
        metric_values: &[V],
        cfg: &Config,
    ) -> &DictionaryValueTransform {
        if self.entries[val_id].is_none() {
            let val_str = metric_values[val_id].as_ref();
            let xform = eval_value_transform_one(
                val_str,
                true,
                cfg,
                self.in_place,
                self.target_valid,
                self.single_capture_group,
                &mut self.locs,
            );
            self.entries[val_id] = Some(xform);
        }
        self.entries[val_id].as_ref().unwrap()
    }
}

#[allow(clippy::too_many_arguments)]
fn eval_value_transform_one(
    val_str: &str,
    is_present: bool,
    cfg: &Config,
    in_place: bool,
    target_valid: bool,
    single_capture_group: Option<Option<usize>>,
    locs: &mut Option<CaptureLocations>,
) -> DictionaryValueTransform {
    if !target_valid {
        return DictionaryValueTransform::KeepExisting;
    }
    match cfg.action {
        Action::Replace => {
            if cfg.regex.is_default()
                && matches!(cfg.replacement.as_str(), "$1" | "${1}" | "$0" | "${0}")
            {
                return classify_slice_transform(0, val_str.len(), val_str, in_place, is_present);
            }
            if let Some(res) = direct_replacement(cfg, val_str) {
                return classify_value_transform(Cow::Borrowed(res), val_str, in_place, is_present);
            }
            let locs = locs.as_mut().expect("capture locations initialized");
            if cfg.regex.compiled.captures_read(locs, val_str).is_none() {
                return DictionaryValueTransform::KeepExisting;
            }
            if let Some(single_group) = single_capture_group {
                return match single_group.and_then(|idx| locs.get(idx)) {
                    Some((start, end)) => {
                        classify_slice_transform(start, end, val_str, in_place, is_present)
                    }
                    None => classify_slice_transform(0, 0, val_str, in_place, is_present),
                };
            }
            let res = expand_template(&cfg.replacement, val_str, locs, &cfg.regex.named_groups);
            classify_value_transform(res, val_str, in_place, is_present)
        }
        Action::Lowercase => {
            let lower = go_to_lowercase(val_str);
            classify_value_transform(lower, val_str, in_place, is_present)
        }
        Action::Uppercase => {
            let upper = go_to_uppercase(val_str);
            classify_value_transform(upper, val_str, in_place, is_present)
        }
        Action::HashMod => {
            if cfg.modulus == 0 {
                return DictionaryValueTransform::KeepExisting;
            }
            let modulo = hashmod_value(val_str, cfg.modulus);
            classify_value_transform(Cow::Owned(modulo), val_str, in_place, is_present)
        }
        _ => unreachable!(),
    }
}

/// If `replacement` consists of a single capture reference (`$1`, `${1}`, `$name`, `${name}`),
/// returns `Some(Some(group_idx))` when that capture group exists on `regex` or `Some(None)` when
/// the group does not exist (always expanding to `""`). Returns `None` for literal or multi-part
/// templates.
fn resolve_single_capture_replacement(replacement: &str, regex: &Regexp) -> Option<Option<usize>> {
    let after_dollar = replacement.strip_prefix('$')?;
    if after_dollar.starts_with('$') {
        return None;
    }
    let (name, num, remaining) = extract_template_var(after_dollar)?;
    if !remaining.is_empty() {
        return None;
    }
    let resolved = match num {
        Some(idx) if idx < regex.compiled.captures_len() => Some(idx),
        Some(_) => None,
        None => regex
            .named_groups
            .iter()
            .find(|(n, _)| n.as_ref() == name)
            .map(|&(_, idx)| idx),
    };
    Some(resolved)
}

fn classify_slice_transform(
    start: usize,
    end: usize,
    val_str: &str,
    in_place: bool,
    is_present: bool,
) -> DictionaryValueTransform {
    if start == end {
        if in_place && !is_present {
            DictionaryValueTransform::KeepExisting
        } else {
            DictionaryValueTransform::DeleteTarget
        }
    } else if in_place && is_present && start == 0 && end == val_str.len() {
        DictionaryValueTransform::KeepExisting
    } else {
        DictionaryValueTransform::SetTargetSlice { start, end }
    }
}

fn classify_value_transform(
    new_val: Cow<'_, str>,
    val_str: &str,
    in_place: bool,
    is_present: bool,
) -> DictionaryValueTransform {
    if new_val.is_empty() {
        if in_place && !is_present {
            DictionaryValueTransform::KeepExisting
        } else {
            DictionaryValueTransform::DeleteTarget
        }
    } else if in_place && is_present && new_val.as_ref() == val_str {
        DictionaryValueTransform::KeepExisting
    } else {
        DictionaryValueTransform::SetTarget(new_val.into_owned())
    }
}

/// Maps `s` to lowercase using Go `strings.ToLower` (`unicode.ToLower`) simple 1-to-1 per-rune
/// case mapping rather than Unicode `SpecialCasing` multi-character or context-sensitive rules.
fn go_to_lowercase(s: &str) -> Cow<'_, str> {
    if s.is_ascii() {
        if !s.bytes().any(|b| b.is_ascii_uppercase()) {
            return Cow::Borrowed(s);
        }
        return Cow::Owned(s.to_ascii_lowercase());
    }
    for (idx, ch) in s.char_indices() {
        let mapped = go_lowercase_char(ch);
        if mapped != ch {
            let mut out = String::with_capacity(s.len());
            out.push_str(&s[..idx]);
            out.push(mapped);
            for rest_ch in s[idx + ch.len_utf8()..].chars() {
                out.push(go_lowercase_char(rest_ch));
            }
            return Cow::Owned(out);
        }
    }
    Cow::Borrowed(s)
}

/// Maps `s` to uppercase using Go `strings.ToUpper` (`unicode.ToUpper`) simple 1-to-1 per-rune
/// case mapping (so `"straße"` maps to `"STRAßE"`, matching Prometheus).
fn go_to_uppercase(s: &str) -> Cow<'_, str> {
    if s.is_ascii() {
        if !s.bytes().any(|b| b.is_ascii_lowercase()) {
            return Cow::Borrowed(s);
        }
        return Cow::Owned(s.to_ascii_uppercase());
    }
    for (idx, ch) in s.char_indices() {
        let mapped = go_uppercase_char(ch);
        if mapped != ch {
            let mut out = String::with_capacity(s.len());
            out.push_str(&s[..idx]);
            out.push(mapped);
            for rest_ch in s[idx + ch.len_utf8()..].chars() {
                out.push(go_uppercase_char(rest_ch));
            }
            return Cow::Owned(out);
        }
    }
    Cow::Borrowed(s)
}

fn go_lowercase_char(ch: char) -> char {
    if ch.is_ascii() {
        return ch.to_ascii_lowercase();
    }
    if ch == '\u{0130}' {
        return 'i';
    }
    let mut it = ch.to_lowercase();
    let first = it.next().unwrap_or(ch);
    if it.next().is_none() { first } else { ch }
}

fn go_uppercase_char(ch: char) -> char {
    if ch.is_ascii() {
        return ch.to_ascii_uppercase();
    }
    match ch as u32 {
        cp @ (0x1F80..=0x1F87 | 0x1F90..=0x1F97 | 0x1FA0..=0x1FA7) => {
            char::from_u32(cp + 8).unwrap_or(ch)
        }
        0x1FB3 => '\u{1FBC}',
        0x1FC3 => '\u{1FCC}',
        0x1FF3 => '\u{1FFC}',
        _ => {
            let mut it = ch.to_uppercase();
            let first = it.next().unwrap_or(ch);
            if it.next().is_none() { first } else { ch }
        }
    }
}

/// Computes the Prometheus `hashmod` decimal string from the lower 64 big-endian bits of MD5.
fn hashmod_value(val: &str, modulus: u64) -> String {
    let digest = md5_sum(val.as_bytes());
    // Prometheus uses the last 8 bytes of the 16-byte MD5 digest as big-endian u64.
    let low = u64::from_be_bytes([
        digest[8], digest[9], digest[10], digest[11], digest[12], digest[13], digest[14],
        digest[15],
    ]);
    (low % modulus).to_string()
}

/// Pure-Rust RFC 1321 MD5 implementation used by [`Action::HashMod`].
fn md5_sum(input: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

    let mut state = [0x67452301u32, 0xefcdab89, 0x98badcfe, 0x10325476];

    let process_block = |state: &mut [u32; 4], chunk: &[u8; 64]| {
        let mut m = [0u32; 16];
        for (i, word) in m.iter_mut().enumerate() {
            let base = i * 4;
            *word = u32::from_le_bytes([
                chunk[base],
                chunk[base + 1],
                chunk[base + 2],
                chunk[base + 3],
            ]);
        }

        let [mut a, mut b, mut c, mut d] = *state;
        for i in 0..64 {
            let (f, g) = if i < 16 {
                ((b & c) | (!b & d), i)
            } else if i < 32 {
                ((d & b) | (!d & c), (5 * i + 1) % 16)
            } else if i < 48 {
                (b ^ c ^ d, (3 * i + 5) % 16)
            } else {
                (c ^ (b | !d), (7 * i) % 16)
            };
            let temp = d;
            d = c;
            c = b;
            let sum = a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g]);
            b = b.wrapping_add(sum.rotate_left(S[i]));
            a = temp;
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    };

    let (full_chunks, rem) = input.as_chunks::<64>();
    for chunk in full_chunks {
        process_block(&mut state, chunk);
    }

    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut tail = [0u8; 128];
    tail[..rem.len()].copy_from_slice(rem);
    tail[rem.len()] = 0x80;
    let tail_blocks = if rem.len() < 56 {
        tail[56..64].copy_from_slice(&bit_len.to_le_bytes());
        &tail[..64]
    } else {
        tail[120..128].copy_from_slice(&bit_len.to_le_bytes());
        &tail[..128]
    };
    for chunk in tail_blocks.as_chunks::<64>().0 {
        process_block(&mut state, chunk);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&state[0].to_le_bytes());
    out[4..8].copy_from_slice(&state[1].to_le_bytes());
    out[8..12].copy_from_slice(&state[2].to_le_bytes());
    out[12..16].copy_from_slice(&state[3].to_le_bytes());
    out
}
