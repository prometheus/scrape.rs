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

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::time::Duration;

#[cfg(feature = "arrow")]
use prometheus_expfmt::arrow::{DecodeBudget, DecodeOptions};
use prometheus_expfmt::format::EscapingScheme;
use prometheus_relabel::{
    ADDRESS_LABEL, Config as RelabelConfig, LabelSet, METRICS_PATH_LABEL, PARAM_LABEL_PREFIX,
    PopulatedTarget, SCHEME_LABEL, TargetPopulateConfig, ValidationScheme, populate_labels,
};

use crate::scrape::ScrapeError;

/// Default interval between scrapes of the same target (`15s`).
pub const DEFAULT_SCRAPE_INTERVAL: Duration = Duration::from_secs(15);

/// Default per-target HTTP scrape timeout (`10s`).
pub const DEFAULT_SCRAPE_TIMEOUT: Duration = Duration::from_secs(10);

/// Default maximum uncompressed HTTP response body size (`16 MiB`).
pub const DEFAULT_MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Default cap on `Vec<u8>` capacity retained in [`crate::scrape::BodyBufferPool`] (`4 MiB`).
pub const DEFAULT_MAX_RETAINED_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Default maximum data points per emitted Arrow chunk (`2,048`).
pub const DEFAULT_MAX_DATA_POINTS_PER_BATCH: usize = 2_048;

/// Default `User-Agent` header sent on scrape HTTP requests.
pub const DEFAULT_USER_AGENT: &str =
    concat!("prometheus-scrape-manager/", env!("CARGO_PKG_VERSION"));

const DEFAULT_CONCURRENT_IN_FLIGHT: usize = 8;
const DEFAULT_CONCURRENT_BUFFERED_BODIES: usize = 2;

/// Single HTTP endpoint and associated target labels scheduled by a scrape pool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScrapeTarget {
    url: reqwest::Url,
    labels: BTreeMap<String, String>,
}

impl ScrapeTarget {
    /// Creates a new [`ScrapeTarget`] for `url` with an empty target label set.
    #[must_use]
    pub const fn new(url: reqwest::Url) -> Self {
        Self {
            url,
            labels: BTreeMap::new(),
        }
    }

    /// Parses `raw_url` into a [`ScrapeTarget`].
    ///
    /// # Errors
    ///
    /// Returns [`ScrapeError::InvalidConfig`] if `raw_url` is not a valid HTTP or HTTPS URL.
    pub fn parse(raw_url: &str) -> Result<Self, ScrapeError> {
        let url = reqwest::Url::parse(raw_url).map_err(|err| {
            ScrapeError::InvalidConfig(format!("invalid scrape target URL {raw_url:?}: {err}"))
        })?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(ScrapeError::InvalidConfig(format!(
                "unsupported scrape target URL scheme {:?} in {raw_url:?}",
                url.scheme()
            )));
        }
        Ok(Self::new(url))
    }

    /// Constructs a [`ScrapeTarget`] from a relabeled [`PopulatedTarget`], resolving its HTTP URL
    /// from `__scheme__`, `__address__`, `__metrics_path__`, and any `__param_<name>` labels and
    /// attaching all non-reserved (`!__`) labels as [`ScrapeTarget::labels`].
    ///
    /// # Errors
    ///
    /// Returns [`ScrapeError::InvalidConfig`] if `__address__` is missing or the resulting URL is
    /// not a valid `http` or `https` endpoint.
    pub fn from_populated(populated: &PopulatedTarget) -> Result<Self, ScrapeError> {
        let scheme = populated
            .labels
            .get(SCHEME_LABEL)
            .map_or("http", String::as_str);
        let addr = populated
            .labels
            .get(ADDRESS_LABEL)
            .map(String::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                ScrapeError::InvalidConfig("populated target missing __address__".to_owned())
            })?;
        let raw_path = populated
            .labels
            .get(METRICS_PATH_LABEL)
            .map_or("/metrics", String::as_str);
        let base_url = if raw_path.starts_with('/') {
            format!("{scheme}://{addr}{raw_path}")
        } else {
            format!("{scheme}://{addr}/{raw_path}")
        };

        let mut target = Self::parse(&base_url)?;
        let mut has_params = false;
        for (k, v) in &populated.labels {
            if let Some(param_name) = k.strip_prefix(PARAM_LABEL_PREFIX)
                && !param_name.is_empty()
                && !v.is_empty()
            {
                if !has_params {
                    has_params = true;
                }
                target
                    .url
                    .query_pairs_mut()
                    .append_pair(param_name, v.as_str());
            }
        }
        let _ = has_params;
        target.labels = populated.public_labels();
        Ok(target)
    }

    /// Inserts or replaces a target metadata label (such as `instance` or `job`).
    #[must_use]
    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }

    /// Inserts all `(key, value)` pairs into the target's label set.
    #[must_use]
    pub fn with_labels<I, K, V>(mut self, iter: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        for (k, v) in iter {
            self.labels.insert(k.into(), v.into());
        }
        self
    }

    /// Returns the scrape endpoint URL.
    #[must_use]
    pub const fn url(&self) -> &reqwest::Url {
        &self.url
    }

    /// Returns the sorted target label map.
    #[must_use]
    pub const fn labels(&self) -> &BTreeMap<String, String> {
        &self.labels
    }
}

/// Cadence policy when [`SchedulingMode::Sequential`] is selected.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SequentialSchedule {
    /// Runs all configured targets back-to-back on a single job-wide interval tick.
    ///
    /// Reproduces the prototype single-loop cadence where one timer wakes every `scrape_interval`
    /// and iterates targets sequentially.
    #[default]
    CycleTick,
    /// Schedules each target at its deterministic `hash(target) % scrape_interval` offset and
    /// executes due targets one at a time in due-timestamp order.
    Jittered,
}

/// Target scheduling and concurrency strategy for a scrape pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchedulingMode {
    /// Executes at most one scrape at a time using one reusable HTTP body buffer and one decoder.
    Sequential {
        /// Cadence policy for sequential target execution.
        schedule: SequentialSchedule,
    },
    /// Schedules each target on an independent deterministic jittered timer while bounding
    /// in-flight HTTP requests, buffered response bodies, and pooled decoders separately.
    Concurrent {
        /// Maximum concurrent in-flight HTTP scrape requests (`>= 1`).
        max_in_flight: NonZeroUsize,
        /// Maximum HTTP response bodies buffered in memory simultaneously (`1..=max_in_flight`).
        max_buffered_bodies: NonZeroUsize,
        /// Maximum reusable decoders pooled simultaneously (`1..=max_in_flight`).
        max_decoders: NonZeroUsize,
    },
}

impl Default for SchedulingMode {
    fn default() -> Self {
        Self::concurrent(
            NonZeroUsize::new(DEFAULT_CONCURRENT_IN_FLIGHT).expect("non-zero constant"),
        )
    }
}

impl SchedulingMode {
    /// Sequential cycle-tick mode: scrapes all targets one after another on each interval tick.
    #[must_use]
    pub const fn sequential() -> Self {
        Self::Sequential {
            schedule: SequentialSchedule::CycleTick,
        }
    }

    /// Sequential jittered mode: schedules per-target deterministic offsets while executing at
    /// most one scrape at a time.
    #[must_use]
    pub const fn sequential_jittered() -> Self {
        Self::Sequential {
            schedule: SequentialSchedule::Jittered,
        }
    }

    /// Concurrent jittered mode with `max_in_flight` HTTP concurrency, at most `2` (clamped to
    /// `max_in_flight`) concurrent buffered bodies, and `1` shared reusable decoder.
    #[must_use]
    pub fn concurrent(max_in_flight: NonZeroUsize) -> Self {
        let body_cap = max_in_flight.get().min(DEFAULT_CONCURRENT_BUFFERED_BODIES);
        let max_buffered_bodies = NonZeroUsize::new(body_cap).expect("min of >=1 and 2 is >=1");
        let max_decoders = NonZeroUsize::new(1).expect("non-zero constant");
        Self::Concurrent {
            max_in_flight,
            max_buffered_bodies,
            max_decoders,
        }
    }

    /// Concurrent jittered mode with explicit caps on in-flight HTTP requests, buffered response
    /// bodies, and pooled decoders.
    #[must_use]
    pub const fn concurrent_with_pools(
        max_in_flight: NonZeroUsize,
        max_buffered_bodies: NonZeroUsize,
        max_decoders: NonZeroUsize,
    ) -> Self {
        Self::Concurrent {
            max_in_flight,
            max_buffered_bodies,
            max_decoders,
        }
    }

    /// Returns the maximum number of HTTP requests allowed in flight simultaneously.
    #[must_use]
    pub const fn max_in_flight(&self) -> NonZeroUsize {
        match *self {
            Self::Sequential { .. } => NonZeroUsize::MIN,
            Self::Concurrent { max_in_flight, .. } => max_in_flight,
        }
    }

    /// Returns the maximum number of response body buffers leased simultaneously.
    #[must_use]
    pub const fn max_buffered_bodies(&self) -> NonZeroUsize {
        match *self {
            Self::Sequential { .. } => NonZeroUsize::MIN,
            Self::Concurrent {
                max_in_flight,
                max_buffered_bodies,
                ..
            } => {
                if max_buffered_bodies.get() > max_in_flight.get() {
                    max_in_flight
                } else {
                    max_buffered_bodies
                }
            }
        }
    }

    /// Returns the maximum number of decoders pooled simultaneously.
    #[must_use]
    pub const fn max_decoders(&self) -> NonZeroUsize {
        match *self {
            Self::Sequential { .. } => NonZeroUsize::MIN,
            Self::Concurrent {
                max_in_flight,
                max_decoders,
                ..
            } => {
                if max_decoders.get() > max_in_flight.get() {
                    max_in_flight
                } else {
                    max_decoders
                }
            }
        }
    }
}

/// Configuration for [`crate::scrape::ReqwestFetcher`] and scrape pool scheduling.
#[derive(Clone, Debug)]
pub struct ScrapeConfig {
    /// Logical Prometheus `job` name associated with this scrape pool.
    pub job_name: String,
    /// Target scrape cadence (`> 0`).
    pub scrape_interval: Duration,
    /// Per-scrape HTTP + body read timeout (`0 < scrape_timeout <= scrape_interval`).
    pub scrape_timeout: Duration,
    /// Optional startup delay applied before the first scrape cycle.
    pub initial_delay: Duration,
    /// Seed mixed into deterministic per-target FNV-1a offset hashing.
    pub jitter_seed: u64,
    /// Sequential vs bounded-concurrent scheduling policy.
    pub scheduling: SchedulingMode,
    /// Advertise `application/openmetrics-text` in the `Accept` header when `true`.
    pub enable_open_metrics: bool,
    /// UTF-8 metric/label name escaping scheme advertised in `Accept`.
    pub escaping_scheme: EscapingScheme,
    /// Negotiate and transparently decompress `Content-Encoding: gzip` responses when `true`.
    pub enable_compression: bool,
    /// Preserve explicit sample timestamps when `true`; override with scrape time when `false`.
    pub honor_timestamps: bool,
    /// Preserve sample labels that collide with target labels when `true`; prefix conflicting
    /// sample labels with `exported_` when `false`.
    pub honor_labels: bool,
    /// Target relabeling rules applied by [`ScrapeConfig::populate_target`].
    pub relabel_configs: Vec<RelabelConfig>,
    /// Per-scrape sample relabeling rules applied after decoding.
    pub metric_relabel_configs: Vec<RelabelConfig>,
    /// Maximum uncompressed HTTP response body size in bytes (`0` disables the limit).
    pub max_body_bytes: usize,
    /// Maximum capacity in bytes retained per idle `Vec<u8>` in [`crate::scrape::BodyBufferPool`].
    pub max_retained_body_bytes: usize,
    /// Maximum data points emitted per decoded Arrow chunk (`0` decodes each scrape as one batch).
    pub max_data_points_per_batch: usize,
    /// `User-Agent` header value sent on HTTP scrape requests.
    pub user_agent: String,
    /// Track per-target active series across scrapes and emit `FLAG_NO_RECORDED_VALUE` markers
    /// when series disappear, a target scrape fails, or a target is removed.
    #[cfg(feature = "arrow")]
    pub track_staleness: bool,
    /// Cooperative per-step parsing budget when the `arrow` feature is enabled.
    #[cfg(feature = "arrow")]
    pub decode_budget: DecodeBudget,
    /// Base `ArrowDecoder` translation options when the `arrow` feature is enabled.
    #[cfg(feature = "arrow")]
    pub decode_options: DecodeOptions,
}

impl Default for ScrapeConfig {
    fn default() -> Self {
        Self {
            job_name: "default".to_owned(),
            scrape_interval: DEFAULT_SCRAPE_INTERVAL,
            scrape_timeout: DEFAULT_SCRAPE_TIMEOUT,
            initial_delay: Duration::ZERO,
            jitter_seed: 0,
            scheduling: SchedulingMode::default(),
            enable_open_metrics: true,
            escaping_scheme: EscapingScheme::default(),
            enable_compression: true,
            honor_timestamps: true,
            honor_labels: false,
            relabel_configs: Vec::new(),
            metric_relabel_configs: Vec::new(),
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            max_retained_body_bytes: DEFAULT_MAX_RETAINED_BODY_BYTES,
            max_data_points_per_batch: DEFAULT_MAX_DATA_POINTS_PER_BATCH,
            user_agent: DEFAULT_USER_AGENT.to_owned(),
            #[cfg(feature = "arrow")]
            track_staleness: false,
            #[cfg(feature = "arrow")]
            decode_budget: DecodeBudget::default(),
            #[cfg(feature = "arrow")]
            decode_options: DecodeOptions::new(),
        }
    }
}

impl ScrapeConfig {
    /// Creates a [`ScrapeConfig`] for `job_name` with default intervals and concurrent scheduling.
    #[must_use]
    pub fn new(job_name: impl Into<String>) -> Self {
        Self {
            job_name: job_name.into(),
            ..Self::default()
        }
    }

    /// Sets [`ScrapeConfig::scrape_interval`].
    #[must_use]
    pub const fn with_scrape_interval(mut self, interval: Duration) -> Self {
        self.scrape_interval = interval;
        self
    }

    /// Sets [`ScrapeConfig::scrape_timeout`].
    #[must_use]
    pub const fn with_scrape_timeout(mut self, timeout: Duration) -> Self {
        self.scrape_timeout = timeout;
        self
    }

    /// Sets [`ScrapeConfig::initial_delay`].
    #[must_use]
    pub const fn with_initial_delay(mut self, delay: Duration) -> Self {
        self.initial_delay = delay;
        self
    }

    /// Sets [`ScrapeConfig::jitter_seed`].
    #[must_use]
    pub const fn with_jitter_seed(mut self, seed: u64) -> Self {
        self.jitter_seed = seed;
        self
    }

    /// Sets [`ScrapeConfig::scheduling`].
    #[must_use]
    pub const fn with_scheduling(mut self, scheduling: SchedulingMode) -> Self {
        self.scheduling = scheduling;
        self
    }

    /// Sets [`ScrapeConfig::enable_open_metrics`].
    #[must_use]
    pub const fn with_enable_open_metrics(mut self, enable: bool) -> Self {
        self.enable_open_metrics = enable;
        self
    }

    /// Sets [`ScrapeConfig::escaping_scheme`].
    #[must_use]
    pub const fn with_escaping_scheme(mut self, scheme: EscapingScheme) -> Self {
        self.escaping_scheme = scheme;
        self
    }

    /// Sets [`ScrapeConfig::enable_compression`].
    #[must_use]
    pub const fn with_enable_compression(mut self, enable: bool) -> Self {
        self.enable_compression = enable;
        self
    }

    /// Sets [`ScrapeConfig::max_body_bytes`].
    #[must_use]
    pub const fn with_max_body_bytes(mut self, max_bytes: usize) -> Self {
        self.max_body_bytes = max_bytes;
        self
    }

    /// Sets [`ScrapeConfig::max_retained_body_bytes`].
    #[must_use]
    pub const fn with_max_retained_body_bytes(mut self, max_bytes: usize) -> Self {
        self.max_retained_body_bytes = max_bytes;
        self
    }

    /// Sets [`ScrapeConfig::max_data_points_per_batch`].
    #[must_use]
    pub const fn with_max_data_points_per_batch(mut self, max_points: usize) -> Self {
        self.max_data_points_per_batch = max_points;
        self
    }

    /// Sets [`ScrapeConfig::honor_labels`].
    #[must_use]
    pub const fn with_honor_labels(mut self, honor: bool) -> Self {
        self.honor_labels = honor;
        self
    }

    /// Sets [`ScrapeConfig::relabel_configs`].
    #[must_use]
    pub fn with_relabel_configs(mut self, configs: Vec<RelabelConfig>) -> Self {
        self.relabel_configs = configs;
        self
    }

    /// Sets [`ScrapeConfig::metric_relabel_configs`].
    #[must_use]
    pub fn with_metric_relabel_configs(mut self, configs: Vec<RelabelConfig>) -> Self {
        self.metric_relabel_configs = configs;
        self
    }

    /// Sets [`ScrapeConfig::track_staleness`].
    #[cfg(feature = "arrow")]
    #[must_use]
    pub const fn with_track_staleness(mut self, enable: bool) -> Self {
        self.track_staleness = enable;
        self
    }

    /// Sets [`ScrapeConfig::decode_budget`].
    #[cfg(feature = "arrow")]
    #[must_use]
    pub const fn with_decode_budget(mut self, budget: DecodeBudget) -> Self {
        self.decode_budget = budget;
        self
    }

    /// Populates discovered target labels, runs [`ScrapeConfig::relabel_configs`], and resolves the
    /// resulting [`ScrapeTarget`] URL and public labels (`Ok(None)` if dropped by relabeling).
    ///
    /// # Errors
    ///
    /// Returns [`ScrapeError::InvalidConfig`] if target relabeling or URL resolution fails.
    pub fn populate_target(
        &self,
        raw_labels: &LabelSet,
        group_labels: &LabelSet,
    ) -> Result<Option<ScrapeTarget>, ScrapeError> {
        let populate_cfg = TargetPopulateConfig {
            job_name: self.job_name.clone(),
            scrape_interval: format_prometheus_duration(self.scrape_interval),
            scrape_timeout: format_prometheus_duration(self.scrape_timeout),
            ..TargetPopulateConfig::default()
        };
        let Some(populated) = populate_labels(
            raw_labels,
            group_labels,
            &populate_cfg,
            &self.relabel_configs,
        )
        .map_err(|err| ScrapeError::InvalidConfig(err.to_string()))?
        else {
            return Ok(None);
        };
        ScrapeTarget::from_populated(&populated).map(Some)
    }

    pub(crate) fn normalize_relabel_configs(&mut self) -> Result<(), ScrapeError> {
        for (idx, cfg) in self.relabel_configs.iter_mut().enumerate() {
            cfg.validate(ValidationScheme::Utf8).map_err(|err| {
                ScrapeError::InvalidConfig(format!("relabel_configs[{idx}]: {err}"))
            })?;
        }
        for (idx, cfg) in self.metric_relabel_configs.iter_mut().enumerate() {
            cfg.validate(ValidationScheme::Utf8).map_err(|err| {
                ScrapeError::InvalidConfig(format!("metric_relabel_configs[{idx}]: {err}"))
            })?;
        }
        Ok(())
    }

    /// Validates interval, timeout, pool, and relabel rule invariants.
    ///
    /// # Errors
    ///
    /// Returns [`ScrapeError::InvalidConfig`] if `job_name` is empty, `scrape_interval` or
    /// `scrape_timeout` is zero, `scrape_timeout > scrape_interval`, a concurrent pool size
    /// exceeds `max_in_flight`, or any relabel rule is invalid.
    pub fn validate(&self) -> Result<(), ScrapeError> {
        if self.job_name.trim().is_empty() {
            return Err(ScrapeError::InvalidConfig(
                "job_name must not be empty".to_owned(),
            ));
        }
        if self.scrape_interval.is_zero() {
            return Err(ScrapeError::InvalidConfig(
                "scrape_interval must be greater than zero".to_owned(),
            ));
        }
        if self.scrape_timeout.is_zero() {
            return Err(ScrapeError::InvalidConfig(
                "scrape_timeout must be greater than zero".to_owned(),
            ));
        }
        if self.scrape_timeout > self.scrape_interval {
            return Err(ScrapeError::InvalidConfig(format!(
                "scrape_timeout ({:?}) must not exceed scrape_interval ({:?})",
                self.scrape_timeout, self.scrape_interval
            )));
        }
        if let SchedulingMode::Concurrent {
            max_in_flight,
            max_buffered_bodies,
            max_decoders,
        } = self.scheduling
        {
            if max_buffered_bodies > max_in_flight {
                return Err(ScrapeError::InvalidConfig(format!(
                    "max_buffered_bodies ({max_buffered_bodies}) must not exceed max_in_flight ({max_in_flight})"
                )));
            }
            if max_decoders > max_in_flight {
                return Err(ScrapeError::InvalidConfig(format!(
                    "max_decoders ({max_decoders}) must not exceed max_in_flight ({max_in_flight})"
                )));
            }
        }
        for (idx, cfg) in self.relabel_configs.iter().enumerate() {
            let mut copy = cfg.clone();
            copy.validate(ValidationScheme::Utf8).map_err(|err| {
                ScrapeError::InvalidConfig(format!("relabel_configs[{idx}]: {err}"))
            })?;
        }
        for (idx, cfg) in self.metric_relabel_configs.iter().enumerate() {
            let mut copy = cfg.clone();
            copy.validate(ValidationScheme::Utf8).map_err(|err| {
                ScrapeError::InvalidConfig(format!("metric_relabel_configs[{idx}]: {err}"))
            })?;
        }
        Ok(())
    }

    /// Effective uncompressed response body byte limit (`usize::MAX` when `max_body_bytes == 0`).
    #[must_use]
    pub const fn effective_max_body_bytes(&self) -> usize {
        if self.max_body_bytes == 0 {
            usize::MAX
        } else {
            self.max_body_bytes
        }
    }
}

/// Formats `duration` using Prometheus duration units (`s`, `ms`) accepted by
/// `prometheus_relabel::populate_labels`, clamping sub-millisecond positive values up to `1ms`.
pub(crate) fn format_prometheus_duration(duration: Duration) -> String {
    if duration.is_zero() {
        return "0".to_owned();
    }
    let total_ms = duration.as_millis().max(1);
    let secs = total_ms / 1_000;
    let rem_ms = total_ms % 1_000;
    if secs > 0 && rem_ms == 0 {
        format!("{secs}s")
    } else if secs > 0 {
        format!("{secs}s{rem_ms}ms")
    } else {
        format!("{rem_ms}ms")
    }
}
