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
use prometheus_expfmt::arrow::{DecodeBudget, DecodeOptions, TargetAttributes};
use prometheus_expfmt::format::EscapingScheme;
use prometheus_relabel::{
    ADDRESS_LABEL, Config as RelabelConfig, METRICS_PATH_LABEL, PARAM_LABEL_PREFIX,
    PopulatedTarget, SCHEME_LABEL, TargetPopulateConfig, ValidationScheme, populate_labels,
};

use crate::discovery::{TargetGroup, format_duration};
use crate::scrape::ScrapeError;

/// Default interval between scrapes of the same target (`15s`).
pub const DEFAULT_SCRAPE_INTERVAL: Duration = Duration::from_secs(15);

/// Default per-target HTTP scrape timeout (`10s`).
pub const DEFAULT_SCRAPE_TIMEOUT: Duration = Duration::from_secs(10);

/// Default HTTP request path scraped on each target (`"/metrics"`).
pub const DEFAULT_METRICS_PATH: &str = "/metrics";

/// Default URL scheme scraped on each target (`"http"`).
pub const DEFAULT_SCHEME: &str = "http";

/// Default maximum uncompressed HTTP response body size (`16 MiB`).
pub const DEFAULT_MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Default cap on `Vec<u8>` capacity retained in [`crate::scrape::BodyBufferPool`] (`4 MiB`).
pub const DEFAULT_MAX_RETAINED_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Default cap on scratch capacity retained per idle decoder in [`crate::scrape::DecoderPool`] (`4 MiB`).
pub const DEFAULT_MAX_RETAINED_DECODER_BYTES: usize = 4 * 1024 * 1024;

/// Default maximum data points per emitted Arrow chunk (`2,048`).
pub const DEFAULT_MAX_DATA_POINTS_PER_BATCH: usize = 2_048;

/// Default `User-Agent` header sent on scrape HTTP requests.
pub const DEFAULT_USER_AGENT: &str =
    concat!("prometheus-scrape-manager/", env!("CARGO_PKG_VERSION"));

const DEFAULT_CONCURRENT_IN_FLIGHT: usize = 8;
const DEFAULT_CONCURRENT_BUFFERED_BODIES: usize = 2;
const MAX_SCHEDULE_DURATION: Duration = Duration::from_secs(365 * 24 * 60 * 60);

/// Single HTTP endpoint and associated target labels scheduled by a scrape pool.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

    /// Builds a [`ScrapeTarget`] from a relabeled [`PopulatedTarget`], constructing the scrape URL
    /// from `__scheme__`, `__address__`, `__metrics_path__`, and `__param_*` labels and storing
    /// only the public (non-`__`-prefixed) target labels.
    ///
    /// # Errors
    ///
    /// Returns [`ScrapeError::InvalidConfig`] if `__scheme__` is missing or not `http`/`https`,
    /// or if `__address__` cannot form a valid target URL.
    pub fn from_populated(populated: &PopulatedTarget) -> Result<Self, ScrapeError> {
        Self::from_populated_with_params(populated, &BTreeMap::new())
    }

    /// Builds a [`ScrapeTarget`] from a relabeled [`PopulatedTarget`] and optional base
    /// `scrape_config.params`, matching Prometheus `Target.URL()` query parameter merging
    /// (`__param_<name>` replaces the first value of `config_params[name]` while preserving any
    /// additional values).
    ///
    /// # Errors
    ///
    /// Returns [`ScrapeError::InvalidConfig`] if `__scheme__` is missing or not `http`/`https`,
    /// or if `__address__` cannot form a valid target URL.
    pub fn from_populated_with_params(
        populated: &PopulatedTarget,
        config_params: &BTreeMap<String, Vec<String>>,
    ) -> Result<Self, ScrapeError> {
        let scheme = populated
            .labels
            .get(SCHEME_LABEL)
            .map(String::as_str)
            .unwrap_or("");
        if !matches!(scheme, "http" | "https") {
            return Err(ScrapeError::InvalidConfig(format!(
                "unsupported scrape target scheme {scheme:?}"
            )));
        }

        let address = populated
            .labels
            .get(ADDRESS_LABEL)
            .map(String::as_str)
            .unwrap_or("");
        if address.is_empty() || address.contains('/') {
            return Err(ScrapeError::InvalidConfig(format!(
                "invalid scrape target address {address:?}"
            )));
        }

        let mut url = reqwest::Url::parse(&format!("{scheme}://{address}")).map_err(|err| {
            ScrapeError::InvalidConfig(format!(
                "invalid scrape target URL from scheme {scheme:?} and address {address:?}: {err}"
            ))
        })?;
        if url.host().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(ScrapeError::InvalidConfig(format!(
                "invalid scrape target address {address:?}"
            )));
        }

        if let Some(path) = populated.labels.get(METRICS_PATH_LABEL) {
            url.set_path(path);
        }

        let mut params = config_params.clone();
        for (key, value) in &populated.labels {
            let Some(param_name) = key.strip_prefix(PARAM_LABEL_PREFIX) else {
                continue;
            };
            if let Some(existing) = params.get_mut(param_name)
                && !existing.is_empty()
            {
                existing[0].clone_from(value);
            } else {
                params.insert(param_name.to_owned(), vec![value.clone()]);
            }
        }
        if !params.is_empty() {
            let mut pairs = url.query_pairs_mut();
            for (key, values) in &params {
                for value in values {
                    pairs.append_pair(key, value);
                }
            }
        }

        Ok(Self {
            url,
            labels: populated.public_labels(),
        })
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

    /// Builds OpenTelemetry [`TargetAttributes`] derived from [`Self::labels`], returning `None`
    /// when the target has no public non-empty labels.
    #[cfg(feature = "arrow")]
    #[must_use]
    pub fn to_target_attributes(&self) -> Option<TargetAttributes> {
        if self.labels.is_empty() {
            return None;
        }
        let attrs = TargetAttributes::from_target_labels(&self.labels);
        (!attrs.is_empty()).then_some(attrs)
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

    /// Concurrent jittered mode with `max_in_flight` HTTP concurrency and up to `2` (clamped to
    /// `max_in_flight`) concurrent buffered bodies and pooled decoders.
    #[must_use]
    pub fn concurrent(max_in_flight: NonZeroUsize) -> Self {
        let pool_cap = max_in_flight.get().min(DEFAULT_CONCURRENT_BUFFERED_BODIES);
        let max_buffered_bodies = NonZeroUsize::new(pool_cap).expect("min of >=1 and 2 is >=1");
        let max_decoders = max_buffered_bodies;
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
#[non_exhaustive]
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
    /// Maximum uncompressed HTTP response body size in bytes (`0` disables the limit).
    pub max_body_bytes: usize,
    /// Maximum capacity in bytes retained per idle `Vec<u8>` in [`crate::scrape::BodyBufferPool`].
    pub max_retained_body_bytes: usize,
    /// Maximum scratch capacity in bytes retained per idle decoder in [`crate::scrape::DecoderPool`]
    /// (`0` drops idle decoders after every scrape).
    pub max_retained_decoder_bytes: usize,
    /// Maximum data points emitted per decoded Arrow chunk (`0` decodes each scrape as one batch).
    pub max_data_points_per_batch: usize,
    /// `User-Agent` header value sent on HTTP scrape requests.
    pub user_agent: String,
    /// Default HTTP path populated into `__metrics_path__` during target discovery
    /// (defaults to `"/metrics"`).
    pub metrics_path: String,
    /// Default URL scheme populated into `__scheme__` during target discovery (`"http"` or
    /// `"https"`, defaults to `"http"`).
    pub scheme: String,
    /// Optional HTTP query parameters populated into `__param_<name>` and appended to target URLs.
    pub params: BTreeMap<String, Vec<String>>,
    /// Controls how exposed sample labels colliding with public target labels are resolved,
    /// matching Prometheus `scrape_config.honor_labels` (defaults to `false`).
    pub honor_labels: bool,
    /// Target discovery relabeling rules applied by [`ScrapeConfig::populate_targets`].
    pub relabel_configs: Vec<RelabelConfig>,
    /// Post-scrape metric relabeling rules compiled once into a `MetricRelabelPlan` by
    /// [`crate::scrape::ScrapeManager::new`] and executed in `ArrowDecoder`.
    pub metric_relabel_configs: Vec<RelabelConfig>,
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
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            max_retained_body_bytes: DEFAULT_MAX_RETAINED_BODY_BYTES,
            max_retained_decoder_bytes: DEFAULT_MAX_RETAINED_DECODER_BYTES,
            max_data_points_per_batch: DEFAULT_MAX_DATA_POINTS_PER_BATCH,
            user_agent: DEFAULT_USER_AGENT.to_owned(),
            metrics_path: DEFAULT_METRICS_PATH.to_owned(),
            scheme: DEFAULT_SCHEME.to_owned(),
            params: BTreeMap::new(),
            honor_labels: false,
            relabel_configs: Vec::new(),
            metric_relabel_configs: Vec::new(),
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

    /// Sets [`ScrapeConfig::max_retained_decoder_bytes`].
    #[must_use]
    pub const fn with_max_retained_decoder_bytes(mut self, max_bytes: usize) -> Self {
        self.max_retained_decoder_bytes = max_bytes;
        self
    }

    /// Sets [`ScrapeConfig::max_data_points_per_batch`].
    #[must_use]
    pub const fn with_max_data_points_per_batch(mut self, max_points: usize) -> Self {
        self.max_data_points_per_batch = max_points;
        self
    }

    /// Sets [`ScrapeConfig::user_agent`].
    #[must_use]
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = user_agent.into();
        self
    }

    /// Sets [`ScrapeConfig::metrics_path`].
    #[must_use]
    pub fn with_metrics_path(mut self, path: impl Into<String>) -> Self {
        self.metrics_path = path.into();
        self
    }

    /// Sets [`ScrapeConfig::scheme`].
    #[must_use]
    pub fn with_scheme(mut self, scheme: impl Into<String>) -> Self {
        self.scheme = scheme.into();
        self
    }

    /// Sets [`ScrapeConfig::params`].
    #[must_use]
    pub fn with_params(mut self, params: BTreeMap<String, Vec<String>>) -> Self {
        self.params = params;
        self
    }

    /// Inserts or replaces a single query parameter in [`ScrapeConfig::params`].
    #[must_use]
    pub fn with_param(mut self, key: impl Into<String>, values: Vec<String>) -> Self {
        self.params.insert(key.into(), values);
        self
    }

    /// Sets [`ScrapeConfig::honor_labels`].
    #[must_use]
    pub const fn with_honor_labels(mut self, honor_labels: bool) -> Self {
        self.honor_labels = honor_labels;
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

    /// Sets [`ScrapeConfig::decode_budget`].
    #[cfg(feature = "arrow")]
    #[must_use]
    pub const fn with_decode_budget(mut self, budget: DecodeBudget) -> Self {
        self.decode_budget = budget;
        self
    }

    /// Sets [`ScrapeConfig::decode_options`].
    #[cfg(feature = "arrow")]
    #[must_use]
    pub fn with_decode_options(mut self, options: DecodeOptions) -> Self {
        self.decode_options = options;
        self
    }

    /// Builds the [`TargetPopulateConfig`] used to seed pre-relabel target discovery labels.
    #[must_use]
    pub fn target_populate_config(&self) -> TargetPopulateConfig {
        TargetPopulateConfig {
            job_name: self.job_name.clone(),
            scrape_interval: format_duration(self.scrape_interval),
            scrape_timeout: format_duration(self.scrape_timeout),
            metrics_path: self.metrics_path.clone(),
            scheme: self.scheme.clone(),
            params: self.params.clone(),
        }
    }

    /// Populates and relabels all discovered targets across `groups` using
    /// [`Self::relabel_configs`], returning the kept [`ScrapeTarget`] endpoints ready for
    /// [`crate::scrape::ScrapeManager`].
    ///
    /// Targets dropped by [`Self::relabel_configs`] are omitted from the returned vector. Pool
    /// scheduling uses [`Self::scrape_interval`] and [`Self::scrape_timeout`].
    ///
    /// # Errors
    ///
    /// Returns [`ScrapeError::InvalidConfig`] if `self` fails validation, if `populate_labels`
    /// rejects a relabeled target (for example missing `__address__` or invalid
    /// `__scrape_interval__`/`__scrape_timeout__`), or if the relabeled target cannot form a
    /// valid HTTP/HTTPS URL.
    pub fn populate_targets(
        &self,
        groups: &[TargetGroup],
    ) -> Result<Vec<ScrapeTarget>, ScrapeError> {
        self.validate()?;
        let validated_relabel = validate_relabel_configs(&self.relabel_configs)?;
        let pop_cfg = self.target_populate_config();

        let mut out = Vec::new();
        for group in groups {
            for target_labels in &group.targets {
                let Some(populated) =
                    populate_labels(target_labels, &group.labels, &pop_cfg, &validated_relabel)
                        .map_err(|err| ScrapeError::InvalidConfig(err.to_string()))?
                else {
                    continue;
                };
                out.push(ScrapeTarget::from_populated_with_params(
                    &populated,
                    &self.params,
                )?);
            }
        }
        Ok(out)
    }

    /// Validates interval, timeout, scheme, relabel rules, and pool invariants.
    ///
    /// # Errors
    ///
    /// Returns [`ScrapeError::InvalidConfig`] if `job_name` is empty, `scrape_interval` or
    /// `scrape_timeout` is zero, `scrape_timeout > scrape_interval`, `scheme` is not `"http"` or
    /// `"https"`, any rule in `relabel_configs` or `metric_relabel_configs` is invalid, or a
    /// concurrent pool size exceeds `max_in_flight`.
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
        if self.scrape_interval > MAX_SCHEDULE_DURATION {
            return Err(ScrapeError::InvalidConfig(format!(
                "scrape_interval ({:?}) exceeds maximum ({MAX_SCHEDULE_DURATION:?})",
                self.scrape_interval
            )));
        }
        if self.initial_delay > MAX_SCHEDULE_DURATION {
            return Err(ScrapeError::InvalidConfig(format!(
                "initial_delay ({:?}) exceeds maximum ({MAX_SCHEDULE_DURATION:?})",
                self.initial_delay
            )));
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
        if !matches!(self.scheme.as_str(), "http" | "https") {
            return Err(ScrapeError::InvalidConfig(format!(
                "unsupported scrape scheme {:?} (expected \"http\" or \"https\")",
                self.scheme
            )));
        }
        if reqwest::header::HeaderValue::from_str(&self.user_agent).is_err() {
            return Err(ScrapeError::InvalidConfig(format!(
                "user_agent contains invalid HTTP header bytes: {:?}",
                self.user_agent
            )));
        }
        let _ = validate_relabel_configs(&self.relabel_configs)?;
        let _ = validate_relabel_configs(&self.metric_relabel_configs)?;
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

fn validate_relabel_configs(cfgs: &[RelabelConfig]) -> Result<Vec<RelabelConfig>, ScrapeError> {
    let mut validated = Vec::with_capacity(cfgs.len());
    for cfg in cfgs {
        let mut cloned = cfg.clone();
        cloned
            .validate(ValidationScheme::Utf8)
            .map_err(|err| ScrapeError::InvalidConfig(err.to_string()))?;
        validated.push(cloned);
    }
    Ok(validated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrape_target_parse_enforces_http_and_https_schemes() {
        let http = ScrapeTarget::parse("http://127.0.0.1:9090/metrics")
            .expect("http")
            .with_labels([("job", "prom"), ("env", "prod")]);
        assert_eq!(http.labels().len(), 2);

        let https = ScrapeTarget::parse("https://example.com/metrics").expect("https");
        assert_eq!(https.url().scheme(), "https");

        assert!(matches!(
            ScrapeTarget::parse("ftp://example.com/metrics"),
            Err(ScrapeError::InvalidConfig(_))
        ));
        assert!(matches!(
            ScrapeTarget::parse("not a url"),
            Err(ScrapeError::InvalidConfig(_))
        ));
    }

    #[test]
    fn scheduling_mode_and_config_validation_cover_edge_cases() {
        let one = NonZeroUsize::MIN;
        let two = NonZeroUsize::new(2).unwrap();
        let c1 = SchedulingMode::concurrent(one);
        assert_eq!(c1.max_in_flight(), one);
        assert_eq!(c1.max_buffered_bodies(), one);
        assert_eq!(c1.max_decoders(), one);

        let clamped = SchedulingMode::concurrent_with_pools(one, two, two);
        assert_eq!(clamped.max_buffered_bodies(), one);
        assert_eq!(clamped.max_decoders(), one);

        let unlimited = ScrapeConfig::new("job").with_max_body_bytes(0);
        assert_eq!(unlimited.effective_max_body_bytes(), usize::MAX);
        assert!(unlimited.validate().is_ok());

        let invalid_cases = [
            ScrapeConfig::new("   "),
            ScrapeConfig::new("job").with_scrape_interval(Duration::ZERO),
            ScrapeConfig::new("job")
                .with_scrape_interval(MAX_SCHEDULE_DURATION + Duration::from_secs(1)),
            ScrapeConfig::new("job")
                .with_initial_delay(MAX_SCHEDULE_DURATION + Duration::from_secs(1)),
            ScrapeConfig::new("job").with_scrape_timeout(Duration::ZERO),
            ScrapeConfig::new("job")
                .with_scrape_interval(Duration::from_secs(5))
                .with_scrape_timeout(Duration::from_secs(6)),
            ScrapeConfig::new("job").with_user_agent("bad\r\nheader"),
            ScrapeConfig::new("job").with_scheme("ftp"),
            ScrapeConfig::new("job").with_relabel_configs(vec![RelabelConfig {
                action: prometheus_relabel::Action::HashMod,
                target_label: "shard".to_owned(),
                modulus: 0,
                ..RelabelConfig::default()
            }]),
            ScrapeConfig::new("job").with_metric_relabel_configs(vec![RelabelConfig {
                action: prometheus_relabel::Action::Replace,
                target_label: String::new(),
                ..RelabelConfig::default()
            }]),
            ScrapeConfig::new("job")
                .with_scheduling(SchedulingMode::concurrent_with_pools(one, two, one)),
            ScrapeConfig::new("job")
                .with_scheduling(SchedulingMode::concurrent_with_pools(one, one, two)),
        ];
        for (idx, cfg) in invalid_cases.iter().enumerate() {
            assert!(
                matches!(cfg.validate(), Err(ScrapeError::InvalidConfig(_))),
                "case {idx} unexpectedly passed validate: {cfg:?}"
            );
        }
    }

    #[test]
    fn populate_targets_applies_relabel_configs_params_and_url_rules() {
        use crate::discovery::StaticConfig;
        use prometheus_relabel::{Action, Regexp};

        let group_a = StaticConfig {
            targets: vec![
                "10.0.0.1:9100".to_owned(),
                "10.0.0.2:9100".to_owned(),
                "[::1]:9443".to_owned(),
            ],
            labels: BTreeMap::from([
                ("env".to_owned(), "prod".to_owned()),
                ("__meta_role".to_owned(), "api".to_owned()),
            ]),
        }
        .into_target_group("0");

        let cfg = ScrapeConfig::new("api-pool")
            .with_metrics_path("/custom")
            .with_param("module", vec!["default".to_owned(), "extra".to_owned()])
            .with_relabel_configs(vec![
                // Drop 10.0.0.2.
                RelabelConfig {
                    source_labels: vec![ADDRESS_LABEL.to_owned()],
                    regex: Regexp::must_new("10\\.0\\.0\\.2:.*"),
                    action: Action::Drop,
                    ..RelabelConfig::default()
                },
                // Override the first `module` query parameter while keeping secondary values.
                RelabelConfig {
                    source_labels: vec!["__meta_role".to_owned()],
                    target_label: "__param_module".to_owned(),
                    replacement: "http_$1".to_owned(),
                    action: Action::Replace,
                    ..RelabelConfig::default()
                },
                // Add a new `__param_target` query parameter and promote `__meta_role` to `role`.
                RelabelConfig {
                    source_labels: vec![ADDRESS_LABEL.to_owned()],
                    target_label: "__param_target".to_owned(),
                    action: Action::Replace,
                    ..RelabelConfig::default()
                },
                RelabelConfig {
                    source_labels: vec!["__meta_role".to_owned()],
                    target_label: "role".to_owned(),
                    action: Action::Replace,
                    ..RelabelConfig::default()
                },
                // Switch IPv6 target to https and `/probe`.
                RelabelConfig {
                    source_labels: vec![ADDRESS_LABEL.to_owned()],
                    regex: Regexp::must_new("\\[::1\\]:.*"),
                    target_label: SCHEME_LABEL.to_owned(),
                    replacement: "https".to_owned(),
                    action: Action::Replace,
                    ..RelabelConfig::default()
                },
                RelabelConfig {
                    source_labels: vec![ADDRESS_LABEL.to_owned()],
                    regex: Regexp::must_new("\\[::1\\]:.*"),
                    target_label: METRICS_PATH_LABEL.to_owned(),
                    replacement: "/probe".to_owned(),
                    action: Action::Replace,
                    ..RelabelConfig::default()
                },
            ]);

        let targets = cfg.populate_targets(&[group_a]).expect("populate_targets");
        assert_eq!(targets.len(), 2);

        assert_eq!(
            targets[0].url().as_str(),
            "http://10.0.0.1:9100/custom?module=http_api&module=extra&target=10.0.0.1%3A9100"
        );
        assert_eq!(
            targets[0].labels(),
            &BTreeMap::from([
                ("env".to_owned(), "prod".to_owned()),
                ("instance".to_owned(), "10.0.0.1:9100".to_owned()),
                ("job".to_owned(), "api-pool".to_owned()),
                ("role".to_owned(), "api".to_owned()),
            ])
        );

        assert_eq!(
            targets[1].url().as_str(),
            "https://[::1]:9443/probe?module=http_api&module=extra&target=%5B%3A%3A1%5D%3A9443"
        );
        assert_eq!(
            targets[1].labels().get("instance").map(String::as_str),
            Some("[::1]:9443")
        );

        #[cfg(feature = "arrow")]
        {
            let ta = targets[0]
                .to_target_attributes()
                .expect("non-empty target attributes");
            assert_eq!(
                ta.resource_attributes()
                    .get("service.name")
                    .map(String::as_str),
                Some("api-pool")
            );
            assert_eq!(
                ta.resource_attributes()
                    .get("service.instance.id")
                    .map(String::as_str),
                Some("10.0.0.1:9100")
            );
            assert_eq!(
                ta.resource_attributes().get("env").map(String::as_str),
                Some("prod")
            );
            assert_eq!(
                ta.resource_attributes().get("role").map(String::as_str),
                Some("api")
            );
        }

        // Relabeling that clears `__address__` or injects URL userinfo/query fails cleanly.
        let bad_addr_group = StaticConfig {
            targets: vec!["user:pass@127.0.0.1:9100".to_owned()],
            labels: BTreeMap::new(),
        }
        .into_target_group("bad");
        assert!(matches!(
            ScrapeConfig::new("bad").populate_targets(&[bad_addr_group]),
            Err(ScrapeError::InvalidConfig(_))
        ));

        let strip_addr = ScrapeConfig::new("strip").with_relabel_configs(vec![RelabelConfig {
            target_label: ADDRESS_LABEL.to_owned(),
            replacement: String::new(),
            action: Action::Replace,
            ..RelabelConfig::default()
        }]);
        let g = StaticConfig {
            targets: vec!["127.0.0.1:9100".to_owned()],
            labels: BTreeMap::new(),
        }
        .into_target_group("0");
        assert!(matches!(
            strip_addr.populate_targets(&[g]),
            Err(ScrapeError::InvalidConfig(_))
        ));
    }
}
