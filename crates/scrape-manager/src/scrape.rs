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

//! Bounded-memory HTTP target scraping and interval scheduling.
//!
//! Provides reusable scratch pools ([`BodyBufferPool`] and, with the `arrow` feature enabled,
//! [`DecoderPool`]) and an HTTP target fetcher ([`ReqwestFetcher`]) that delays body buffer
//! acquisition until response headers arrive so slow targets waiting on network I/O do not hold
//! payload buffers.

mod config;
mod http;
mod pool;

pub use config::{
    DEFAULT_MAX_BODY_BYTES, DEFAULT_MAX_DATA_POINTS_PER_BATCH, DEFAULT_MAX_RETAINED_BODY_BYTES,
    DEFAULT_SCRAPE_INTERVAL, DEFAULT_SCRAPE_TIMEOUT, DEFAULT_USER_AGENT, SchedulingMode,
    ScrapeConfig, ScrapeTarget, SequentialSchedule,
};
pub use http::{
    FetchedScrape, ReqwestFetcher, ScrapeError, TargetFetcher, build_accept_header,
    format_scrape_timeout_seconds, resolve_scrape_format,
};
pub use pool::{BodyBufferPool, PooledBodyBuffer};

#[cfg(feature = "arrow")]
pub use pool::{DecoderPool, PooledDecoder};
