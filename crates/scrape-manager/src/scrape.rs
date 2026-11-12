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
//! [`ScrapeManager`] coordinates periodic target scraping in two user-selectable modes via
//! [`SchedulingMode`]:
//! - [`SchedulingMode::Sequential`]: scrapes one target at a time with a single reusable HTTP body
//!   buffer and a single decoder, using either a job-wide tick ([`SequentialSchedule::CycleTick`])
//!   or deterministic per-target FNV-1a phase offsets ([`SequentialSchedule::Jittered`]).
//! - [`SchedulingMode::Concurrent`]: schedules every target on its own deterministic jittered
//!   interval (`hash(target) % scrape_interval`) while decoupling in-flight HTTP header concurrency
//!   (`max_in_flight`) from pooled response body buffers (`max_buffered_bodies`) and pooled
//!   decoders (`max_decoders`). Slow targets stalled on TCP connect or server-side metric
//!   generation neither delay sibling targets nor hold response payload buffers.

mod config;
mod http;
mod manager;
mod pool;
mod schedule;

pub use config::{
    DEFAULT_MAX_BODY_BYTES, DEFAULT_MAX_DATA_POINTS_PER_BATCH, DEFAULT_MAX_RETAINED_BODY_BYTES,
    DEFAULT_MAX_RETAINED_DECODER_BYTES, DEFAULT_SCRAPE_INTERVAL, DEFAULT_SCRAPE_TIMEOUT,
    DEFAULT_USER_AGENT, SchedulingMode, ScrapeConfig, ScrapeTarget, SequentialSchedule,
};
pub use http::{
    FetchedScrape, ReqwestFetcher, ScrapeError, TargetFetcher, build_accept_header,
    format_scrape_timeout_seconds, resolve_scrape_format,
};
#[cfg(feature = "arrow")]
pub use manager::ArrowScrapeSink;
pub use manager::{
    ManagerStats, RawScrapeSink, ScrapeCommand, ScrapeControl, ScrapeManager, ScrapeReport,
};
pub use pool::{BodyBufferPool, PooledBodyBuffer};
#[cfg(feature = "arrow")]
pub use pool::{DecoderPool, PooledDecoder};
pub use schedule::target_offset;
