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

//! Prometheus and OpenMetrics wire exposition format decoders.

#[cfg(feature = "arrow")]
pub mod arrow;
#[cfg(feature = "discovery")]
pub mod discovery;
#[cfg(feature = "dto")]
pub mod dto;
pub mod format;
// Layer 0 parsers remain crate-internal; `arrow` and `dto` expose the public decoding APIs.
#[allow(dead_code, unused_imports)]
pub(crate) mod parse;
