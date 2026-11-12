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

use std::num::NonZeroUsize;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

#[cfg(feature = "arrow")]
use prometheus_expfmt::arrow::ArrowDecoder;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::scrape::http::PooledGzipDecoder;

/// Bounded pool of reusable HTTP response body buffers.
///
/// Concurrent scrapes acquire a [`PooledBodyBuffer`] only after HTTP response headers arrive, and
/// return the cleared `Vec<u8>` on drop. Any buffer that grew past `max_retained_body_bytes` on an
/// outlier scrape shrinks back to `max_retained_body_bytes` before returning to the idle freelist.
#[derive(Clone, Debug)]
pub struct BodyBufferPool {
    inner: Arc<BodyPoolInner>,
}

#[derive(Debug)]
struct IdleBodySlot {
    buf: Vec<u8>,
    gzip: Option<Box<PooledGzipDecoder>>,
}

#[derive(Debug)]
struct BodyPoolInner {
    semaphore: Arc<Semaphore>,
    idle: Mutex<Vec<IdleBodySlot>>,
    max_retained_bytes: usize,
    active_leases: AtomicUsize,
    peak_leases: AtomicUsize,
    total_created: AtomicUsize,
}

impl BodyBufferPool {
    /// Creates a new [`BodyBufferPool`] allowing at most `max_buffers` concurrent leases and
    /// retaining at most `max_retained_bytes` per idle buffer (`0` retains nothing).
    #[must_use]
    pub fn new(max_buffers: NonZeroUsize, max_retained_bytes: usize) -> Self {
        let cap = max_buffers.get();
        Self {
            inner: Arc::new(BodyPoolInner {
                semaphore: Arc::new(Semaphore::new(cap)),
                idle: Mutex::new(Vec::with_capacity(cap)),
                max_retained_bytes,
                active_leases: AtomicUsize::new(0),
                peak_leases: AtomicUsize::new(0),
                total_created: AtomicUsize::new(0),
            }),
        }
    }

    /// Waits for a buffer permit and returns a cleared [`PooledBodyBuffer`], pre-reserving up to
    /// `capacity_hint` bytes when starting from a fresh allocation.
    pub async fn acquire(&self, capacity_hint: usize) -> PooledBodyBuffer {
        let permit = Arc::clone(&self.inner.semaphore)
            .acquire_owned()
            .await
            .expect("BodyBufferPool semaphore is never closed");

        let active = self.inner.active_leases.fetch_add(1, Ordering::Relaxed) + 1;
        self.inner.peak_leases.fetch_max(active, Ordering::Relaxed);

        let mut slot = {
            let mut idle = self
                .inner
                .idle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            idle.pop()
        }
        .unwrap_or_else(|| {
            self.inner.total_created.fetch_add(1, Ordering::Relaxed);
            IdleBodySlot {
                buf: Vec::new(),
                gzip: None,
            }
        });

        slot.buf.clear();
        let mut leased = PooledBodyBuffer {
            buf: slot.buf,
            gzip: slot.gzip,
            pool: Arc::clone(&self.inner),
            _permit: permit,
        };
        if capacity_hint > leased.buf.capacity() {
            leased.buf.reserve(capacity_hint - leased.buf.capacity());
        }
        leased
    }

    /// Number of buffers currently leased by active scrapes.
    #[must_use]
    pub fn active_leases(&self) -> usize {
        self.inner.active_leases.load(Ordering::Relaxed)
    }

    /// High-water mark of simultaneously leased body buffers since pool creation.
    #[must_use]
    pub fn peak_leases(&self) -> usize {
        self.inner.peak_leases.load(Ordering::Relaxed)
    }

    /// Total distinct `Vec<u8>` instances ever allocated by this pool (`<= max_buffers`).
    #[must_use]
    pub fn total_buffers_created(&self) -> usize {
        self.inner.total_created.load(Ordering::Relaxed)
    }

    /// Sum of `Vec::capacity()` across buffers currently parked in the idle freelist.
    #[must_use]
    pub fn retained_memory_bytes(&self) -> usize {
        let idle = self
            .inner
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        idle.iter().map(|slot| slot.buf.capacity()).sum()
    }
}

/// RAII lease over a reusable `Vec<u8>` from a [`BodyBufferPool`].
#[derive(Debug)]
pub struct PooledBodyBuffer {
    buf: Vec<u8>,
    gzip: Option<Box<PooledGzipDecoder>>,
    pool: Arc<BodyPoolInner>,
    // Field drop order guarantees `buf` is pushed back to `pool.idle` in `Drop` before `_permit`
    // releases its semaphore slot to a waiting task.
    _permit: OwnedSemaphorePermit,
}

impl PooledBodyBuffer {
    /// Returns the buffered response payload bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.buf.as_slice()
    }

    pub(crate) fn parts_mut(&mut self) -> (&mut Vec<u8>, &mut Option<Box<PooledGzipDecoder>>) {
        (&mut self.buf, &mut self.gzip)
    }
}

impl Deref for PooledBodyBuffer {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.buf
    }
}

impl DerefMut for PooledBodyBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buf
    }
}

impl AsRef<[u8]> for PooledBodyBuffer {
    fn as_ref(&self) -> &[u8] {
        self.buf.as_slice()
    }
}

impl Drop for PooledBodyBuffer {
    fn drop(&mut self) {
        let mut buf = std::mem::take(&mut self.buf);
        buf.clear();
        if buf.capacity() > self.pool.max_retained_bytes {
            buf.shrink_to(self.pool.max_retained_bytes);
        }
        let mut gzip = self.gzip.take();
        if self.pool.max_retained_bytes == 0 {
            gzip = None;
        } else if let Some(dec) = gzip.as_mut() {
            dec.shrink_retained(self.pool.max_retained_bytes);
        }
        self.pool.active_leases.fetch_sub(1, Ordering::Relaxed);
        let mut idle = self
            .pool
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        idle.push(IdleBodySlot { buf, gzip });
    }
}

/// Bounded pool of reusable [`ArrowDecoder`] instances.
#[cfg(feature = "arrow")]
#[derive(Clone, Debug)]
pub struct DecoderPool {
    inner: Arc<DecoderPoolInner>,
}

#[cfg(feature = "arrow")]
#[derive(Debug)]
struct DecoderPoolInner {
    semaphore: Arc<Semaphore>,
    idle: Mutex<Vec<ArrowDecoder>>,
    max_retained_bytes: usize,
    active_leases: AtomicUsize,
    peak_leases: AtomicUsize,
    total_created: AtomicUsize,
}

#[cfg(feature = "arrow")]
impl DecoderPool {
    /// Creates a new [`DecoderPool`] allowing at most `max_decoders` concurrent leases and
    /// retaining at most `max_retained_bytes` of scratch capacity per idle decoder (`0` retains
    /// no idle decoders).
    #[must_use]
    pub fn new(max_decoders: NonZeroUsize, max_retained_bytes: usize) -> Self {
        let cap = max_decoders.get();
        Self {
            inner: Arc::new(DecoderPoolInner {
                semaphore: Arc::new(Semaphore::new(cap)),
                idle: Mutex::new(Vec::with_capacity(cap)),
                max_retained_bytes,
                active_leases: AtomicUsize::new(0),
                peak_leases: AtomicUsize::new(0),
                total_created: AtomicUsize::new(0),
            }),
        }
    }

    /// Waits for a decoder permit and returns a reusable [`PooledDecoder`].
    pub async fn acquire(&self) -> PooledDecoder {
        let permit = Arc::clone(&self.inner.semaphore)
            .acquire_owned()
            .await
            .expect("DecoderPool semaphore is never closed");

        let active = self.inner.active_leases.fetch_add(1, Ordering::Relaxed) + 1;
        self.inner.peak_leases.fetch_max(active, Ordering::Relaxed);

        let decoder = {
            let mut idle = self
                .inner
                .idle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            idle.pop()
        }
        .unwrap_or_else(|| {
            self.inner.total_created.fetch_add(1, Ordering::Relaxed);
            ArrowDecoder::new()
        });

        PooledDecoder {
            decoder: Some(decoder),
            pool: Arc::clone(&self.inner),
            _permit: permit,
        }
    }

    /// High-water mark of simultaneously leased decoders since pool creation.
    #[must_use]
    pub fn peak_leases(&self) -> usize {
        self.inner.peak_leases.load(Ordering::Relaxed)
    }

    /// Total distinct [`ArrowDecoder`] instances ever allocated by this pool (`<= max_decoders`).
    #[must_use]
    pub fn total_decoders_created(&self) -> usize {
        self.inner.total_created.load(Ordering::Relaxed)
    }

    /// Sum of [`ArrowDecoder::retained_memory_bytes`] across decoders currently parked in the pool.
    #[must_use]
    pub fn retained_memory_bytes(&self) -> usize {
        let idle = self
            .inner
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        idle.iter().map(ArrowDecoder::retained_memory_bytes).sum()
    }
}

/// RAII lease over a reusable [`ArrowDecoder`] from a [`DecoderPool`].
#[cfg(feature = "arrow")]
#[derive(Debug)]
pub struct PooledDecoder {
    decoder: Option<ArrowDecoder>,
    pool: Arc<DecoderPoolInner>,
    _permit: OwnedSemaphorePermit,
}

#[cfg(feature = "arrow")]
impl Deref for PooledDecoder {
    type Target = ArrowDecoder;

    fn deref(&self) -> &Self::Target {
        self.decoder
            .as_ref()
            .expect("PooledDecoder is Some until Drop")
    }
}

#[cfg(feature = "arrow")]
impl DerefMut for PooledDecoder {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.decoder
            .as_mut()
            .expect("PooledDecoder is Some until Drop")
    }
}

#[cfg(feature = "arrow")]
impl Drop for PooledDecoder {
    fn drop(&mut self) {
        self.pool.active_leases.fetch_sub(1, Ordering::Relaxed);
        if let Some(mut decoder) = self.decoder.take() {
            if decoder.retained_memory_bytes() > self.pool.max_retained_bytes {
                let fresh = ArrowDecoder::new();
                if fresh.retained_memory_bytes() <= self.pool.max_retained_bytes {
                    decoder = fresh;
                } else {
                    return;
                }
            }
            let mut idle = self
                .pool
                .idle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            idle.push(decoder);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use super::*;

    #[tokio::test]
    async fn body_buffer_pool_reuses_slots_and_shrinks_outliers() {
        let pool = BodyBufferPool::new(NonZeroUsize::MIN, 1_024);
        let mut lease = pool.acquire(256).await;
        assert_eq!(pool.active_leases(), 1);
        lease.resize(16 * 1024, b'x');
        assert_eq!(lease.as_ref().len(), 16 * 1024);
        drop(lease);

        assert_eq!(pool.active_leases(), 0);
        assert_eq!(pool.peak_leases(), 1);
        assert_eq!(pool.total_buffers_created(), 1);
        assert!(pool.retained_memory_bytes() <= 1_024);

        let zero_pool = BodyBufferPool::new(NonZeroUsize::MIN, 0);
        let mut z = zero_pool.acquire(512).await;
        z.extend_from_slice(b"abc");
        drop(z);
        assert_eq!(zero_pool.retained_memory_bytes(), 0);
    }

    #[cfg(feature = "arrow")]
    #[tokio::test]
    async fn decoder_pool_caps_retained_memory_after_outlier_scrape() {
        use prometheus_expfmt::arrow::DecodeOptions;
        use prometheus_expfmt::format::Format;

        let baseline = ArrowDecoder::new().retained_memory_bytes();
        let cap = baseline + 16 * 1024;
        let pool = DecoderPool::new(NonZeroUsize::MIN, cap);

        let mut big = String::from("# TYPE big_metric gauge\n");
        for i in 0..8_000 {
            big.push_str(&format!(
                "big_metric{{instance=\"host-{i}\",pod=\"pod-{i}-long-label-value\"}} {i}\n"
            ));
        }

        let mut dec = pool.acquire().await;
        let _ = dec
            .decode(big.as_bytes(), &Format::TEXT, &DecodeOptions::new())
            .expect("decode big");
        assert!(
            dec.retained_memory_bytes() > cap,
            "expected outlier scrape to grow decoder past {cap}, got {}",
            dec.retained_memory_bytes()
        );
        drop(dec);

        assert_eq!(pool.total_decoders_created(), 1);
        assert!(
            pool.retained_memory_bytes() <= cap,
            "expected idle decoder <= {cap} bytes, got {}",
            pool.retained_memory_bytes()
        );

        let zero_pool = DecoderPool::new(NonZeroUsize::MIN, 0);
        let dec0 = zero_pool.acquire().await;
        drop(dec0);
        assert_eq!(zero_pool.retained_memory_bytes(), 0);
    }
}
