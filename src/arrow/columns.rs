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

//! Reusable zero-allocation column and table staging buffers for [`super::ArrowDecoder`].

use std::sync::Arc;

use arrow_array::types::{UInt8Type, UInt16Type};
use arrow_array::{
    ArrayRef, BooleanArray, DictionaryArray, FixedSizeBinaryArray, Float64Array, Int32Array,
    ListArray, RecordBatch, StringArray, StructArray, TimestampNanosecondArray, UInt8Array,
    UInt16Array, UInt32Array, UInt64Array,
};
use arrow_buffer::{BooleanBuffer, Buffer, NullBuffer, OffsetBuffer, ScalarBuffer};

use super::DecodeError;
use super::intern::StringInterner;
use super::schema::{
    AGGREGATION_TEMPORALITY_CUMULATIVE, ATTR_VALUE_TYPE_STR, KeyEncoding,
    OTAP_METRIC_TYPE_HISTOGRAM, OTAP_METRIC_TYPE_SUM, UTC_TIME_ZONE, ValEncoding, dp_attrs_schema,
    exemplars_schema, histogram_bucket_counts_item_field, histogram_dp_schema,
    histogram_explicit_bounds_item_field, metric_attrs_key_dict, metric_attrs_schema,
    metric_attrs_type_val_dict, number_dp_schema, resource_struct_fields, summary_dp_schema,
    summary_quantile_item_field, summary_quantile_struct_fields, univariate_metrics_schema,
};

/// Reusable scratch vectors used when materializing Arrow columns without reallocating.
pub(super) struct ScratchBuffers {
    pub(super) u8_buf: Vec<u8>,
    pub(super) u16_buf: Vec<u16>,
    pub(super) u32_buf: Vec<u32>,
    pub(super) i32_buf: Vec<i32>,
    pub(super) bytes: Vec<u8>,
}

impl ScratchBuffers {
    pub(super) fn with_capacity(metrics: usize, data_points: usize, attrs: usize) -> Self {
        Self {
            u8_buf: Vec::with_capacity(attrs.max(metrics)),
            u16_buf: Vec::with_capacity(attrs.max(metrics)),
            u32_buf: Vec::with_capacity(data_points),
            i32_buf: Vec::with_capacity(metrics + 1),
            bytes: Vec::new(),
        }
    }

    pub(super) fn retained_memory_bytes(&self) -> usize {
        self.u8_buf.capacity()
            + self.u16_buf.capacity() * size_of::<u16>()
            + self.u32_buf.capacity() * size_of::<u32>()
            + self.i32_buf.capacity() * size_of::<i32>()
            + self.bytes.capacity()
    }

    pub(super) fn build_attr_columns(
        &mut self,
        pairs: &[(u32, u32)],
        enc: &AttrEncoding<'_>,
        table: &'static str,
    ) -> Result<(ArrayRef, ArrayRef, ArrayRef), DecodeError> {
        let num_attrs = pairs.len();

        let key_arr: ArrayRef = match enc.key_enc {
            KeyEncoding::DictU8 => {
                self.u8_buf.clear();
                self.u8_buf.extend(pairs.iter().map(|&(k, _)| k as u8));
                let keys = UInt8Array::new(scalar_from_slice(&self.u8_buf), None);
                let dict = Arc::clone(enc.key_dict.as_ref().expect("key_dict present for DictU8"));
                Arc::new(DictionaryArray::<UInt8Type>::new(keys, dict))
            }
            KeyEncoding::DictU16 => {
                self.u16_buf.clear();
                self.u16_buf.extend(pairs.iter().map(|&(k, _)| k as u16));
                let keys = UInt16Array::new(scalar_from_slice(&self.u16_buf), None);
                let dict = Arc::clone(enc.key_dict.as_ref().expect("key_dict present for DictU16"));
                Arc::new(DictionaryArray::<UInt16Type>::new(keys, dict))
            }
            KeyEncoding::Utf8 => Arc::new(materialize_plain_strings(
                enc.key_interner,
                pairs.iter().map(|&(k, _)| k),
                &mut self.i32_buf,
                &mut self.bytes,
                table,
            )?),
        };

        self.u8_buf.clear();
        self.u8_buf.resize(num_attrs, ATTR_VALUE_TYPE_STR);
        let type_arr: ArrayRef = Arc::new(UInt8Array::new(scalar_from_slice(&self.u8_buf), None));

        let val_arr: ArrayRef = match enc.val_enc {
            ValEncoding::DictU16 => {
                self.u16_buf.clear();
                self.u16_buf.extend(pairs.iter().map(|&(_, v)| v as u16));
                let keys = UInt16Array::new(scalar_from_slice(&self.u16_buf), None);
                let dict = Arc::clone(enc.val_dict.as_ref().expect("val_dict present for DictU16"));
                Arc::new(DictionaryArray::<UInt16Type>::new(keys, dict))
            }
            ValEncoding::Utf8 => Arc::new(materialize_plain_strings(
                enc.val_interner,
                pairs.iter().map(|&(_, v)| v),
                &mut self.i32_buf,
                &mut self.bytes,
                table,
            )?),
        };

        Ok((key_arr, type_arr, val_arr))
    }
}

/// Shared key/value dictionary encoding state across all attribute tables in a finalized batch.
pub(super) struct AttrEncoding<'a> {
    key_interner: &'a StringInterner,
    val_interner: &'a StringInterner,
    pub(super) key_enc: KeyEncoding,
    pub(super) val_enc: ValEncoding,
    key_dict: Option<ArrayRef>,
    val_dict: Option<ArrayRef>,
}

impl<'a> AttrEncoding<'a> {
    pub(super) fn new(
        key_interner: &'a StringInterner,
        val_interner: &'a StringInterner,
        materialize_dicts: bool,
    ) -> Self {
        if !materialize_dicts {
            return Self {
                key_interner,
                val_interner,
                key_enc: KeyEncoding::DictU8,
                val_enc: ValEncoding::DictU16,
                key_dict: None,
                val_dict: None,
            };
        }
        let unique_keys = key_interner.len();
        let unique_vals = val_interner.len();
        let key_enc = if unique_keys <= 256 {
            KeyEncoding::DictU8
        } else if unique_keys <= 65_536 {
            KeyEncoding::DictU16
        } else {
            KeyEncoding::Utf8
        };
        let val_enc = if unique_vals <= 65_536 {
            ValEncoding::DictU16
        } else {
            ValEncoding::Utf8
        };
        let key_dict = (key_enc != KeyEncoding::Utf8)
            .then(|| Arc::new(key_interner.to_string_array()) as ArrayRef);
        let val_dict = (val_enc != ValEncoding::Utf8)
            .then(|| Arc::new(val_interner.to_string_array()) as ArrayRef);
        Self {
            key_interner,
            val_interner,
            key_enc,
            val_enc,
            key_dict,
            val_dict,
        }
    }
}

/// Staging buffer for an optional UTF-8 string column (`description` or `unit` on
/// `UnivariateMetrics`) that materializes its `offsets` and validity bitmap lazily on first
/// presence or first null.
pub(super) struct OptionalStringCol {
    offsets: Vec<i32>,
    bytes: Vec<u8>,
    valid: Vec<bool>,
    pub(super) any: bool,
    all: bool,
}

impl Default for OptionalStringCol {
    fn default() -> Self {
        Self::new()
    }
}

impl OptionalStringCol {
    pub(super) const fn new() -> Self {
        Self {
            offsets: Vec::new(),
            bytes: Vec::new(),
            valid: Vec::new(),
            any: false,
            all: true,
        }
    }

    pub(super) fn clear(&mut self) {
        self.offsets.clear();
        self.bytes.clear();
        self.valid.clear();
        self.any = false;
        self.all = true;
    }

    pub(super) fn retained_memory_bytes(&self) -> usize {
        self.offsets.capacity() * size_of::<i32>()
            + self.bytes.capacity()
            + self.valid.capacity() * size_of::<bool>()
    }

    #[inline]
    pub(super) fn check_next_offset(
        &self,
        present: bool,
        value: &[u8],
        table: &'static str,
    ) -> Result<Option<i32>, DecodeError> {
        if !present {
            return Ok(None);
        }
        let next_len = self.bytes.len().saturating_add(value.len());
        let off = i32::try_from(next_len).map_err(|_| DecodeError::CapacityOverflow {
            table,
            count: next_len,
        })?;
        Ok(Some(off))
    }

    #[inline]
    pub(super) fn append_checked(&mut self, row_index: usize, next_end: Option<i32>, value: &[u8]) {
        if let Some(end_off) = next_end {
            if !self.any {
                self.any = true;
                self.offsets.resize(row_index + 1, 0);
                if row_index > 0 {
                    self.valid.resize(row_index, false);
                    self.valid.push(true);
                }
            } else if !self.all {
                self.valid.push(true);
            }
            self.bytes.extend_from_slice(value);
            self.offsets.push(end_off);
        } else {
            if self.all {
                self.all = false;
                if self.any {
                    self.valid.resize(row_index, true);
                }
            }
            if self.any {
                self.valid.push(false);
                self.offsets.push(self.bytes.len() as i32);
            }
        }
    }

    pub(super) fn to_array(&self) -> ArrayRef {
        let nulls = (!self.all)
            .then(|| NullBuffer::new(BooleanBuffer::from_iter(self.valid.iter().copied())));
        Arc::new(string_array_from_slices(&self.offsets, &self.bytes, nulls))
    }
}

/// Staging buffers for `UnivariateMetrics` and `MetricAttrs`.
pub(super) struct MetricTable {
    pub(super) metric_types: Vec<u8>,
    pub(super) is_monotonic: Vec<bool>,
    pub(super) attr_type_keys: Vec<u16>,
    pub(super) name_offsets: Vec<i32>,
    pub(super) name_bytes: Vec<u8>,
    pub(super) desc: OptionalStringCol,
    pub(super) unit: OptionalStringCol,
    pub(super) any_temporality: bool,
    pub(super) all_temporality: bool,
    pub(super) any_sum: bool,
    pub(super) all_sum: bool,
}

impl MetricTable {
    pub(super) fn with_capacity(metrics: usize) -> Self {
        let mut name_offsets = Vec::with_capacity(metrics + 1);
        name_offsets.push(0);
        Self {
            metric_types: Vec::with_capacity(metrics),
            is_monotonic: Vec::with_capacity(metrics),
            attr_type_keys: Vec::with_capacity(metrics),
            name_offsets,
            name_bytes: Vec::with_capacity(metrics.saturating_mul(32)),
            desc: OptionalStringCol::new(),
            unit: OptionalStringCol::new(),
            any_temporality: false,
            all_temporality: true,
            any_sum: false,
            all_sum: true,
        }
    }

    pub(super) fn clear(&mut self) {
        self.metric_types.clear();
        self.is_monotonic.clear();
        self.attr_type_keys.clear();
        self.name_offsets.clear();
        self.name_offsets.push(0);
        self.name_bytes.clear();
        self.desc.clear();
        self.unit.clear();
        self.any_temporality = false;
        self.all_temporality = true;
        self.any_sum = false;
        self.all_sum = true;
    }

    pub(super) fn retained_memory_bytes(&self) -> usize {
        self.metric_types.capacity()
            + self.is_monotonic.capacity() * size_of::<bool>()
            + self.attr_type_keys.capacity() * size_of::<u16>()
            + self.name_offsets.capacity() * size_of::<i32>()
            + self.name_bytes.capacity()
            + self.desc.retained_memory_bytes()
            + self.unit.retained_memory_bytes()
    }

    #[inline]
    pub(super) fn len(&self) -> usize {
        self.metric_types.len()
    }

    #[inline]
    pub(super) fn is_empty(&self) -> bool {
        self.metric_types.is_empty()
    }

    pub(super) fn build_univariate_metrics(
        &self,
        scratch: &mut ScratchBuffers,
    ) -> Result<RecordBatch, DecodeError> {
        let num_metrics = self.metric_types.len();
        let schema = univariate_metrics_schema(
            self.desc.any,
            self.unit.any,
            self.any_temporality,
            self.any_sum,
        );
        let mut cols: Vec<ArrayRef> = Vec::with_capacity(schema.fields().len());

        scratch.u16_buf.clear();
        scratch.u16_buf.extend((0..num_metrics).map(|i| i as u16));
        cols.push(Arc::new(UInt16Array::new(
            scalar_from_slice(&scratch.u16_buf),
            None,
        )));

        scratch.u16_buf.clear();
        scratch.u16_buf.resize(num_metrics, 0);
        let res_ids: ArrayRef =
            Arc::new(UInt16Array::new(scalar_from_slice(&scratch.u16_buf), None));
        cols.push(Arc::new(StructArray::new(
            resource_struct_fields(),
            vec![res_ids],
            None,
        )));

        cols.push(Arc::new(UInt8Array::new(
            scalar_from_slice(&self.metric_types),
            None,
        )));

        cols.push(Arc::new(string_array_from_slices(
            &self.name_offsets,
            &self.name_bytes,
            None,
        )));

        if self.desc.any {
            cols.push(self.desc.to_array());
        }

        if self.unit.any {
            cols.push(self.unit.to_array());
        }

        if self.any_temporality {
            scratch.i32_buf.clear();
            scratch.i32_buf.extend(self.metric_types.iter().map(|&t| {
                if t == OTAP_METRIC_TYPE_SUM || t == OTAP_METRIC_TYPE_HISTOGRAM {
                    AGGREGATION_TEMPORALITY_CUMULATIVE
                } else {
                    0
                }
            }));
            let temp_nulls = (!self.all_temporality).then(|| {
                NullBuffer::new(BooleanBuffer::from_iter(
                    self.metric_types
                        .iter()
                        .map(|&t| t == OTAP_METRIC_TYPE_SUM || t == OTAP_METRIC_TYPE_HISTOGRAM),
                ))
            });
            cols.push(Arc::new(Int32Array::new(
                scalar_from_slice(&scratch.i32_buf),
                temp_nulls,
            )));
        }

        if self.any_sum {
            let monotonic_values = BooleanBuffer::from_iter(self.is_monotonic.iter().copied());
            let sum_nulls = (!self.all_sum).then(|| {
                NullBuffer::new(BooleanBuffer::from_iter(
                    self.metric_types.iter().map(|&t| t == OTAP_METRIC_TYPE_SUM),
                ))
            });
            cols.push(Arc::new(BooleanArray::new(monotonic_values, sum_nulls)));
        }

        Ok(RecordBatch::try_new(schema, cols)?)
    }

    pub(super) fn build_metric_attrs(
        &self,
        scratch: &mut ScratchBuffers,
    ) -> Result<RecordBatch, DecodeError> {
        let num_metrics = self.metric_types.len();
        scratch.u16_buf.clear();
        scratch.u16_buf.extend((0..num_metrics).map(|i| i as u16));

        let parent_id_arr = UInt16Array::new(scalar_from_slice(&scratch.u16_buf), None);

        scratch.u8_buf.clear();
        scratch.u8_buf.resize(num_metrics, 0);
        let key_keys = UInt8Array::new(scalar_from_slice(&scratch.u8_buf), None);
        let key_dict = DictionaryArray::<UInt8Type>::new(key_keys, metric_attrs_key_dict());

        scratch.u8_buf.fill(ATTR_VALUE_TYPE_STR);
        let type_arr = UInt8Array::new(scalar_from_slice(&scratch.u8_buf), None);

        let str_keys = UInt16Array::new(scalar_from_slice(&self.attr_type_keys), None);
        let str_dict = DictionaryArray::<UInt16Type>::new(str_keys, metric_attrs_type_val_dict());

        Ok(RecordBatch::try_new(
            metric_attrs_schema(),
            vec![
                Arc::new(parent_id_arr),
                Arc::new(key_dict),
                Arc::new(type_arr),
                Arc::new(str_dict),
            ],
        )?)
    }
}

/// Staging buffer for an optional nanosecond timestamp column (`start_time_unix_nano` or
/// `time_unix_nano`) that stays unallocated when every row in the batch omits the timestamp.
#[derive(Default)]
pub(super) struct SparseTimestampCol {
    values: Vec<i64>,
    valid: Vec<bool>,
}

impl SparseTimestampCol {
    pub(super) fn clear(&mut self) {
        self.values.clear();
        self.valid.clear();
    }

    pub(super) fn retained_memory_bytes(&self) -> usize {
        self.values.capacity() * size_of::<i64>() + self.valid.capacity() * size_of::<bool>()
    }

    #[inline]
    pub(super) fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    #[inline]
    pub(super) fn has_nulls(&self) -> bool {
        !self.valid.is_empty()
    }

    #[inline]
    pub(super) fn push(&mut self, row_index: usize, val: Option<i64>) {
        match val {
            Some(v) => {
                if row_index > 0 && self.values.is_empty() {
                    self.values.resize(row_index, 0);
                    self.valid.resize(row_index, false);
                }
                self.values.push(v);
                if !self.valid.is_empty() {
                    self.valid.push(true);
                }
            }
            None => {
                if !self.values.is_empty() {
                    if self.valid.is_empty() {
                        self.valid.resize(row_index, true);
                    }
                    self.values.push(0);
                    self.valid.push(false);
                }
            }
        }
    }

    #[inline]
    pub(super) fn to_array(&self, nullable: bool) -> ArrayRef {
        let nulls =
            nullable.then(|| NullBuffer::new(BooleanBuffer::from_iter(self.valid.iter().copied())));
        let arr = TimestampNanosecondArray::new(scalar_from_slice(&self.values), nulls)
            .with_timezone(UTC_TIME_ZONE);
        Arc::new(arr)
    }
}

/// Shared leading columns (`id`, `parent_id`, `start_time_unix_nano`, `time_unix_nano`) across
/// `NumberDataPoints`, `SummaryDataPoints`, and `HistogramDataPoints`.
#[derive(Default)]
pub(super) struct DpBaseCols {
    pub(super) parent_ids: Vec<u16>,
    pub(super) start_time: SparseTimestampCol,
    pub(super) time: SparseTimestampCol,
}

impl DpBaseCols {
    pub(super) fn with_capacity(cap: usize) -> Self {
        Self {
            parent_ids: Vec::with_capacity(cap),
            start_time: SparseTimestampCol::default(),
            time: SparseTimestampCol::default(),
        }
    }

    pub(super) fn clear(&mut self) {
        self.parent_ids.clear();
        self.start_time.clear();
        self.time.clear();
    }

    pub(super) fn retained_memory_bytes(&self) -> usize {
        self.parent_ids.capacity() * size_of::<u16>()
            + self.start_time.retained_memory_bytes()
            + self.time.retained_memory_bytes()
    }

    #[inline]
    pub(super) fn len(&self) -> usize {
        self.parent_ids.len()
    }

    #[inline]
    pub(super) fn is_empty(&self) -> bool {
        self.parent_ids.is_empty()
    }

    #[inline]
    pub(super) fn push(&mut self, parent_id: u16, start_ts_ns: Option<i64>, ts_ns: Option<i64>) {
        let dp_index = self.parent_ids.len();
        self.parent_ids.push(parent_id);
        self.start_time.push(dp_index, start_ts_ns);
        self.time.push(dp_index, ts_ns);
    }

    #[inline]
    pub(super) fn schema_flags(&self, has_default_ts: bool) -> (bool, bool, bool, bool) {
        let has_start_time = !self.start_time.is_empty();
        let start_time_nullable = has_start_time && self.start_time.has_nulls();
        let has_time = !self.time.is_empty();
        let time_nullable = has_time && !has_default_ts && self.time.has_nulls();
        (has_start_time, start_time_nullable, has_time, time_nullable)
    }

    pub(super) fn append_columns(
        &self,
        cols: &mut Vec<ArrayRef>,
        has_id: bool,
        has_default_ts: bool,
        scratch_u32: &mut Vec<u32>,
    ) {
        let num_dps = self.parent_ids.len();
        let (has_start_time, start_time_nullable, has_time, time_nullable) =
            self.schema_flags(has_default_ts);

        if has_id {
            scratch_u32.clear();
            scratch_u32.extend(0..num_dps as u32);
            cols.push(Arc::new(UInt32Array::new(
                scalar_from_slice(scratch_u32),
                None,
            )));
        }

        cols.push(Arc::new(UInt16Array::new(
            scalar_from_slice(&self.parent_ids),
            None,
        )));

        if has_start_time {
            cols.push(self.start_time.to_array(start_time_nullable));
        }

        if has_time {
            cols.push(self.time.to_array(time_nullable));
        }
    }
}

/// Staging buffer for a dense column (`count` or `sum` on summaries and histograms) whose validity
/// bitmap is materialized lazily when the first `None` arrives.
#[derive(Default)]
pub(super) struct OptionalValueCol<T> {
    values: Vec<T>,
    valid: Vec<bool>,
}

impl<T: Copy + Default> OptionalValueCol<T> {
    pub(super) fn clear(&mut self) {
        self.values.clear();
        self.valid.clear();
    }

    pub(super) fn retained_memory_bytes(&self) -> usize {
        self.values.capacity() * size_of::<T>() + self.valid.capacity() * size_of::<bool>()
    }

    #[inline]
    pub(super) fn is_nullable(&self) -> bool {
        !self.valid.is_empty()
    }

    #[inline]
    pub(super) fn push(&mut self, row_index: usize, val: Option<T>) {
        match val {
            Some(v) => {
                self.values.push(v);
                if !self.valid.is_empty() {
                    self.valid.push(true);
                }
            }
            None => {
                if self.valid.is_empty() {
                    self.valid.resize(row_index, true);
                }
                self.values.push(T::default());
                self.valid.push(false);
            }
        }
    }

    #[inline]
    fn nulls(&self) -> Option<NullBuffer> {
        (!self.valid.is_empty())
            .then(|| NullBuffer::new(BooleanBuffer::from_iter(self.valid.iter().copied())))
    }
}

impl OptionalValueCol<u64> {
    #[inline]
    pub(super) fn to_u64_array(&self) -> ArrayRef {
        Arc::new(UInt64Array::new(
            scalar_from_slice(&self.values),
            self.nulls(),
        ))
    }
}

impl OptionalValueCol<f64> {
    #[inline]
    pub(super) fn to_f64_array(&self) -> ArrayRef {
        Arc::new(Float64Array::new(
            scalar_from_slice(&self.values),
            self.nulls(),
        ))
    }
}

/// Staging buffer for a `u32`-parented attribute table (`NumberDpAttrs`, `SummaryDpAttrs`,
/// `HistogramDpAttrs`, `NumberDpExemplarAttrs`, or `HistogramDpExemplarAttrs`).
#[derive(Default)]
pub(super) struct AttrTable {
    pub(super) parent_ids: Vec<u32>,
    pub(super) pairs: Vec<(u32, u32)>,
}

impl AttrTable {
    pub(super) fn with_capacity(cap: usize) -> Self {
        Self {
            parent_ids: Vec::with_capacity(cap),
            pairs: Vec::with_capacity(cap),
        }
    }

    pub(super) fn clear(&mut self) {
        self.parent_ids.clear();
        self.pairs.clear();
    }

    pub(super) fn retained_memory_bytes(&self) -> usize {
        self.parent_ids.capacity() * size_of::<u32>()
            + self.pairs.capacity() * size_of::<(u32, u32)>()
    }

    #[inline]
    pub(super) fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    #[inline]
    pub(super) fn len(&self) -> usize {
        self.pairs.len()
    }

    #[inline]
    pub(super) fn push(&mut self, parent_id: u32, key_id: u32, val_id: u32) {
        self.parent_ids.push(parent_id);
        self.pairs.push((key_id, val_id));
    }

    #[inline]
    pub(super) fn extend_for_parent(&mut self, parent_id: u32, attrs: &[(u32, u32)]) {
        self.parent_ids
            .extend(std::iter::repeat_n(parent_id, attrs.len()));
        self.pairs.extend_from_slice(attrs);
    }

    pub(super) fn build_batch(
        &self,
        enc: &AttrEncoding<'_>,
        scratch: &mut ScratchBuffers,
    ) -> Result<Option<RecordBatch>, DecodeError> {
        if self.is_empty() {
            return Ok(None);
        }
        let parent_id_arr: ArrayRef =
            Arc::new(UInt32Array::new(scalar_from_slice(&self.parent_ids), None));
        let (key_arr, type_arr, val_arr) =
            scratch.build_attr_columns(&self.pairs, enc, "DpAttrs")?;
        Ok(Some(RecordBatch::try_new(
            dp_attrs_schema(enc.key_enc, enc.val_enc),
            vec![parent_id_arr, key_arr, type_arr, val_arr],
        )?))
    }
}

/// Staging buffer for an optional fixed-size binary column (`span_id` or `trace_id` on exemplars).
#[derive(Default)]
pub(super) struct SparseFixedBinaryCol<const N: usize> {
    values: Vec<[u8; N]>,
    valid: Vec<bool>,
    pub(super) any_present: bool,
}

impl<const N: usize> SparseFixedBinaryCol<N> {
    pub(super) fn clear(&mut self) {
        self.values.clear();
        self.valid.clear();
        self.any_present = false;
    }

    pub(super) fn retained_memory_bytes(&self) -> usize {
        self.values.capacity() * size_of::<[u8; N]>() + self.valid.capacity() * size_of::<bool>()
    }

    #[inline]
    pub(super) fn push(&mut self, row_index: usize, val: Option<[u8; N]>) {
        match val {
            Some(v) => {
                if !self.any_present {
                    self.any_present = true;
                    self.values.resize(row_index, [0u8; N]);
                    if row_index > 0 {
                        self.valid.resize(row_index, false);
                        self.valid.push(true);
                    }
                } else if !self.valid.is_empty() {
                    self.valid.push(true);
                }
                self.values.push(v);
            }
            None => {
                if self.any_present {
                    if self.valid.is_empty() {
                        self.valid.resize(row_index, true);
                    }
                    self.values.push([0u8; N]);
                    self.valid.push(false);
                }
            }
        }
    }

    pub(super) fn to_array(&self, scratch_bytes: &mut Vec<u8>) -> Result<ArrayRef, DecodeError> {
        scratch_bytes.clear();
        for id in &self.values {
            scratch_bytes.extend_from_slice(id);
        }
        let nulls = (!self.valid.is_empty())
            .then(|| NullBuffer::new(BooleanBuffer::from_iter(self.valid.iter().copied())));
        let arr = FixedSizeBinaryArray::try_new(
            N as i32,
            Buffer::from_slice_ref(&scratch_bytes[..]),
            nulls,
        )?;
        Ok(Arc::new(arr))
    }
}

/// Staging buffers for an OTAP exemplar table (`NumberDpExemplars` or `HistogramDpExemplars`) and
/// its child attribute table (`NumberDpExemplarAttrs` or `HistogramDpExemplarAttrs`).
#[derive(Default)]
pub(super) struct ExemplarTable {
    pub(super) parent_ids: Vec<u32>,
    pub(super) timestamps: Vec<i64>,
    pub(super) values: Vec<f64>,
    pub(super) span_ids: SparseFixedBinaryCol<8>,
    pub(super) trace_ids: SparseFixedBinaryCol<16>,
    pub(super) attrs: AttrTable,
}

impl ExemplarTable {
    pub(super) fn clear(&mut self) {
        self.parent_ids.clear();
        self.timestamps.clear();
        self.values.clear();
        self.span_ids.clear();
        self.trace_ids.clear();
        self.attrs.clear();
    }

    pub(super) fn retained_memory_bytes(&self) -> usize {
        self.parent_ids.capacity() * size_of::<u32>()
            + self.timestamps.capacity() * size_of::<i64>()
            + self.values.capacity() * size_of::<f64>()
            + self.span_ids.retained_memory_bytes()
            + self.trace_ids.retained_memory_bytes()
            + self.attrs.retained_memory_bytes()
    }

    #[inline]
    pub(super) fn is_empty(&self) -> bool {
        self.parent_ids.is_empty()
    }

    #[inline]
    pub(super) fn next_id(&self, table: &'static str) -> Result<u32, DecodeError> {
        let idx = self.parent_ids.len();
        u32::try_from(idx).map_err(|_| DecodeError::CapacityOverflow {
            table,
            count: idx + 1,
        })
    }

    #[inline]
    pub(super) fn push_row(
        &mut self,
        parent_id: u32,
        ts_ns: i64,
        value: f64,
        span_id: Option<[u8; 8]>,
        trace_id: Option<[u8; 16]>,
    ) {
        let ex_idx = self.parent_ids.len();
        self.parent_ids.push(parent_id);
        self.timestamps.push(ts_ns);
        self.values.push(value);
        self.span_ids.push(ex_idx, span_id);
        self.trace_ids.push(ex_idx, trace_id);
    }

    pub(super) fn build_batch(
        &self,
        scratch: &mut ScratchBuffers,
    ) -> Result<Option<RecordBatch>, DecodeError> {
        if self.parent_ids.is_empty() {
            return Ok(None);
        }
        let has_id = !self.attrs.is_empty();
        let has_span_id = self.span_ids.any_present;
        let has_trace_id = self.trace_ids.any_present;
        let schema = exemplars_schema(has_id, has_span_id, has_trace_id);
        let num_rows = self.parent_ids.len();
        let mut cols: Vec<ArrayRef> = Vec::with_capacity(schema.fields().len());

        if has_id {
            scratch.u32_buf.clear();
            scratch.u32_buf.extend(0..num_rows as u32);
            cols.push(Arc::new(UInt32Array::new(
                scalar_from_slice(&scratch.u32_buf),
                None,
            )));
        }

        cols.push(Arc::new(UInt32Array::new(
            scalar_from_slice(&self.parent_ids),
            None,
        )));

        let ts_arr = TimestampNanosecondArray::new(scalar_from_slice(&self.timestamps), None)
            .with_timezone(UTC_TIME_ZONE);
        cols.push(Arc::new(ts_arr));

        cols.push(Arc::new(Float64Array::new(
            scalar_from_slice(&self.values),
            None,
        )));

        if has_span_id {
            cols.push(self.span_ids.to_array(&mut scratch.bytes)?);
        }

        if has_trace_id {
            cols.push(self.trace_ids.to_array(&mut scratch.bytes)?);
        }

        Ok(Some(RecordBatch::try_new(schema, cols)?))
    }
}

/// Staging buffers for `NumberDataPoints`, `NumberDpAttrs`, `NumberDpExemplars`, and
/// `NumberDpExemplarAttrs`.
pub(super) struct NumberDpTable {
    pub(super) base: DpBaseCols,
    pub(super) values: Vec<f64>,
    pub(super) attrs: AttrTable,
    pub(super) exemplars: ExemplarTable,
}

impl NumberDpTable {
    pub(super) fn with_capacity(data_points: usize, attrs: usize) -> Self {
        Self {
            base: DpBaseCols::with_capacity(data_points),
            values: Vec::with_capacity(data_points),
            attrs: AttrTable::with_capacity(attrs),
            exemplars: ExemplarTable::default(),
        }
    }

    pub(super) fn clear(&mut self) {
        self.base.clear();
        self.values.clear();
        self.attrs.clear();
        self.exemplars.clear();
    }

    pub(super) fn retained_memory_bytes(&self) -> usize {
        self.base.retained_memory_bytes()
            + self.values.capacity() * size_of::<f64>()
            + self.attrs.retained_memory_bytes()
            + self.exemplars.retained_memory_bytes()
    }

    pub(super) fn build_batch(
        &self,
        has_default_ts: bool,
        scratch: &mut ScratchBuffers,
    ) -> Result<Option<RecordBatch>, DecodeError> {
        if self.base.is_empty() {
            return Ok(None);
        }
        let has_id = !self.attrs.is_empty() || !self.exemplars.is_empty();
        let (has_start_time, start_time_nullable, has_time, time_nullable) =
            self.base.schema_flags(has_default_ts);

        let schema = number_dp_schema(
            has_id,
            has_start_time,
            start_time_nullable,
            has_time,
            time_nullable,
        );
        let mut cols: Vec<ArrayRef> = Vec::with_capacity(schema.fields().len());
        self.base
            .append_columns(&mut cols, has_id, has_default_ts, &mut scratch.u32_buf);
        cols.push(Arc::new(Float64Array::new(
            scalar_from_slice(&self.values),
            None,
        )));

        Ok(Some(RecordBatch::try_new(schema, cols)?))
    }
}

/// Staging buffers for `SummaryDataPoints` and `SummaryDpAttrs`.
#[derive(Default)]
pub(super) struct SummaryDpTable {
    pub(super) base: DpBaseCols,
    pub(super) counts: OptionalValueCol<u64>,
    pub(super) sums: OptionalValueCol<f64>,
    pub(super) quantile_offsets: Vec<i32>,
    pub(super) quantile_bounds: Vec<f64>,
    pub(super) quantile_vals: Vec<f64>,
    pub(super) attrs: AttrTable,
}

impl SummaryDpTable {
    pub(super) fn clear(&mut self) {
        self.base.clear();
        self.counts.clear();
        self.sums.clear();
        self.quantile_offsets.clear();
        self.quantile_bounds.clear();
        self.quantile_vals.clear();
        self.attrs.clear();
    }

    pub(super) fn retained_memory_bytes(&self) -> usize {
        self.base.retained_memory_bytes()
            + self.counts.retained_memory_bytes()
            + self.sums.retained_memory_bytes()
            + self.quantile_offsets.capacity() * size_of::<i32>()
            + self.quantile_bounds.capacity() * size_of::<f64>()
            + self.quantile_vals.capacity() * size_of::<f64>()
            + self.attrs.retained_memory_bytes()
    }

    pub(super) fn build_batch(
        &self,
        has_default_ts: bool,
        scratch: &mut ScratchBuffers,
    ) -> Result<Option<RecordBatch>, DecodeError> {
        if self.base.is_empty() {
            return Ok(None);
        }
        let has_id = !self.attrs.is_empty();
        let (has_start_time, start_time_nullable, has_time, time_nullable) =
            self.base.schema_flags(has_default_ts);
        let count_nullable = self.counts.is_nullable();
        let sum_nullable = self.sums.is_nullable();

        let schema = summary_dp_schema(
            has_id,
            has_start_time,
            start_time_nullable,
            has_time,
            time_nullable,
            count_nullable,
            sum_nullable,
        );
        let mut cols: Vec<ArrayRef> = Vec::with_capacity(schema.fields().len());
        self.base
            .append_columns(&mut cols, has_id, has_default_ts, &mut scratch.u32_buf);
        cols.push(self.counts.to_u64_array());
        cols.push(self.sums.to_f64_array());

        let q_struct = StructArray::try_new(
            summary_quantile_struct_fields(),
            vec![
                Arc::new(Float64Array::new(
                    scalar_from_slice(&self.quantile_bounds),
                    None,
                )),
                Arc::new(Float64Array::new(
                    scalar_from_slice(&self.quantile_vals),
                    None,
                )),
            ],
            None,
        )?;
        let q_list = ListArray::new(
            summary_quantile_item_field(),
            OffsetBuffer::new(scalar_from_slice(&self.quantile_offsets)),
            Arc::new(q_struct),
            None,
        );
        cols.push(Arc::new(q_list));

        Ok(Some(RecordBatch::try_new(schema, cols)?))
    }
}

/// Staging buffers for `HistogramDataPoints`, `HistogramDpAttrs`, `HistogramDpExemplars`, and
/// `HistogramDpExemplarAttrs`.
#[derive(Default)]
pub(super) struct HistogramDpTable {
    pub(super) base: DpBaseCols,
    pub(super) counts: OptionalValueCol<u64>,
    pub(super) sums: OptionalValueCol<f64>,
    pub(super) bucket_offsets: Vec<i32>,
    pub(super) bucket_counts: Vec<u64>,
    pub(super) bounds_offsets: Vec<i32>,
    pub(super) bounds_vals: Vec<f64>,
    pub(super) attrs: AttrTable,
    pub(super) exemplars: ExemplarTable,
}

impl HistogramDpTable {
    pub(super) fn clear(&mut self) {
        self.base.clear();
        self.counts.clear();
        self.sums.clear();
        self.bucket_offsets.clear();
        self.bucket_counts.clear();
        self.bounds_offsets.clear();
        self.bounds_vals.clear();
        self.attrs.clear();
        self.exemplars.clear();
    }

    pub(super) fn retained_memory_bytes(&self) -> usize {
        self.base.retained_memory_bytes()
            + self.counts.retained_memory_bytes()
            + self.sums.retained_memory_bytes()
            + self.bucket_offsets.capacity() * size_of::<i32>()
            + self.bucket_counts.capacity() * size_of::<u64>()
            + self.bounds_offsets.capacity() * size_of::<i32>()
            + self.bounds_vals.capacity() * size_of::<f64>()
            + self.attrs.retained_memory_bytes()
            + self.exemplars.retained_memory_bytes()
    }

    pub(super) fn build_batch(
        &self,
        has_default_ts: bool,
        scratch: &mut ScratchBuffers,
    ) -> Result<Option<RecordBatch>, DecodeError> {
        if self.base.is_empty() {
            return Ok(None);
        }
        let has_id = !self.attrs.is_empty() || !self.exemplars.is_empty();
        let (has_start_time, start_time_nullable, has_time, time_nullable) =
            self.base.schema_flags(has_default_ts);
        let count_nullable = self.counts.is_nullable();
        let sum_nullable = self.sums.is_nullable();

        let schema = histogram_dp_schema(
            has_id,
            has_start_time,
            start_time_nullable,
            has_time,
            time_nullable,
            count_nullable,
            sum_nullable,
        );
        let mut cols: Vec<ArrayRef> = Vec::with_capacity(schema.fields().len());
        self.base
            .append_columns(&mut cols, has_id, has_default_ts, &mut scratch.u32_buf);
        cols.push(self.counts.to_u64_array());
        cols.push(self.sums.to_f64_array());

        let bucket_counts_list = ListArray::new(
            histogram_bucket_counts_item_field(),
            OffsetBuffer::new(scalar_from_slice(&self.bucket_offsets)),
            Arc::new(UInt64Array::new(
                scalar_from_slice(&self.bucket_counts),
                None,
            )),
            None,
        );
        cols.push(Arc::new(bucket_counts_list));

        let explicit_bounds_list = ListArray::new(
            histogram_explicit_bounds_item_field(),
            OffsetBuffer::new(scalar_from_slice(&self.bounds_offsets)),
            Arc::new(Float64Array::new(
                scalar_from_slice(&self.bounds_vals),
                None,
            )),
            None,
        );
        cols.push(Arc::new(explicit_bounds_list));

        Ok(Some(RecordBatch::try_new(schema, cols)?))
    }
}

#[inline]
pub(super) fn ms_to_ns(timestamp_ms: i64) -> Result<i64, DecodeError> {
    timestamp_ms
        .checked_mul(1_000_000)
        .ok_or(DecodeError::TimestampOverflow { timestamp_ms })
}

#[inline]
pub(super) fn f64_to_u64_count(value: f64) -> u64 {
    if value.is_sign_positive() && value.is_finite() {
        value as u64
    } else {
        0
    }
}

pub(super) fn parse_hex_array<const N: usize>(raw: &[u8]) -> Option<[u8; N]> {
    if raw.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (i, &[hi_b, lo_b]) in raw.as_chunks::<2>().0.iter().enumerate() {
        let hi = hex_nibble(hi_b)?;
        let lo = hex_nibble(lo_b)?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

#[inline]
const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[inline]
pub(super) fn scalar_from_slice<T: arrow_buffer::ArrowNativeType>(slice: &[T]) -> ScalarBuffer<T> {
    ScalarBuffer::<T>::new(Buffer::from_slice_ref(slice), 0, slice.len())
}

#[inline]
pub(super) fn string_array_from_slices(
    offsets: &[i32],
    bytes: &[u8],
    nulls: Option<NullBuffer>,
) -> StringArray {
    let offsets_buf = OffsetBuffer::new(scalar_from_slice(offsets));
    let values_buf = Buffer::from_slice_ref(bytes);
    StringArray::new(offsets_buf, values_buf, nulls)
}

#[cold]
pub(super) fn materialize_plain_strings(
    interner: &StringInterner,
    ids: impl Iterator<Item = u32>,
    scratch_offsets: &mut Vec<i32>,
    scratch_bytes: &mut Vec<u8>,
    table: &'static str,
) -> Result<StringArray, DecodeError> {
    scratch_offsets.clear();
    scratch_bytes.clear();
    scratch_offsets.push(0);
    for id in ids {
        let s = interner.get_bytes(id);
        scratch_bytes.extend_from_slice(s);
        let off =
            i32::try_from(scratch_bytes.len()).map_err(|_| DecodeError::CapacityOverflow {
                table,
                count: scratch_bytes.len(),
            })?;
        scratch_offsets.push(off);
    }
    Ok(string_array_from_slices(
        scratch_offsets,
        scratch_bytes,
        None,
    ))
}
