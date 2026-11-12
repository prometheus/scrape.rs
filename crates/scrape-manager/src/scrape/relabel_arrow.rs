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

//! Post-decode Prometheus `honor_labels` and `metric_relabel_configs` evaluation over OTAP
//! [`OtapMetricRecords`] batches.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock};

use arrow_array::types::{UInt8Type, UInt16Type};
use arrow_array::{
    Array, ArrayRef, BooleanArray, DictionaryArray, FixedSizeBinaryArray, Float64Array, Int32Array,
    ListArray, RecordBatch, StringArray, StructArray, TimestampNanosecondArray, UInt8Array,
    UInt16Array, UInt32Array, UInt64Array,
};
use arrow_buffer::{BooleanBuffer, Buffer, NullBuffer, OffsetBuffer, ScalarBuffer};
use arrow_schema::{DataType, Field, Fields, Schema, SchemaRef, TimeUnit};
use prometheus_expfmt::arrow::{DecodeError, MetricPayloadType, OtapMetricRecords};
use prometheus_relabel::{
    Action, Config as RelabelConfig, LabelSet, METRIC_NAME_LABEL, RESERVED_LABEL_PREFIX,
    merge_target_and_metric_labels, process_in_place, resolve_conflicting_exposed_keys,
};

const ATTR_VALUE_TYPE_STR: u8 = 1;
const OTAP_METRIC_TYPE_SUM: u8 = 2;
const OTAP_METRIC_TYPE_HISTOGRAM: u8 = 3;
const AGGREGATION_TEMPORALITY_CUMULATIVE: i32 = 2;
const UTC_TIME_ZONE: &str = "UTC";

fn plain_id_metadata() -> HashMap<String, String> {
    HashMap::from([("encoding".to_owned(), "plain".to_owned())])
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum KeyEnc {
    DictU8 = 0,
    DictU16 = 1,
    Utf8 = 2,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ValEnc {
    DictU16 = 0,
    Utf8 = 1,
}

static DP_ATTRS_SCHEMAS: LazyLock<[SchemaRef; 6]> = LazyLock::new(|| {
    let build = |k: KeyEnc, v: ValEnc| -> SchemaRef {
        let key_dt = match k {
            KeyEnc::DictU8 => {
                DataType::Dictionary(Box::new(DataType::UInt8), Box::new(DataType::Utf8))
            }
            KeyEnc::DictU16 => {
                DataType::Dictionary(Box::new(DataType::UInt16), Box::new(DataType::Utf8))
            }
            KeyEnc::Utf8 => DataType::Utf8,
        };
        let val_dt = match v {
            ValEnc::DictU16 => {
                DataType::Dictionary(Box::new(DataType::UInt16), Box::new(DataType::Utf8))
            }
            ValEnc::Utf8 => DataType::Utf8,
        };
        Arc::new(Schema::new(vec![
            Field::new("parent_id", DataType::UInt32, false).with_metadata(plain_id_metadata()),
            Field::new("key", key_dt, false),
            Field::new("type", DataType::UInt8, false),
            Field::new("str", val_dt, true),
        ]))
    };
    [
        build(KeyEnc::DictU8, ValEnc::DictU16),
        build(KeyEnc::DictU8, ValEnc::Utf8),
        build(KeyEnc::DictU16, ValEnc::DictU16),
        build(KeyEnc::DictU16, ValEnc::Utf8),
        build(KeyEnc::Utf8, ValEnc::DictU16),
        build(KeyEnc::Utf8, ValEnc::Utf8),
    ]
});

fn dp_attrs_schema(key_enc: KeyEnc, val_enc: ValEnc) -> SchemaRef {
    let idx = (key_enc as usize) * 2 + (val_enc as usize);
    Arc::clone(&DP_ATTRS_SCHEMAS[idx])
}

type DpTableTriple = (
    MetricPayloadType,
    MetricPayloadType,
    Option<(MetricPayloadType, MetricPayloadType)>,
);

const DP_TABLE_TRIPLES: [DpTableTriple; 3] = [
    (
        MetricPayloadType::NumberDataPoints,
        MetricPayloadType::NumberDpAttrs,
        Some((
            MetricPayloadType::NumberDpExemplars,
            MetricPayloadType::NumberDpExemplarAttrs,
        )),
    ),
    (
        MetricPayloadType::SummaryDataPoints,
        MetricPayloadType::SummaryDpAttrs,
        None,
    ),
    (
        MetricPayloadType::HistogramDataPoints,
        MetricPayloadType::HistogramDpAttrs,
        Some((
            MetricPayloadType::HistogramDpExemplars,
            MetricPayloadType::HistogramDpExemplarAttrs,
        )),
    ),
];

/// Applies Prometheus `honor_labels` conflict resolution and `metric_relabel_configs` to an
/// [`OtapMetricRecords`] chunk decoded for a target with `target_labels`.
///
/// Target labels remain represented at the batch/resource level unless overridden by a sample (when
/// `honor_labels` is `true`) or synthesized/mutated by `metric_relabel_configs`: `DpAttrs` emits
/// all post-relabel non-reserved (`!__`) labels `(k, v)` whose value differs from
/// `target_labels[k]`.
///
/// # Errors
///
/// Returns [`DecodeError`] if an expanded attribute table overflows OTAP's integer ID limits or an
/// input `RecordBatch` violates expected OTAP column types.
pub fn apply_metric_relabel(
    mut records: OtapMetricRecords,
    target_labels: &LabelSet,
    honor_labels: bool,
    metric_relabel_configs: &[RelabelConfig],
) -> Result<OtapMetricRecords, DecodeError> {
    if records.is_empty() {
        return Ok(records);
    }

    if metric_relabel_configs.is_empty() {
        if honor_labels || target_labels.is_empty() {
            return Ok(records);
        }
        rename_conflicting_sample_keys_only(&mut records, target_labels)?;
        return Ok(records);
    }

    let public_target: LabelSet = target_labels
        .iter()
        .filter(|(k, v)| !k.starts_with(RESERVED_LABEL_PREFIX) && !v.is_empty())
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    if let Some(batch_outcome) = try_eval_batch_invariant(
        &records,
        &public_target,
        honor_labels,
        metric_relabel_configs,
    ) {
        return apply_batch_invariant_relabel(records, &public_target, honor_labels, batch_outcome);
    }

    apply_per_datapoint_relabel(
        records,
        &public_target,
        honor_labels,
        metric_relabel_configs,
    )
}

enum BatchInvariantOutcome {
    DropAll,
    Keep {
        extra_dp_labels: Vec<(String, String)>,
    },
}

/// Checks whether `metric_relabel_configs` depends only on batch-invariant labels (target labels
/// and absent labels) without reading or clobbering sample-varying keys or `__name__`.
///
/// When true, evaluates `metric_relabel_configs` once for the entire batch instead of per data
/// point.
fn try_eval_batch_invariant(
    records: &OtapMetricRecords,
    public_target: &LabelSet,
    honor_labels: bool,
    metric_relabel_configs: &[RelabelConfig],
) -> Option<BatchInvariantOutcome> {
    let mut varying_keys = HashSet::new();
    let mut renamed_buf = Vec::new();

    for &(_, attrs_kind, _) in &DP_TABLE_TRIPLES {
        let Some(attrs_batch) = records.get(attrs_kind) else {
            continue;
        };
        // Fast path requires dictionary-encoded key and value columns.
        let key_dict = extract_dict_strings(attrs_batch.column_by_name("key")?)?;
        let _val_dict = extract_dict_u16_strings(attrs_batch.column_by_name("str")?)?;

        if resolve_conflicting_exposed_keys(
            &key_dict,
            public_target,
            honor_labels,
            &mut renamed_buf,
        ) {
            for (idx, raw_key) in key_dict.iter().enumerate() {
                if let Some(renamed) = &renamed_buf[idx] {
                    varying_keys.insert(renamed.clone());
                } else {
                    varying_keys.insert((*raw_key).to_owned());
                }
            }
        } else {
            for &raw_key in &key_dict {
                varying_keys.insert(raw_key.to_owned());
            }
        }
    }

    let mut simulated_keys = varying_keys.clone();
    for cfg in metric_relabel_configs {
        match cfg.action {
            Action::Replace | Action::Lowercase | Action::Uppercase | Action::HashMod => {
                if cfg.target_label.is_empty()
                    || cfg.target_label.contains('$')
                    || cfg.target_label == METRIC_NAME_LABEL
                    || simulated_keys.contains(cfg.target_label.as_str())
                {
                    return None;
                }
                if cfg
                    .source_labels
                    .iter()
                    .any(|s| s == METRIC_NAME_LABEL || simulated_keys.contains(s.as_str()))
                {
                    return None;
                }
            }
            Action::Keep | Action::Drop => {
                if cfg
                    .source_labels
                    .iter()
                    .any(|s| s == METRIC_NAME_LABEL || simulated_keys.contains(s.as_str()))
                {
                    return None;
                }
            }
            Action::KeepEqual | Action::DropEqual => {
                if cfg.target_label == METRIC_NAME_LABEL
                    || simulated_keys.contains(cfg.target_label.as_str())
                    || cfg
                        .source_labels
                        .iter()
                        .any(|s| s == METRIC_NAME_LABEL || simulated_keys.contains(s.as_str()))
                {
                    return None;
                }
            }
            Action::LabelMap | Action::LabelDrop | Action::LabelKeep => {
                return None;
            }
        }
        let _ = &mut simulated_keys;
    }

    let mut batch_labels = public_target.clone();
    if !process_in_place(&mut batch_labels, metric_relabel_configs) {
        return Some(BatchInvariantOutcome::DropAll);
    }

    let extra_dp_labels: Vec<(String, String)> = batch_labels
        .into_iter()
        .filter(|(k, v)| {
            !k.starts_with(RESERVED_LABEL_PREFIX)
                && !v.is_empty()
                && public_target.get(k) != Some(v)
        })
        .collect();

    Some(BatchInvariantOutcome::Keep { extra_dp_labels })
}

fn apply_batch_invariant_relabel(
    mut records: OtapMetricRecords,
    public_target: &LabelSet,
    honor_labels: bool,
    outcome: BatchInvariantOutcome,
) -> Result<OtapMetricRecords, DecodeError> {
    let extra_dp_labels = match outcome {
        BatchInvariantOutcome::DropAll => return Ok(OtapMetricRecords::default()),
        BatchInvariantOutcome::Keep { extra_dp_labels } => extra_dp_labels,
    };

    if extra_dp_labels.is_empty() {
        if !honor_labels && !public_target.is_empty() {
            rename_conflicting_sample_keys_only(&mut records, public_target)?;
        }
        return Ok(records);
    }

    for &(dp_kind, attrs_kind, _) in &DP_TABLE_TRIPLES {
        let Some(dp_batch) = records.get(dp_kind).cloned() else {
            continue;
        };
        let num_dps = dp_batch.num_rows();
        let existing_attrs = records.get(attrs_kind);
        let merged_attrs = merge_extra_dp_attrs(
            num_dps,
            existing_attrs,
            public_target,
            honor_labels,
            &extra_dp_labels,
        )?;
        let updated_dp = ensure_dp_id_column(&dp_batch, true)?;
        records.set(dp_kind, Some(updated_dp));
        records.set(attrs_kind, Some(merged_attrs));
    }

    Ok(records)
}

fn rename_conflicting_sample_keys_only(
    records: &mut OtapMetricRecords,
    target_labels: &LabelSet,
) -> Result<(), DecodeError> {
    let mut renamed = Vec::new();
    for &(_, attrs_kind, _) in &DP_TABLE_TRIPLES {
        let Some(attrs_batch) = records.get(attrs_kind).cloned() else {
            continue;
        };
        let schema = attrs_batch.schema();
        let Ok(key_col_idx) = schema.index_of("key") else {
            continue;
        };
        let key_col = attrs_batch.column(key_col_idx);

        if let Some(dict_u8) = key_col
            .as_any()
            .downcast_ref::<DictionaryArray<UInt8Type>>()
        {
            let Some(str_vals) = dict_u8.values().as_any().downcast_ref::<StringArray>() else {
                continue;
            };
            let key_strs: Vec<&str> = (0..str_vals.len()).map(|i| str_vals.value(i)).collect();
            if !resolve_conflicting_exposed_keys(&key_strs, target_labels, false, &mut renamed) {
                continue;
            }
            let new_vals: ArrayRef = Arc::new(StringArray::from_iter_values(
                key_strs
                    .iter()
                    .enumerate()
                    .map(|(i, &orig)| renamed[i].as_deref().unwrap_or(orig)),
            ));
            let new_key_col: ArrayRef = Arc::new(DictionaryArray::<UInt8Type>::new(
                dict_u8.keys().clone(),
                new_vals,
            ));
            let mut cols = attrs_batch.columns().to_vec();
            cols[key_col_idx] = new_key_col;
            records.set(attrs_kind, Some(RecordBatch::try_new(schema, cols)?));
        } else if let Some(dict_u16) = key_col
            .as_any()
            .downcast_ref::<DictionaryArray<UInt16Type>>()
        {
            let Some(str_vals) = dict_u16.values().as_any().downcast_ref::<StringArray>() else {
                continue;
            };
            let key_strs: Vec<&str> = (0..str_vals.len()).map(|i| str_vals.value(i)).collect();
            if !resolve_conflicting_exposed_keys(&key_strs, target_labels, false, &mut renamed) {
                continue;
            }
            let new_vals: ArrayRef = Arc::new(StringArray::from_iter_values(
                key_strs
                    .iter()
                    .enumerate()
                    .map(|(i, &orig)| renamed[i].as_deref().unwrap_or(orig)),
            ));
            let new_key_col: ArrayRef = Arc::new(DictionaryArray::<UInt16Type>::new(
                dict_u16.keys().clone(),
                new_vals,
            ));
            let mut cols = attrs_batch.columns().to_vec();
            cols[key_col_idx] = new_key_col;
            records.set(attrs_kind, Some(RecordBatch::try_new(schema, cols)?));
        } else if let Some(plain_strs) = key_col.as_any().downcast_ref::<StringArray>() {
            let key_strs: Vec<&str> = (0..plain_strs.len()).map(|i| plain_strs.value(i)).collect();
            if !resolve_conflicting_exposed_keys(&key_strs, target_labels, false, &mut renamed) {
                continue;
            }
            let new_key_col: ArrayRef = Arc::new(StringArray::from_iter_values(
                key_strs
                    .iter()
                    .enumerate()
                    .map(|(i, &orig)| renamed[i].as_deref().unwrap_or(orig)),
            ));
            let mut cols = attrs_batch.columns().to_vec();
            cols[key_col_idx] = new_key_col;
            records.set(attrs_kind, Some(RecordBatch::try_new(schema, cols)?));
        }
    }
    Ok(())
}

enum KeyIndexSlice<'a> {
    U8(&'a [u8]),
    U16(&'a [u16]),
}

impl KeyIndexSlice<'_> {
    #[inline]
    fn get(&self, idx: usize) -> u32 {
        match self {
            Self::U8(s) => u32::from(s[idx]),
            Self::U16(s) => u32::from(s[idx]),
        }
    }
}

fn extract_dict_strings(col: &ArrayRef) -> Option<Vec<&str>> {
    if let Some(d8) = col.as_any().downcast_ref::<DictionaryArray<UInt8Type>>() {
        let vals = d8.values().as_any().downcast_ref::<StringArray>()?;
        Some((0..vals.len()).map(|i| vals.value(i)).collect())
    } else if let Some(d16) = col.as_any().downcast_ref::<DictionaryArray<UInt16Type>>() {
        let vals = d16.values().as_any().downcast_ref::<StringArray>()?;
        Some((0..vals.len()).map(|i| vals.value(i)).collect())
    } else {
        None
    }
}

fn extract_dict_u16_strings(col: &ArrayRef) -> Option<Vec<&str>> {
    let d16 = col.as_any().downcast_ref::<DictionaryArray<UInt16Type>>()?;
    let vals = d16.values().as_any().downcast_ref::<StringArray>()?;
    Some((0..vals.len()).map(|i| vals.value(i)).collect())
}

fn merge_extra_dp_attrs(
    num_dps: usize,
    existing_attrs: Option<&RecordBatch>,
    public_target: &LabelSet,
    honor_labels: bool,
    extra_dp_labels: &[(String, String)],
) -> Result<RecordBatch, DecodeError> {
    let dp_count_u32 = u32::try_from(num_dps).map_err(|_| DecodeError::CapacityOverflow {
        table: "DpAttrs",
        count: num_dps,
    })?;

    let mut key_dict_vec: Vec<String> = Vec::new();
    let mut val_dict_vec: Vec<String> = Vec::new();

    let existing_parts = if let Some(batch) = existing_attrs {
        let pids = batch
            .column_by_name("parent_id")
            .and_then(|c| c.as_any().downcast_ref::<UInt32Array>())
            .expect("DpAttrs parent_id must be UInt32Array");
        let key_col = batch.column_by_name("key").expect("DpAttrs key column");
        let val_col = batch.column_by_name("str").expect("DpAttrs str column");

        let (key_indices, raw_keys) = if let Some(d8) = key_col
            .as_any()
            .downcast_ref::<DictionaryArray<UInt8Type>>()
        {
            let vals = d8
                .values()
                .as_any()
                .downcast_ref::<StringArray>()
                .expect("key dict values StringArray");
            (
                KeyIndexSlice::U8(d8.keys().values()),
                (0..vals.len()).map(|i| vals.value(i)).collect::<Vec<_>>(),
            )
        } else if let Some(d16) = key_col
            .as_any()
            .downcast_ref::<DictionaryArray<UInt16Type>>()
        {
            let vals = d16
                .values()
                .as_any()
                .downcast_ref::<StringArray>()
                .expect("key dict values StringArray");
            (
                KeyIndexSlice::U16(d16.keys().values()),
                (0..vals.len()).map(|i| vals.value(i)).collect::<Vec<_>>(),
            )
        } else {
            unreachable!("verified dictionary-encoded key column in try_eval_batch_invariant")
        };

        let mut renamed = Vec::new();
        if resolve_conflicting_exposed_keys(&raw_keys, public_target, honor_labels, &mut renamed) {
            key_dict_vec.extend(
                raw_keys
                    .iter()
                    .enumerate()
                    .map(|(i, &orig)| renamed[i].clone().unwrap_or_else(|| orig.to_owned())),
            );
        } else {
            key_dict_vec.extend(raw_keys.iter().map(|&s| s.to_owned()));
        }

        let d16_val = val_col
            .as_any()
            .downcast_ref::<DictionaryArray<UInt16Type>>()
            .expect("verified DictU16 str column in try_eval_batch_invariant");
        let str_vals = d16_val
            .values()
            .as_any()
            .downcast_ref::<StringArray>()
            .expect("str dict values StringArray");
        val_dict_vec.extend((0..str_vals.len()).map(|i| str_vals.value(i).to_owned()));

        Some((
            pids.values().as_ref(),
            key_indices,
            d16_val.keys().values().as_ref(),
        ))
    } else {
        None
    };

    let mut extra_encoded: Vec<(u32, u32)> = Vec::with_capacity(extra_dp_labels.len());
    for (ek, ev) in extra_dp_labels {
        let key_id =
            u32::try_from(key_dict_vec.len()).map_err(|_| DecodeError::CapacityOverflow {
                table: "DpAttrs",
                count: key_dict_vec.len() + 1,
            })?;
        key_dict_vec.push(ek.clone());

        let val_id = if let Some(existing_idx) = val_dict_vec.iter().position(|s| s == ev) {
            existing_idx as u32
        } else {
            let next_id =
                u32::try_from(val_dict_vec.len()).map_err(|_| DecodeError::CapacityOverflow {
                    table: "DpAttrs",
                    count: val_dict_vec.len() + 1,
                })?;
            val_dict_vec.push(ev.clone());
            next_id
        };
        extra_encoded.push((key_id, val_id));
    }

    let existing_rows = existing_attrs.map_or(0, RecordBatch::num_rows);
    let total_rows = existing_rows
        .checked_add(num_dps.checked_mul(extra_encoded.len()).ok_or(
            DecodeError::CapacityOverflow {
                table: "DpAttrs",
                count: usize::MAX,
            },
        )?)
        .ok_or(DecodeError::CapacityOverflow {
            table: "DpAttrs",
            count: usize::MAX,
        })?;

    let mut parent_ids = Vec::with_capacity(total_rows);
    let mut pairs = Vec::with_capacity(total_rows);

    let mut cursor = 0_usize;
    for dp_id in 0..dp_count_u32 {
        if let Some((old_pids, ref old_keys, old_vals)) = existing_parts {
            while cursor < old_pids.len() && old_pids[cursor] == dp_id {
                pairs.push((old_keys.get(cursor), u32::from(old_vals[cursor])));
                parent_ids.push(dp_id);
                cursor += 1;
            }
        }
        for &(ek_id, ev_id) in &extra_encoded {
            parent_ids.push(dp_id);
            pairs.push((ek_id, ev_id));
        }
    }

    build_dp_attrs_batch(&parent_ids, &pairs, &key_dict_vec, &val_dict_vec)
}

fn build_dp_attrs_batch(
    parent_ids: &[u32],
    pairs: &[(u32, u32)],
    key_dict_vec: &[String],
    val_dict_vec: &[String],
) -> Result<RecordBatch, DecodeError> {
    let num_rows = pairs.len();
    let key_enc = if key_dict_vec.len() <= 256 {
        KeyEnc::DictU8
    } else if key_dict_vec.len() <= 65_536 {
        KeyEnc::DictU16
    } else {
        KeyEnc::Utf8
    };
    let val_enc = if val_dict_vec.len() <= 65_536 {
        ValEnc::DictU16
    } else {
        ValEnc::Utf8
    };

    let parent_id_arr: ArrayRef = Arc::new(UInt32Array::new(
        ScalarBuffer::from(parent_ids.to_vec()),
        None,
    ));

    let key_arr: ArrayRef = match key_enc {
        KeyEnc::DictU8 => {
            let keys: Vec<u8> = pairs.iter().map(|&(k, _)| k as u8).collect();
            let dict: ArrayRef = Arc::new(StringArray::from_iter_values(
                key_dict_vec.iter().map(String::as_str),
            ));
            Arc::new(DictionaryArray::<UInt8Type>::new(
                UInt8Array::new(ScalarBuffer::from(keys), None),
                dict,
            ))
        }
        KeyEnc::DictU16 => {
            let keys: Vec<u16> = pairs.iter().map(|&(k, _)| k as u16).collect();
            let dict: ArrayRef = Arc::new(StringArray::from_iter_values(
                key_dict_vec.iter().map(String::as_str),
            ));
            Arc::new(DictionaryArray::<UInt16Type>::new(
                UInt16Array::new(ScalarBuffer::from(keys), None),
                dict,
            ))
        }
        KeyEnc::Utf8 => Arc::new(StringArray::from_iter_values(
            pairs
                .iter()
                .map(|&(k, _)| key_dict_vec[k as usize].as_str()),
        )),
    };

    let type_arr: ArrayRef = Arc::new(UInt8Array::new(
        ScalarBuffer::from(vec![ATTR_VALUE_TYPE_STR; num_rows]),
        None,
    ));

    let val_arr: ArrayRef = match val_enc {
        ValEnc::DictU16 => {
            let keys: Vec<u16> = pairs.iter().map(|&(_, v)| v as u16).collect();
            let dict: ArrayRef = Arc::new(StringArray::from_iter_values(
                val_dict_vec.iter().map(String::as_str),
            ));
            Arc::new(DictionaryArray::<UInt16Type>::new(
                UInt16Array::new(ScalarBuffer::from(keys), None),
                dict,
            ))
        }
        ValEnc::Utf8 => Arc::new(StringArray::from_iter_values(
            pairs
                .iter()
                .map(|&(_, v)| val_dict_vec[v as usize].as_str()),
        )),
    };

    Ok(RecordBatch::try_new(
        dp_attrs_schema(key_enc, val_enc),
        vec![parent_id_arr, key_arr, type_arr, val_arr],
    )?)
}

fn ensure_dp_id_column(batch: &RecordBatch, need_id: bool) -> Result<RecordBatch, DecodeError> {
    let schema = batch.schema();
    let has_id = schema.index_of("id").is_ok();
    if has_id == need_id {
        return Ok(batch.clone());
    }
    let num_rows = batch.num_rows();
    if need_id {
        let id_count = u32::try_from(num_rows).map_err(|_| DecodeError::CapacityOverflow {
            table: "DataPoints",
            count: num_rows,
        })?;
        let ids: Vec<u32> = (0..id_count).collect();
        let id_arr: ArrayRef = Arc::new(UInt32Array::new(ScalarBuffer::from(ids), None));

        let mut fields = Vec::with_capacity(schema.fields().len() + 1);
        fields.push(Arc::new(
            Field::new("id", DataType::UInt32, false).with_metadata(plain_id_metadata()),
        ));
        fields.extend(schema.fields().iter().cloned());

        let mut cols = Vec::with_capacity(batch.num_columns() + 1);
        cols.push(id_arr);
        cols.extend(batch.columns().iter().cloned());

        Ok(RecordBatch::try_new(Arc::new(Schema::new(fields)), cols)?)
    } else {
        let id_idx = schema.index_of("id").expect("checked has_id");
        let fields: Vec<_> = schema
            .fields()
            .iter()
            .enumerate()
            .filter(|&(i, _)| i != id_idx)
            .map(|(_, f)| Arc::clone(f))
            .collect();
        let cols: Vec<_> = batch
            .columns()
            .iter()
            .enumerate()
            .filter(|&(i, _)| i != id_idx)
            .map(|(_, c)| Arc::clone(c))
            .collect();
        Ok(RecordBatch::try_new(Arc::new(Schema::new(fields)), cols)?)
    }
}

#[derive(Clone)]
struct MetricDescriptorRow {
    metric_type: u8,
    name: String,
    description: Option<String>,
    unit: Option<String>,
    aggregation_temporality: Option<i32>,
    is_monotonic: Option<bool>,
    prom_type_attr: Option<String>,
}

struct StringInternMap {
    map: HashMap<String, u32>,
    values: Vec<String>,
}

impl StringInternMap {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
            values: Vec::new(),
        }
    }

    fn intern(&mut self, s: &str) -> Result<u32, DecodeError> {
        if let Some(&id) = self.map.get(s) {
            return Ok(id);
        }
        let id = u32::try_from(self.values.len()).map_err(|_| DecodeError::CapacityOverflow {
            table: "DpAttrs",
            count: self.values.len() + 1,
        })?;
        let owned = s.to_owned();
        self.values.push(owned.clone());
        self.map.insert(owned, id);
        Ok(id)
    }
}

fn apply_per_datapoint_relabel(
    mut records: OtapMetricRecords,
    public_target: &LabelSet,
    honor_labels: bool,
    metric_relabel_configs: &[RelabelConfig],
) -> Result<OtapMetricRecords, DecodeError> {
    let Some(metrics_batch) = records.univariate_metrics().cloned() else {
        return Ok(records);
    };

    let mut descriptors = extract_metric_descriptors(&metrics_batch, records.metric_attrs());
    let orig_metric_count = descriptors.len();
    let mut renamed_metric_slots: HashMap<(usize, String), usize> = HashMap::new();
    let mut metric_ref_counts = vec![0_usize; orig_metric_count];

    struct RelabeledTable {
        dp_kind: MetricPayloadType,
        attrs_kind: MetricPayloadType,
        exemplars_kinds: Option<(MetricPayloadType, MetricPayloadType)>,
        kept_indices: Vec<usize>,
        metric_slots: Vec<usize>,
        attr_parent_ids: Vec<u32>,
        attr_pairs: Vec<(u32, u32)>,
        key_interner: StringInternMap,
        val_interner: StringInternMap,
    }

    let mut tables = Vec::with_capacity(3);
    let mut sample_labels = LabelSet::new();

    for &(dp_kind, attrs_kind, exemplars_kinds) in &DP_TABLE_TRIPLES {
        let Some(dp_batch) = records.get(dp_kind) else {
            continue;
        };
        let num_dps = dp_batch.num_rows();
        let parent_ids = dp_batch
            .column_by_name("parent_id")
            .and_then(|c| c.as_any().downcast_ref::<UInt16Array>())
            .expect("DataPoints parent_id must be UInt16Array");

        let attrs_reader = records.get(attrs_kind).map(DecodedAttrsView::new);
        let mut attr_cursor = 0_usize;

        let mut kept_indices = Vec::with_capacity(num_dps);
        let mut metric_slots = Vec::with_capacity(num_dps);
        let mut attr_parent_ids = Vec::new();
        let mut attr_pairs = Vec::new();
        let mut key_interner = StringInternMap::new();
        let mut val_interner = StringInternMap::new();

        for dp_idx in 0..num_dps {
            sample_labels.clear();
            let dp_id_u32 = dp_idx as u32;
            if let Some(ref view) = attrs_reader {
                while attr_cursor < view.len() && view.parent_id(attr_cursor) == dp_id_u32 {
                    let k = view.key(attr_cursor);
                    let v = view.val(attr_cursor);
                    if !v.is_empty() {
                        sample_labels.insert(k.to_owned(), v.to_owned());
                    }
                    attr_cursor += 1;
                }
            }

            merge_target_and_metric_labels(&mut sample_labels, public_target, honor_labels);
            let orig_slot = usize::from(parent_ids.value(dp_idx));
            let orig_name = descriptors[orig_slot].name.clone();
            sample_labels.insert(METRIC_NAME_LABEL.to_owned(), orig_name.clone());

            if !process_in_place(&mut sample_labels, metric_relabel_configs) {
                continue;
            }
            let Some(final_name) = sample_labels.remove(METRIC_NAME_LABEL) else {
                continue;
            };
            if final_name.is_empty() {
                continue;
            }

            let target_slot = if final_name == orig_name {
                orig_slot
            } else if let Some(&existing_slot) =
                renamed_metric_slots.get(&(orig_slot, final_name.clone()))
            {
                existing_slot
            } else {
                let mut cloned = descriptors[orig_slot].clone();
                cloned.name = final_name.clone();
                let new_slot = descriptors.len();
                descriptors.push(cloned);
                metric_ref_counts.push(0);
                renamed_metric_slots.insert((orig_slot, final_name), new_slot);
                new_slot
            };

            metric_ref_counts[target_slot] += 1;
            let new_dp_id =
                u32::try_from(kept_indices.len()).map_err(|_| DecodeError::CapacityOverflow {
                    table: "DataPoints",
                    count: kept_indices.len() + 1,
                })?;
            kept_indices.push(dp_idx);
            metric_slots.push(target_slot);

            for (k, v) in &sample_labels {
                if k.starts_with(RESERVED_LABEL_PREFIX)
                    || v.is_empty()
                    || public_target.get(k) == Some(v)
                {
                    continue;
                }
                let kid = key_interner.intern(k)?;
                let vid = val_interner.intern(v)?;
                attr_parent_ids.push(new_dp_id);
                attr_pairs.push((kid, vid));
            }
        }

        tables.push(RelabeledTable {
            dp_kind,
            attrs_kind,
            exemplars_kinds,
            kept_indices,
            metric_slots,
            attr_parent_ids,
            attr_pairs,
            key_interner,
            val_interner,
        });
    }

    if tables.iter().all(|t| t.kept_indices.is_empty()) {
        return Ok(OtapMetricRecords::default());
    }

    // Assign dense `0..M'` `u16` IDs to referenced metric descriptors.
    let mut slot_to_new_metric_id: Vec<Option<u16>> = vec![None; descriptors.len()];
    let mut kept_descriptors: Vec<&MetricDescriptorRow> = Vec::new();
    for (slot, &count) in metric_ref_counts.iter().enumerate() {
        if count > 0 {
            let new_id = u16::try_from(kept_descriptors.len()).map_err(|_| {
                DecodeError::CapacityOverflow {
                    table: "UnivariateMetrics",
                    count: kept_descriptors.len() + 1,
                }
            })?;
            slot_to_new_metric_id[slot] = Some(new_id);
            kept_descriptors.push(&descriptors[slot]);
        }
    }

    let metrics_unchanged = kept_descriptors.len() == orig_metric_count
        && descriptors.len() == orig_metric_count
        && (0..orig_metric_count).all(|i| slot_to_new_metric_id[i] == Some(i as u16));

    if !metrics_unchanged {
        let (new_metrics, new_metric_attrs) = build_metric_batches(&kept_descriptors)?;
        records.set(MetricPayloadType::UnivariateMetrics, Some(new_metrics));
        records.set(MetricPayloadType::MetricAttrs, new_metric_attrs);
    }

    for table in tables {
        let orig_dp = records
            .get(table.dp_kind)
            .cloned()
            .expect("table came from present dp_kind");

        if table.kept_indices.is_empty() {
            records.set(table.dp_kind, None);
            records.set(table.attrs_kind, None);
            if let Some((ex_kind, ex_attrs_kind)) = table.exemplars_kinds {
                records.set(ex_kind, None);
                records.set(ex_attrs_kind, None);
            }
            continue;
        }

        let new_dp_attrs = if table.attr_pairs.is_empty() {
            None
        } else {
            Some(build_dp_attrs_batch(
                &table.attr_parent_ids,
                &table.attr_pairs,
                &table.key_interner.values,
                &table.val_interner.values,
            )?)
        };

        let all_dps_kept = table.kept_indices.len() == orig_dp.num_rows();
        let remapped_parent_ids: Vec<u16> = table
            .metric_slots
            .iter()
            .map(|&slot| slot_to_new_metric_id[slot].expect("referenced metric slot"))
            .collect();

        let has_exemplars = if let Some((ex_kind, ex_attrs_kind)) = table.exemplars_kinds {
            if all_dps_kept {
                records.get(ex_kind).is_some()
            } else {
                let (new_ex, new_ex_attrs) = filter_exemplar_tables(
                    records.get(ex_kind),
                    records.get(ex_attrs_kind),
                    orig_dp.num_rows(),
                    &table.kept_indices,
                )?;
                let present = new_ex.is_some();
                records.set(ex_kind, new_ex);
                records.set(ex_attrs_kind, new_ex_attrs);
                present
            }
        } else {
            false
        };

        let need_id = new_dp_attrs.is_some() || has_exemplars;
        let filtered_dp = if all_dps_kept && metrics_unchanged {
            ensure_dp_id_column(&orig_dp, need_id)?
        } else {
            let sliced = if all_dps_kept {
                orig_dp
            } else {
                take_record_batch(&orig_dp, &table.kept_indices)?
            };
            let with_parents = replace_u16_parent_id(&sliced, &remapped_parent_ids)?;
            let with_id = ensure_dp_id_column(&with_parents, need_id)?;
            if need_id {
                renumber_u32_id_column(&with_id)?
            } else {
                with_id
            }
        };

        records.set(table.dp_kind, Some(filtered_dp));
        records.set(table.attrs_kind, new_dp_attrs);
    }

    Ok(records)
}

enum StrColView<'a> {
    DictU8(&'a DictionaryArray<UInt8Type>, &'a StringArray),
    DictU16(&'a DictionaryArray<UInt16Type>, &'a StringArray),
    Plain(&'a StringArray),
}

impl<'a> StrColView<'a> {
    fn from_array(col: &'a ArrayRef) -> Self {
        if let Some(d8) = col.as_any().downcast_ref::<DictionaryArray<UInt8Type>>() {
            let vals = d8
                .values()
                .as_any()
                .downcast_ref::<StringArray>()
                .expect("DictU8 StringArray");
            Self::DictU8(d8, vals)
        } else if let Some(d16) = col.as_any().downcast_ref::<DictionaryArray<UInt16Type>>() {
            let vals = d16
                .values()
                .as_any()
                .downcast_ref::<StringArray>()
                .expect("DictU16 StringArray");
            Self::DictU16(d16, vals)
        } else {
            let plain = col
                .as_any()
                .downcast_ref::<StringArray>()
                .expect("Utf8 StringArray");
            Self::Plain(plain)
        }
    }

    fn value(&self, row: usize) -> &'a str {
        match self {
            Self::DictU8(d, vals) => vals.value(usize::from(d.keys().value(row))),
            Self::DictU16(d, vals) => vals.value(usize::from(d.keys().value(row))),
            Self::Plain(s) => s.value(row),
        }
    }
}

struct DecodedAttrsView<'a> {
    parent_ids: &'a UInt32Array,
    keys: StrColView<'a>,
    vals: StrColView<'a>,
}

impl<'a> DecodedAttrsView<'a> {
    fn new(batch: &'a RecordBatch) -> Self {
        let parent_ids = batch
            .column_by_name("parent_id")
            .and_then(|c| c.as_any().downcast_ref::<UInt32Array>())
            .expect("Attrs parent_id UInt32Array");
        let keys = StrColView::from_array(batch.column_by_name("key").expect("Attrs key"));
        let vals = StrColView::from_array(batch.column_by_name("str").expect("Attrs str"));
        Self {
            parent_ids,
            keys,
            vals,
        }
    }

    fn len(&self) -> usize {
        self.parent_ids.len()
    }

    fn parent_id(&self, row: usize) -> u32 {
        self.parent_ids.value(row)
    }

    fn key(&self, row: usize) -> &'a str {
        self.keys.value(row)
    }

    fn val(&self, row: usize) -> &'a str {
        self.vals.value(row)
    }
}

fn extract_metric_descriptors(
    metrics: &RecordBatch,
    metric_attrs: Option<&RecordBatch>,
) -> Vec<MetricDescriptorRow> {
    let n = metrics.num_rows();
    let types = metrics
        .column_by_name("metric_type")
        .and_then(|c| c.as_any().downcast_ref::<UInt8Array>())
        .expect("UnivariateMetrics metric_type");
    let names = metrics
        .column_by_name("name")
        .and_then(|c| c.as_any().downcast_ref::<StringArray>())
        .expect("UnivariateMetrics name");
    let descriptions = metrics
        .column_by_name("description")
        .and_then(|c| c.as_any().downcast_ref::<StringArray>());
    let units = metrics
        .column_by_name("unit")
        .and_then(|c| c.as_any().downcast_ref::<StringArray>());
    let temporalities = metrics
        .column_by_name("aggregation_temporality")
        .and_then(|c| c.as_any().downcast_ref::<Int32Array>());
    let monotonics = metrics
        .column_by_name("is_monotonic")
        .and_then(|c| c.as_any().downcast_ref::<BooleanArray>());

    let mut prom_types = vec![None; n];
    if let Some(ma) = metric_attrs {
        let pids = ma
            .column_by_name("parent_id")
            .and_then(|c| c.as_any().downcast_ref::<UInt16Array>())
            .expect("MetricAttrs parent_id");
        let vals = StrColView::from_array(ma.column_by_name("str").expect("MetricAttrs str"));
        for row in 0..ma.num_rows() {
            let pid = usize::from(pids.value(row));
            if pid < n {
                prom_types[pid] = Some(vals.value(row).to_owned());
            }
        }
    }

    (0..n)
        .map(|i| MetricDescriptorRow {
            metric_type: types.value(i),
            name: names.value(i).to_owned(),
            description: descriptions
                .filter(|c| !c.is_null(i))
                .map(|c| c.value(i).to_owned()),
            unit: units
                .filter(|c| !c.is_null(i))
                .map(|c| c.value(i).to_owned()),
            aggregation_temporality: temporalities.filter(|c| !c.is_null(i)).map(|c| c.value(i)),
            is_monotonic: monotonics.filter(|c| !c.is_null(i)).map(|c| c.value(i)),
            prom_type_attr: prom_types[i].clone(),
        })
        .collect()
}

fn build_metric_batches(
    rows: &[&MetricDescriptorRow],
) -> Result<(RecordBatch, Option<RecordBatch>), DecodeError> {
    let n = rows.len();
    let has_desc = rows.iter().any(|r| r.description.is_some());
    let has_unit = rows.iter().any(|r| r.unit.is_some());
    let has_temp = rows.iter().any(|r| r.aggregation_temporality.is_some());
    let has_mono = rows.iter().any(|r| r.is_monotonic.is_some());

    let res_fields = Fields::from(vec![
        Field::new("id", DataType::UInt16, false).with_metadata(plain_id_metadata()),
    ]);
    let mut fields = vec![
        Field::new("id", DataType::UInt16, false).with_metadata(plain_id_metadata()),
        Field::new("resource", DataType::Struct(res_fields.clone()), false),
        Field::new("metric_type", DataType::UInt8, false),
        Field::new("name", DataType::Utf8, false),
    ];
    if has_desc {
        fields.push(Field::new("description", DataType::Utf8, true));
    }
    if has_unit {
        fields.push(Field::new("unit", DataType::Utf8, true));
    }
    if has_temp {
        fields.push(Field::new("aggregation_temporality", DataType::Int32, true));
    }
    if has_mono {
        fields.push(Field::new("is_monotonic", DataType::Boolean, true));
    }

    let ids: Vec<u16> = (0..n as u16).collect();
    let res_ids: ArrayRef = Arc::new(UInt16Array::new(ScalarBuffer::from(vec![0_u16; n]), None));
    let res_struct: ArrayRef = Arc::new(StructArray::new(res_fields, vec![res_ids], None));
    let mtypes: Vec<u8> = rows.iter().map(|r| r.metric_type).collect();

    let mut cols: Vec<ArrayRef> = vec![
        Arc::new(UInt16Array::new(ScalarBuffer::from(ids.clone()), None)),
        res_struct,
        Arc::new(UInt8Array::new(ScalarBuffer::from(mtypes), None)),
        Arc::new(StringArray::from_iter_values(
            rows.iter().map(|r| r.name.as_str()),
        )),
    ];
    if has_desc {
        cols.push(Arc::new(StringArray::from_iter(
            rows.iter().map(|r| r.description.as_deref()),
        )));
    }
    if has_unit {
        cols.push(Arc::new(StringArray::from_iter(
            rows.iter().map(|r| r.unit.as_deref()),
        )));
    }
    if has_temp {
        let all_temp = rows.iter().all(|r| r.aggregation_temporality.is_some());
        let vals: Vec<i32> = rows
            .iter()
            .map(|r| {
                r.aggregation_temporality.unwrap_or(
                    if r.metric_type == OTAP_METRIC_TYPE_SUM
                        || r.metric_type == OTAP_METRIC_TYPE_HISTOGRAM
                    {
                        AGGREGATION_TEMPORALITY_CUMULATIVE
                    } else {
                        0
                    },
                )
            })
            .collect();
        let nulls = (!all_temp).then(|| {
            NullBuffer::new(BooleanBuffer::from_iter(
                rows.iter().map(|r| r.aggregation_temporality.is_some()),
            ))
        });
        cols.push(Arc::new(Int32Array::new(ScalarBuffer::from(vals), nulls)));
    }
    if has_mono {
        let all_mono = rows.iter().all(|r| r.is_monotonic.is_some());
        let vals = BooleanBuffer::from_iter(rows.iter().map(|r| r.is_monotonic.unwrap_or(false)));
        let nulls = (!all_mono).then(|| {
            NullBuffer::new(BooleanBuffer::from_iter(
                rows.iter().map(|r| r.is_monotonic.is_some()),
            ))
        });
        cols.push(Arc::new(BooleanArray::new(vals, nulls)));
    }

    let metrics_batch = RecordBatch::try_new(Arc::new(Schema::new(fields)), cols)?;

    let mut ma_pids = Vec::new();
    let mut ma_val_interner = StringInternMap::new();
    let mut ma_val_ids = Vec::new();
    for (idx, r) in rows.iter().enumerate() {
        if let Some(ref ptype) = r.prom_type_attr {
            ma_pids.push(idx as u16);
            ma_val_ids.push(ma_val_interner.intern(ptype)? as u16);
        }
    }
    let metric_attrs_batch = if ma_pids.is_empty() {
        None
    } else {
        let schema = Arc::new(Schema::new(vec![
            Field::new("parent_id", DataType::UInt16, false).with_metadata(plain_id_metadata()),
            Field::new(
                "key",
                DataType::Dictionary(Box::new(DataType::UInt8), Box::new(DataType::Utf8)),
                false,
            ),
            Field::new("type", DataType::UInt8, false),
            Field::new(
                "str",
                DataType::Dictionary(Box::new(DataType::UInt16), Box::new(DataType::Utf8)),
                true,
            ),
        ]));
        let m_len = ma_pids.len();
        let key_dict: ArrayRef = Arc::new(StringArray::from(vec!["prometheus.type"]));
        let key_col: ArrayRef = Arc::new(DictionaryArray::<UInt8Type>::new(
            UInt8Array::new(ScalarBuffer::from(vec![0_u8; m_len]), None),
            key_dict,
        ));
        let val_dict: ArrayRef = Arc::new(StringArray::from_iter_values(
            ma_val_interner.values.iter().map(String::as_str),
        ));
        let val_col: ArrayRef = Arc::new(DictionaryArray::<UInt16Type>::new(
            UInt16Array::new(ScalarBuffer::from(ma_val_ids), None),
            val_dict,
        ));
        Some(RecordBatch::try_new(
            schema,
            vec![
                Arc::new(UInt16Array::new(ScalarBuffer::from(ma_pids), None)),
                key_col,
                Arc::new(UInt8Array::new(
                    ScalarBuffer::from(vec![ATTR_VALUE_TYPE_STR; m_len]),
                    None,
                )),
                val_col,
            ],
        )?)
    };

    Ok((metrics_batch, metric_attrs_batch))
}

fn filter_exemplar_tables(
    exemplars: Option<&RecordBatch>,
    exemplar_attrs: Option<&RecordBatch>,
    orig_num_dps: usize,
    kept_dp_indices: &[usize],
) -> Result<(Option<RecordBatch>, Option<RecordBatch>), DecodeError> {
    let Some(ex_batch) = exemplars else {
        return Ok((None, None));
    };
    let mut old_dp_to_new: Vec<Option<u32>> = vec![None; orig_num_dps];
    for (new_idx, &old_idx) in kept_dp_indices.iter().enumerate() {
        old_dp_to_new[old_idx] = Some(new_idx as u32);
    }

    let ex_pids = ex_batch
        .column_by_name("parent_id")
        .and_then(|c| c.as_any().downcast_ref::<UInt32Array>())
        .expect("Exemplars parent_id");

    let mut kept_ex_indices = Vec::new();
    let mut new_ex_pids = Vec::new();
    let mut old_ex_to_new: Vec<Option<u32>> = vec![None; ex_batch.num_rows()];

    for (ex_idx, slot) in old_ex_to_new.iter_mut().enumerate() {
        let old_dp = ex_pids.value(ex_idx) as usize;
        if let Some(Some(new_dp)) = old_dp_to_new.get(old_dp).copied() {
            let new_ex_id = kept_ex_indices.len() as u32;
            *slot = Some(new_ex_id);
            kept_ex_indices.push(ex_idx);
            new_ex_pids.push(new_dp);
        }
    }

    if kept_ex_indices.is_empty() {
        return Ok((None, None));
    }

    let new_ex_attrs = if let Some(exa_batch) = exemplar_attrs {
        let exa_pids = exa_batch
            .column_by_name("parent_id")
            .and_then(|c| c.as_any().downcast_ref::<UInt32Array>())
            .expect("ExemplarAttrs parent_id");
        let mut kept_exa_indices = Vec::new();
        let mut new_exa_pids = Vec::new();
        for i in 0..exa_batch.num_rows() {
            let old_ex = exa_pids.value(i) as usize;
            if let Some(Some(new_ex)) = old_ex_to_new.get(old_ex).copied() {
                kept_exa_indices.push(i);
                new_exa_pids.push(new_ex);
            }
        }
        if kept_exa_indices.is_empty() {
            None
        } else {
            let sliced = take_record_batch(exa_batch, &kept_exa_indices)?;
            Some(replace_u32_parent_id(&sliced, &new_exa_pids)?)
        }
    } else {
        None
    };

    let sliced_ex = take_record_batch(ex_batch, &kept_ex_indices)?;
    let with_pids = replace_u32_parent_id(&sliced_ex, &new_ex_pids)?;
    let with_id = ensure_dp_id_column(&with_pids, new_ex_attrs.is_some())?;
    let final_ex = if new_ex_attrs.is_some() {
        renumber_u32_id_column(&with_id)?
    } else {
        with_id
    };

    Ok((Some(final_ex), new_ex_attrs))
}

fn replace_u16_parent_id(
    batch: &RecordBatch,
    new_parent_ids: &[u16],
) -> Result<RecordBatch, DecodeError> {
    let schema = batch.schema();
    let idx = schema
        .index_of("parent_id")
        .expect("DataPoints has parent_id");
    let mut cols = batch.columns().to_vec();
    cols[idx] = Arc::new(UInt16Array::new(
        ScalarBuffer::from(new_parent_ids.to_vec()),
        None,
    ));
    Ok(RecordBatch::try_new(schema, cols)?)
}

fn replace_u32_parent_id(
    batch: &RecordBatch,
    new_parent_ids: &[u32],
) -> Result<RecordBatch, DecodeError> {
    let schema = batch.schema();
    let idx = schema.index_of("parent_id").expect("Batch has parent_id");
    let mut cols = batch.columns().to_vec();
    cols[idx] = Arc::new(UInt32Array::new(
        ScalarBuffer::from(new_parent_ids.to_vec()),
        None,
    ));
    Ok(RecordBatch::try_new(schema, cols)?)
}

fn renumber_u32_id_column(batch: &RecordBatch) -> Result<RecordBatch, DecodeError> {
    let schema = batch.schema();
    let Ok(idx) = schema.index_of("id") else {
        return Ok(batch.clone());
    };
    let ids: Vec<u32> = (0..batch.num_rows() as u32).collect();
    let mut cols = batch.columns().to_vec();
    cols[idx] = Arc::new(UInt32Array::new(ScalarBuffer::from(ids), None));
    Ok(RecordBatch::try_new(schema, cols)?)
}

fn take_record_batch(batch: &RecordBatch, indices: &[usize]) -> Result<RecordBatch, DecodeError> {
    let cols: Result<Vec<ArrayRef>, DecodeError> = batch
        .columns()
        .iter()
        .map(|col| take_array(col, indices))
        .collect();
    Ok(RecordBatch::try_new(batch.schema(), cols?)?)
}

fn take_nulls(arr: &dyn Array, indices: &[usize]) -> Option<NullBuffer> {
    (arr.null_count() > 0).then(|| {
        NullBuffer::new(BooleanBuffer::from_iter(
            indices.iter().map(|&i| !arr.is_null(i)),
        ))
    })
}

fn take_array(col: &ArrayRef, indices: &[usize]) -> Result<ArrayRef, DecodeError> {
    let nulls = take_nulls(col.as_ref(), indices);
    let out: ArrayRef = match col.data_type() {
        DataType::UInt8 => {
            let a = col.as_any().downcast_ref::<UInt8Array>().expect("UInt8");
            let vals: Vec<u8> = indices.iter().map(|&i| a.value(i)).collect();
            Arc::new(UInt8Array::new(ScalarBuffer::from(vals), nulls))
        }
        DataType::UInt16 => {
            let a = col.as_any().downcast_ref::<UInt16Array>().expect("UInt16");
            let vals: Vec<u16> = indices.iter().map(|&i| a.value(i)).collect();
            Arc::new(UInt16Array::new(ScalarBuffer::from(vals), nulls))
        }
        DataType::UInt32 => {
            let a = col.as_any().downcast_ref::<UInt32Array>().expect("UInt32");
            let vals: Vec<u32> = indices.iter().map(|&i| a.value(i)).collect();
            Arc::new(UInt32Array::new(ScalarBuffer::from(vals), nulls))
        }
        DataType::UInt64 => {
            let a = col.as_any().downcast_ref::<UInt64Array>().expect("UInt64");
            let vals: Vec<u64> = indices.iter().map(|&i| a.value(i)).collect();
            Arc::new(UInt64Array::new(ScalarBuffer::from(vals), nulls))
        }
        DataType::Int32 => {
            let a = col.as_any().downcast_ref::<Int32Array>().expect("Int32");
            let vals: Vec<i32> = indices.iter().map(|&i| a.value(i)).collect();
            Arc::new(Int32Array::new(ScalarBuffer::from(vals), nulls))
        }
        DataType::Float64 => {
            let a = col
                .as_any()
                .downcast_ref::<Float64Array>()
                .expect("Float64");
            let vals: Vec<f64> = indices.iter().map(|&i| a.value(i)).collect();
            Arc::new(Float64Array::new(ScalarBuffer::from(vals), nulls))
        }
        DataType::Boolean => {
            let a = col
                .as_any()
                .downcast_ref::<BooleanArray>()
                .expect("Boolean");
            let vals = BooleanBuffer::from_iter(indices.iter().map(|&i| a.value(i)));
            Arc::new(BooleanArray::new(vals, nulls))
        }
        DataType::Timestamp(TimeUnit::Nanosecond, _) => {
            let a = col
                .as_any()
                .downcast_ref::<TimestampNanosecondArray>()
                .expect("TimestampNanosecond");
            let vals: Vec<i64> = indices.iter().map(|&i| a.value(i)).collect();
            Arc::new(
                TimestampNanosecondArray::new(ScalarBuffer::from(vals), nulls)
                    .with_timezone(UTC_TIME_ZONE),
            )
        }
        DataType::Utf8 => {
            let a = col.as_any().downcast_ref::<StringArray>().expect("Utf8");
            Arc::new(StringArray::from_iter(
                indices
                    .iter()
                    .map(|&i| if a.is_null(i) { None } else { Some(a.value(i)) }),
            ))
        }
        DataType::FixedSizeBinary(width) => {
            let a = col
                .as_any()
                .downcast_ref::<FixedSizeBinaryArray>()
                .expect("FixedSizeBinary");
            let w = *width as usize;
            let mut buf = Vec::with_capacity(indices.len() * w);
            for &i in indices {
                buf.extend_from_slice(a.value(i));
            }
            Arc::new(FixedSizeBinaryArray::try_new(
                *width,
                Buffer::from_vec(buf),
                nulls,
            )?)
        }
        DataType::Dictionary(k, _) if k.as_ref() == &DataType::UInt8 => {
            let a = col
                .as_any()
                .downcast_ref::<DictionaryArray<UInt8Type>>()
                .expect("DictU8");
            let keys: Vec<u8> = indices.iter().map(|&i| a.keys().value(i)).collect();
            Arc::new(DictionaryArray::<UInt8Type>::new(
                UInt8Array::new(ScalarBuffer::from(keys), nulls),
                Arc::clone(a.values()),
            ))
        }
        DataType::Dictionary(k, _) if k.as_ref() == &DataType::UInt16 => {
            let a = col
                .as_any()
                .downcast_ref::<DictionaryArray<UInt16Type>>()
                .expect("DictU16");
            let keys: Vec<u16> = indices.iter().map(|&i| a.keys().value(i)).collect();
            Arc::new(DictionaryArray::<UInt16Type>::new(
                UInt16Array::new(ScalarBuffer::from(keys), nulls),
                Arc::clone(a.values()),
            ))
        }
        DataType::Struct(fields) => {
            let a = col.as_any().downcast_ref::<StructArray>().expect("Struct");
            let child_cols: Result<Vec<ArrayRef>, DecodeError> =
                a.columns().iter().map(|c| take_array(c, indices)).collect();
            Arc::new(StructArray::new(fields.clone(), child_cols?, nulls))
        }
        DataType::List(item_field) => {
            let a = col.as_any().downcast_ref::<ListArray>().expect("List");
            let old_offsets = a.value_offsets();
            let mut child_indices = Vec::new();
            let mut new_offsets = Vec::with_capacity(indices.len() + 1);
            new_offsets.push(0_i32);
            for &i in indices {
                let start = old_offsets[i] as usize;
                let end = old_offsets[i + 1] as usize;
                child_indices.extend(start..end);
                let next_off = i32::try_from(child_indices.len()).map_err(|_| {
                    DecodeError::CapacityOverflow {
                        table: "DataPoints",
                        count: child_indices.len(),
                    }
                })?;
                new_offsets.push(next_off);
            }
            let child_arr = take_array(a.values(), &child_indices)?;
            Arc::new(ListArray::try_new(
                Arc::clone(item_field),
                OffsetBuffer::new(ScalarBuffer::from(new_offsets)),
                child_arr,
                nulls,
            )?)
        }
        other => unreachable!("unexpected OTAP column DataType: {other:?}"),
    };
    Ok(out)
}
