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

//! Stage 1 (`__name__` pushdown) and Stage 2 (dictionary-vectorized `honor_labels` and
//! `metric_relabel_configs`) execution for [`super::ArrowDecoder`].

use std::collections::{BTreeMap, HashMap};

use arrow_array::RecordBatch;
use prometheus_relabel::{
    Action, Config, DictionaryValueTransform, LabelSet, METRIC_NAME_LABEL, RelabelError,
    SingleLabelKeepCache, SingleLabelTransformCache, ValidationScheme, eval_key_keep_mask_iter,
    resolve_conflicting_exposed_keys_iter, split_metric_name_pushdown,
};

use super::columns::{
    AttrTable, HistogramDpTable, MetricTable, NumberDpTable, SummaryDpTable,
    build_resource_attrs_batch,
};
use super::intern::StringInterner;
use super::options::{DecodeError, DecodeOptions, TargetAttributes, resolve_resource_attributes};

/// Pre-compiled Prometheus `metric_relabel_configs` plan shared across scrapes and streaming
/// chunks via `Arc<MetricRelabelPlan>`.
///
/// Splits rules once via [`prometheus_relabel::split_metric_name_pushdown`] into:
/// - **Stage 1** (`stage1_configs`): leading `__name__`-only `keep`, `drop`, `keepequal`, and
///   `dropequal` filters evaluated once per contiguous wire series-name transition before label
///   unescaping, string interning, or family assembly.
/// - **Stage 2** (`stage2_configs`): remaining rules executed after family assembly and string
///   interning, using dictionary-vectorized fast paths for `labeldrop`, `labelkeep`, and
///   single-label `keep`/`drop`/`replace`/`lowercase`/`uppercase`/`hashmod` rules and falling back
///   to exact per-data-point [`prometheus_relabel::process_in_place`] for general rules.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MetricRelabelPlan {
    configs: Vec<Config>,
    stage1_len: usize,
}

impl MetricRelabelPlan {
    /// Compiles `configs` into a two-stage [`MetricRelabelPlan`].
    #[must_use]
    pub fn new(configs: Vec<Config>) -> Self {
        let stage1_len = split_metric_name_pushdown(&configs).0.len();
        Self {
            configs,
            stage1_len,
        }
    }

    /// Validates every rule in `configs` against `default_scheme` and compiles a
    /// [`MetricRelabelPlan`].
    ///
    /// # Errors
    ///
    /// Returns [`RelabelError`] if any rule fails [`Config::validate`].
    pub fn try_new(
        mut configs: Vec<Config>,
        default_scheme: ValidationScheme,
    ) -> Result<Self, RelabelError> {
        for cfg in &mut configs {
            cfg.validate(default_scheme)?;
        }
        Ok(Self::new(configs))
    }

    /// Returns all configured `metric_relabel_configs` rules in evaluation order.
    #[must_use]
    pub fn configs(&self) -> &[Config] {
        &self.configs
    }

    /// Returns the leading Stage 1 `__name__`-only filter prefix pushed down into ingestion.
    #[must_use]
    pub fn stage1_configs(&self) -> &[Config] {
        &self.configs[..self.stage1_len]
    }

    /// Returns the remaining Stage 2 rules evaluated at batch finalization.
    #[must_use]
    pub fn stage2_configs(&self) -> &[Config] {
        &self.configs[self.stage1_len..]
    }

    /// Returns `true` when no relabeling rules are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.configs.is_empty()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CachedValAction {
    Uncomputed,
    KeepExisting,
    Delete,
    Set(u32),
}

/// Reusable scratch buffers for Stage 2 dictionary-vectorized relabeling and general fallback,
/// keeping steady-state scrapes free of repeat heap allocations.
#[derive(Default)]
pub(super) struct Stage2Scratch {
    renamed_keys: Vec<Option<String>>,
    remapped_key_ids: Vec<u32>,
    key_keep_mask: Vec<bool>,
    keep_cache: SingleLabelKeepCache,
    xform_cache: SingleLabelTransformCache,
    mapped_val_actions: Vec<CachedValAction>,
    dp_keep: Vec<bool>,
    dp_remap: Vec<u32>,
    ex_keep: Vec<bool>,
    ex_remap: Vec<u32>,
    metric_used: Vec<bool>,
    metric_remap: Vec<u16>,
    tmp_parent_ids: Vec<u32>,
    tmp_pairs: Vec<(u32, u32)>,
    tmp_str: String,
    effective_target_labels: BTreeMap<String, String>,
    scalar_work: LabelSet,
}

impl Stage2Scratch {
    pub(super) fn retained_memory_bytes(&self) -> usize {
        self.renamed_keys.capacity() * size_of::<Option<String>>()
            + self.remapped_key_ids.capacity() * size_of::<u32>()
            + self.key_keep_mask.capacity() * size_of::<bool>()
            + self.keep_cache.retained_memory_bytes()
            + self.xform_cache.retained_memory_bytes()
            + self.mapped_val_actions.capacity() * size_of::<CachedValAction>()
            + self.dp_keep.capacity() * size_of::<bool>()
            + self.dp_remap.capacity() * size_of::<u32>()
            + self.ex_keep.capacity() * size_of::<bool>()
            + self.ex_remap.capacity() * size_of::<u32>()
            + self.metric_used.capacity() * size_of::<bool>()
            + self.metric_remap.capacity() * size_of::<u16>()
            + self.tmp_parent_ids.capacity() * size_of::<u32>()
            + self.tmp_pairs.capacity() * size_of::<(u32, u32)>()
            + self.tmp_str.capacity()
    }
}

/// Runs Stage 2 `honor_labels` collision resolution and `metric_relabel_configs` over the staged
/// columnar tables before Arrow `RecordBatch` materialization.
///
/// Returns the final `ResourceAttrs` batch to attach (reusing the cached batch on
/// [`TargetAttributes`] whenever target labels were not modified by `metric_relabel_configs`).
#[allow(clippy::too_many_arguments)]
pub(super) fn apply_stage2_relabeling(
    opts: &DecodeOptions,
    metrics: &mut MetricTable,
    key_interner: &mut StringInterner,
    val_interner: &mut StringInterner,
    num_dp: &mut NumberDpTable,
    sum_dp: &mut SummaryDpTable,
    hist_dp: &mut HistogramDpTable,
    scratch: &mut Stage2Scratch,
) -> Result<Option<RecordBatch>, DecodeError> {
    let target_attrs = opts.target_attributes.as_deref();
    let stage2_cfgs = opts
        .metric_relabel_plan
        .as_deref()
        .map_or(&[][..], MetricRelabelPlan::stage2_configs);

    // Step 1: Resolve `honor_labels = false` collisions once across `key_interner` in
    // O(unique_keys). Exemplar attributes are intentionally left untouched to match Prometheus.
    if let Some(target) = target_attrs
        && !opts.honor_labels
        && !target.target_labels().is_empty()
    {
        let key_count = key_interner.len();
        let has_collision = resolve_conflicting_exposed_keys_iter(
            (0..key_count).map(|i| key_interner.get(i as u32)),
            target.target_labels(),
            false,
            &mut scratch.renamed_keys,
        );
        if has_collision {
            scratch.remapped_key_ids.clear();
            scratch.remapped_key_ids.reserve(key_count);
            for kid in 0..key_count {
                if let Some(exported) = scratch.renamed_keys[kid].as_deref() {
                    let new_kid = intern_key(key_interner, exported)?;
                    scratch.remapped_key_ids.push(new_kid);
                } else {
                    scratch.remapped_key_ids.push(kid as u32);
                }
            }
            num_dp.attrs.remap_keys(&scratch.remapped_key_ids);
            sum_dp.attrs.remap_keys(&scratch.remapped_key_ids);
            hist_dp.attrs.remap_keys(&scratch.remapped_key_ids);
        }
    }

    if stage2_cfgs.is_empty() {
        return match target_attrs {
            Some(target) => target.resource_attrs_batch(),
            None => Ok(None),
        };
    }

    // Step 2: Execute Stage 2 `metric_relabel_configs`.
    scratch.effective_target_labels.clear();
    if let Some(target) = target_attrs {
        scratch
            .effective_target_labels
            .clone_from(target.target_labels());
    }
    let mut target_labels_dirty = false;
    let mut any_dp_or_metric_mutated = false;

    let mut rule_idx = 0usize;
    while rule_idx < stage2_cfgs.len() {
        if all_dps_empty(num_dp, sum_dp, hist_dp) {
            metrics.clear();
            return Ok(None);
        }

        let cfg = &stage2_cfgs[rule_idx];
        match classify_stage2_rule(cfg) {
            Stage2RuleKind::KeyFilter => {
                apply_key_filter_rule(
                    cfg,
                    key_interner,
                    num_dp,
                    sum_dp,
                    hist_dp,
                    scratch,
                    &mut target_labels_dirty,
                );
                rule_idx += 1;
            }
            Stage2RuleKind::SingleLabelFilter => {
                let dropped_any = apply_single_label_filter_rule(
                    cfg,
                    key_interner,
                    val_interner,
                    num_dp,
                    sum_dp,
                    hist_dp,
                    scratch,
                );
                any_dp_or_metric_mutated |= dropped_any;
                rule_idx += 1;
            }
            Stage2RuleKind::SingleLabelTransform => {
                apply_single_label_transform_rule(
                    cfg,
                    key_interner,
                    val_interner,
                    num_dp,
                    sum_dp,
                    hist_dp,
                    scratch,
                    &mut target_labels_dirty,
                )?;
                rule_idx += 1;
            }
            Stage2RuleKind::General => {
                // Batch contiguous general rules into a single pass over surviving data points.
                let start = rule_idx;
                rule_idx += 1;
                while rule_idx < stage2_cfgs.len()
                    && classify_stage2_rule(&stage2_cfgs[rule_idx]) == Stage2RuleKind::General
                {
                    rule_idx += 1;
                }
                let mutated = apply_general_rules(
                    &stage2_cfgs[start..rule_idx],
                    metrics,
                    key_interner,
                    val_interner,
                    num_dp,
                    sum_dp,
                    hist_dp,
                    scratch,
                    &mut target_labels_dirty,
                )?;
                any_dp_or_metric_mutated |= mutated;
            }
        }
    }

    if all_dps_empty(num_dp, sum_dp, hist_dp) {
        metrics.clear();
        return Ok(None);
    }

    // Step 3: Prune metric families whose data points were all dropped or renamed away.
    if any_dp_or_metric_mutated {
        prune_unused_metrics(metrics, num_dp, sum_dp, hist_dp, scratch);
        if metrics.is_empty() {
            return Ok(None);
        }
    }

    // Step 4: Reuse cached `ResourceAttrs` unless Stage 2 mutated or dropped a target label.
    if !target_labels_dirty {
        return match target_attrs {
            Some(target) => target.resource_attrs_batch(),
            None => Ok(None),
        };
    }

    let empty_explicit = BTreeMap::new();
    let explicit = target_attrs.map_or(
        &empty_explicit,
        TargetAttributes::explicit_resource_attributes,
    );
    let resolved = resolve_resource_attributes(&scratch.effective_target_labels, explicit);
    build_resource_attrs_batch(&resolved)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage2RuleKind {
    KeyFilter,
    SingleLabelFilter,
    SingleLabelTransform,
    General,
}

fn classify_stage2_rule(cfg: &Config) -> Stage2RuleKind {
    match cfg.action {
        Action::LabelDrop => {
            if cfg.regex.is_match(METRIC_NAME_LABEL) {
                Stage2RuleKind::General
            } else {
                Stage2RuleKind::KeyFilter
            }
        }
        Action::LabelKeep => {
            if cfg.regex.is_match(METRIC_NAME_LABEL) {
                Stage2RuleKind::KeyFilter
            } else {
                Stage2RuleKind::General
            }
        }
        Action::Keep | Action::Drop
            if cfg.source_labels.len() == 1 && cfg.source_labels[0] != METRIC_NAME_LABEL =>
        {
            Stage2RuleKind::SingleLabelFilter
        }
        Action::Replace | Action::Lowercase | Action::Uppercase | Action::HashMod
            if cfg.source_labels.len() == 1
                && cfg.source_labels[0] != METRIC_NAME_LABEL
                && cfg.target_label != METRIC_NAME_LABEL
                && !cfg.target_label.contains('$') =>
        {
            Stage2RuleKind::SingleLabelTransform
        }
        _ => Stage2RuleKind::General,
    }
}

#[inline]
fn all_dps_empty(
    num_dp: &NumberDpTable,
    sum_dp: &SummaryDpTable,
    hist_dp: &HistogramDpTable,
) -> bool {
    num_dp.base.is_empty() && sum_dp.base.is_empty() && hist_dp.base.is_empty()
}

#[inline]
fn intern_key(key_interner: &mut StringInterner, key: &str) -> Result<u32, DecodeError> {
    key_interner
        .intern(key.as_bytes())
        .ok_or_else(|| DecodeError::CapacityOverflow {
            table: "DpAttrs.key",
            count: key_interner.len(),
        })
}

#[inline]
fn intern_val(val_interner: &mut StringInterner, val: &str) -> Result<u32, DecodeError> {
    val_interner
        .intern(val.as_bytes())
        .ok_or_else(|| DecodeError::CapacityOverflow {
            table: "DpAttrs.str",
            count: val_interner.len(),
        })
}

fn apply_key_filter_rule(
    cfg: &Config,
    key_interner: &StringInterner,
    num_dp: &mut NumberDpTable,
    sum_dp: &mut SummaryDpTable,
    hist_dp: &mut HistogramDpTable,
    scratch: &mut Stage2Scratch,
    target_labels_dirty: &mut bool,
) {
    let key_count = key_interner.len();
    if let Some(dropped) = eval_key_keep_mask_iter(
        (0..key_count).map(|i| key_interner.get(i as u32)),
        cfg,
        &mut scratch.key_keep_mask,
    ) && dropped > 0
    {
        num_dp.attrs.filter_by_key_mask(&scratch.key_keep_mask);
        sum_dp.attrs.filter_by_key_mask(&scratch.key_keep_mask);
        hist_dp.attrs.filter_by_key_mask(&scratch.key_keep_mask);
    }

    if !scratch.effective_target_labels.is_empty() {
        let before = scratch.effective_target_labels.len();
        match cfg.action {
            Action::LabelDrop => {
                scratch
                    .effective_target_labels
                    .retain(|k, _| !cfg.regex.is_match(k));
            }
            Action::LabelKeep => {
                scratch
                    .effective_target_labels
                    .retain(|k, _| cfg.regex.is_match(k));
            }
            _ => unreachable!(),
        }
        if scratch.effective_target_labels.len() != before {
            *target_labels_dirty = true;
        }
    }
}

fn apply_single_label_filter_rule(
    cfg: &Config,
    key_interner: &StringInterner,
    val_interner: &StringInterner,
    num_dp: &mut NumberDpTable,
    sum_dp: &mut SummaryDpTable,
    hist_dp: &mut HistogramDpTable,
    scratch: &mut Stage2Scratch,
) -> bool {
    let src_key = &cfg.source_labels[0];
    let ok = scratch.keep_cache.prepare(val_interner.len(), cfg);
    debug_assert!(ok);

    let absent_keep = match scratch.effective_target_labels.get(src_key.as_str()) {
        Some(tv) => match cfg.action {
            Action::Keep => cfg.regex.is_match(tv),
            Action::Drop => !cfg.regex.is_match(tv),
            _ => unreachable!(),
        },
        None => scratch.keep_cache.keep_when_absent(),
    };

    let Some(src_kid) = key_interner.lookup(src_key.as_bytes()) else {
        if absent_keep {
            return false;
        }
        num_dp.clear();
        sum_dp.clear();
        hist_dp.clear();
        return true;
    };

    let mut dropped_any = false;

    if !num_dp.base.is_empty() {
        let any_dropped = eval_dp_keep_mask(
            num_dp.base.len(),
            &num_dp.attrs,
            src_kid,
            absent_keep,
            val_interner,
            cfg,
            &mut scratch.keep_cache,
            &mut scratch.dp_keep,
        );
        if any_dropped {
            num_dp.compact(
                &scratch.dp_keep,
                &mut scratch.dp_remap,
                &mut scratch.ex_keep,
                &mut scratch.ex_remap,
            );
            dropped_any = true;
        }
    }

    if !sum_dp.base.is_empty() {
        let any_dropped = eval_dp_keep_mask(
            sum_dp.base.len(),
            &sum_dp.attrs,
            src_kid,
            absent_keep,
            val_interner,
            cfg,
            &mut scratch.keep_cache,
            &mut scratch.dp_keep,
        );
        if any_dropped {
            sum_dp.compact(&scratch.dp_keep, &mut scratch.dp_remap);
            dropped_any = true;
        }
    }

    if !hist_dp.base.is_empty() {
        let any_dropped = eval_dp_keep_mask(
            hist_dp.base.len(),
            &hist_dp.attrs,
            src_kid,
            absent_keep,
            val_interner,
            cfg,
            &mut scratch.keep_cache,
            &mut scratch.dp_keep,
        );
        if any_dropped {
            hist_dp.compact(
                &scratch.dp_keep,
                &mut scratch.dp_remap,
                &mut scratch.ex_keep,
                &mut scratch.ex_remap,
            );
            dropped_any = true;
        }
    }

    dropped_any
}

#[allow(clippy::too_many_arguments)]
fn eval_dp_keep_mask(
    num_dps: usize,
    attrs: &AttrTable,
    src_kid: u32,
    absent_keep: bool,
    val_interner: &StringInterner,
    cfg: &Config,
    keep_cache: &mut SingleLabelKeepCache,
    dp_keep: &mut Vec<bool>,
) -> bool {
    dp_keep.clear();
    dp_keep.reserve(num_dps);
    let mut attr_pos = 0usize;
    let total_attrs = attrs.pairs.len();
    let mut dropped_any = false;

    for dp_idx in 0..num_dps {
        let dp_id = dp_idx as u32;
        let mut found_vid: Option<u32> = None;
        while attr_pos < total_attrs && attrs.parent_ids[attr_pos] == dp_id {
            let (k, v) = attrs.pairs[attr_pos];
            if k == src_kid {
                found_vid = Some(v);
            }
            attr_pos += 1;
        }
        let kept = match found_vid {
            Some(vid) => keep_cache.keep_str(vid as usize, val_interner.get(vid), cfg),
            None => absent_keep,
        };
        if !kept {
            dropped_any = true;
        }
        dp_keep.push(kept);
    }

    dropped_any
}

#[allow(clippy::too_many_arguments)]
fn apply_single_label_transform_rule(
    cfg: &Config,
    key_interner: &mut StringInterner,
    val_interner: &mut StringInterner,
    num_dp: &mut NumberDpTable,
    sum_dp: &mut SummaryDpTable,
    hist_dp: &mut HistogramDpTable,
    scratch: &mut Stage2Scratch,
    target_labels_dirty: &mut bool,
) -> Result<(), DecodeError> {
    let src_key = &cfg.source_labels[0];
    let dst_key = &cfg.target_label;
    let ok = scratch.xform_cache.prepare(val_interner.len(), cfg);
    debug_assert!(ok);

    let src_kid = key_interner.lookup(src_key.as_bytes());
    let target_src_val = scratch
        .effective_target_labels
        .get(src_key.as_str())
        .cloned();

    // Uniform source fast path: no series overrides `src_key` in `DpAttrs`, so every surviving
    // series sees the same source value (either `effective_target_labels[src_key]` or `""`).
    let Some(src_kid) = src_kid else {
        let src_str = target_src_val.as_deref().unwrap_or("");
        let xform = if target_src_val.is_some() {
            scratch.xform_cache.eval_single_str(src_str, cfg)
        } else {
            scratch.xform_cache.when_absent().clone()
        };
        match xform {
            DictionaryValueTransform::KeepExisting => {}
            DictionaryValueTransform::DeleteTarget => {
                if scratch
                    .effective_target_labels
                    .remove(dst_key.as_str())
                    .is_some()
                {
                    *target_labels_dirty = true;
                }
                if let Some(dst_kid) = key_interner.lookup(dst_key.as_bytes()) {
                    delete_key_from_all_dps(dst_kid, num_dp, sum_dp, hist_dp);
                }
            }
            DictionaryValueTransform::SetTargetSlice { .. }
            | DictionaryValueTransform::SetTarget(_) => {
                let new_val = xform
                    .target_value(src_str)
                    .expect("SetTarget* always yields Some");
                if scratch
                    .effective_target_labels
                    .contains_key(dst_key.as_str())
                {
                    if scratch
                        .effective_target_labels
                        .get(dst_key.as_str())
                        .map(String::as_str)
                        != Some(new_val)
                    {
                        scratch
                            .effective_target_labels
                            .insert(dst_key.clone(), new_val.to_owned());
                        *target_labels_dirty = true;
                    }
                    if let Some(dst_kid) = key_interner.lookup(dst_key.as_bytes()) {
                        delete_key_from_all_dps(dst_kid, num_dp, sum_dp, hist_dp);
                    }
                } else {
                    let dst_kid = intern_key(key_interner, dst_key)?;
                    let new_vid = intern_val(val_interner, new_val)?;
                    upsert_uniform_attr_on_all_dps(
                        dst_kid, new_vid, num_dp, sum_dp, hist_dp, scratch,
                    );
                }
            }
        }
        return Ok(());
    };

    // If a per-series varying transform targets a public target label, demote that target label
    // out of `effective_target_labels` onto data points that did not already override it so
    // per-series deletes or mutations cannot leak the old `ResourceAttrs` value.
    if let Some(target_dst_val) = scratch.effective_target_labels.remove(dst_key.as_str()) {
        *target_labels_dirty = true;
        let dst_kid = intern_key(key_interner, dst_key)?;
        let dst_vid = intern_val(val_interner, &target_dst_val)?;
        insert_missing_attr_on_all_dps(dst_kid, dst_vid, num_dp, sum_dp, hist_dp, scratch);
    }

    let absent_action = {
        let src_str = target_src_val.as_deref().unwrap_or("");
        let xform = if target_src_val.is_some() {
            scratch.xform_cache.eval_single_str(src_str, cfg)
        } else {
            scratch.xform_cache.when_absent().clone()
        };
        materialize_transform_action(&xform, src_str, val_interner, &mut scratch.tmp_str)?
    };

    scratch.mapped_val_actions.clear();
    scratch
        .mapped_val_actions
        .resize(val_interner.len(), CachedValAction::Uncomputed);

    let mut dst_kid = key_interner.lookup(dst_key.as_bytes());
    if !num_dp.base.is_empty() {
        apply_single_label_transform_table(
            num_dp.base.len(),
            &mut num_dp.attrs,
            src_kid,
            dst_key,
            &mut dst_kid,
            absent_action,
            key_interner,
            val_interner,
            cfg,
            scratch,
        )?;
    }
    if !sum_dp.base.is_empty() {
        apply_single_label_transform_table(
            sum_dp.base.len(),
            &mut sum_dp.attrs,
            src_kid,
            dst_key,
            &mut dst_kid,
            absent_action,
            key_interner,
            val_interner,
            cfg,
            scratch,
        )?;
    }
    if !hist_dp.base.is_empty() {
        apply_single_label_transform_table(
            hist_dp.base.len(),
            &mut hist_dp.attrs,
            src_kid,
            dst_key,
            &mut dst_kid,
            absent_action,
            key_interner,
            val_interner,
            cfg,
            scratch,
        )?;
    }

    Ok(())
}

fn materialize_transform_action(
    xform: &DictionaryValueTransform,
    src_str: &str,
    val_interner: &mut StringInterner,
    tmp_str: &mut String,
) -> Result<CachedValAction, DecodeError> {
    match xform {
        DictionaryValueTransform::KeepExisting => Ok(CachedValAction::KeepExisting),
        DictionaryValueTransform::DeleteTarget => Ok(CachedValAction::Delete),
        DictionaryValueTransform::SetTargetSlice { start, end } => {
            tmp_str.clear();
            tmp_str.push_str(&src_str[*start..*end]);
            let vid = intern_val(val_interner, tmp_str)?;
            Ok(CachedValAction::Set(vid))
        }
        DictionaryValueTransform::SetTarget(s) => {
            let vid = intern_val(val_interner, s)?;
            Ok(CachedValAction::Set(vid))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_single_label_transform_table(
    num_dps: usize,
    attrs: &mut AttrTable,
    src_kid: u32,
    dst_key: &str,
    dst_kid: &mut Option<u32>,
    absent_action: CachedValAction,
    key_interner: &mut StringInterner,
    val_interner: &mut StringInterner,
    cfg: &Config,
    scratch: &mut Stage2Scratch,
) -> Result<(), DecodeError> {
    scratch.tmp_parent_ids.clear();
    scratch.tmp_pairs.clear();
    scratch.tmp_parent_ids.reserve(attrs.parent_ids.len());
    scratch.tmp_pairs.reserve(attrs.pairs.len());

    let mut attr_pos = 0usize;
    let total_attrs = attrs.pairs.len();

    for dp_idx in 0..num_dps {
        let dp_id = dp_idx as u32;
        let start = attr_pos;
        let mut found_src_vid: Option<u32> = None;
        while attr_pos < total_attrs && attrs.parent_ids[attr_pos] == dp_id {
            let (k, v) = attrs.pairs[attr_pos];
            if k == src_kid {
                found_src_vid = Some(v);
            }
            attr_pos += 1;
        }
        let end = attr_pos;

        let action = match found_src_vid {
            Some(svid) => {
                let idx = svid as usize;
                let cached = scratch.mapped_val_actions[idx];
                if cached == CachedValAction::Uncomputed {
                    let computed = {
                        let src_str = val_interner.get(svid);
                        let xform = scratch.xform_cache.transform_str(idx, src_str, cfg);
                        match xform {
                            DictionaryValueTransform::KeepExisting => CachedValAction::KeepExisting,
                            DictionaryValueTransform::DeleteTarget => CachedValAction::Delete,
                            DictionaryValueTransform::SetTargetSlice { start, end } => {
                                scratch.tmp_str.clear();
                                scratch.tmp_str.push_str(&src_str[*start..*end]);
                                CachedValAction::Set(u32::MAX)
                            }
                            DictionaryValueTransform::SetTarget(s) => {
                                scratch.tmp_str.clear();
                                scratch.tmp_str.push_str(s);
                                CachedValAction::Set(u32::MAX)
                            }
                        }
                    };
                    let finalized = if computed == CachedValAction::Set(u32::MAX) {
                        CachedValAction::Set(intern_val(val_interner, &scratch.tmp_str)?)
                    } else {
                        computed
                    };
                    scratch.mapped_val_actions[idx] = finalized;
                    finalized
                } else {
                    cached
                }
            }
            None => absent_action,
        };

        match action {
            CachedValAction::Uncomputed => unreachable!(),
            CachedValAction::KeepExisting => {
                scratch
                    .tmp_parent_ids
                    .extend_from_slice(&attrs.parent_ids[start..end]);
                scratch
                    .tmp_pairs
                    .extend_from_slice(&attrs.pairs[start..end]);
            }
            CachedValAction::Delete => {
                if let Some(dk) = *dst_kid {
                    for &pair in &attrs.pairs[start..end] {
                        if pair.0 != dk {
                            scratch.tmp_parent_ids.push(dp_id);
                            scratch.tmp_pairs.push(pair);
                        }
                    }
                } else {
                    scratch
                        .tmp_parent_ids
                        .extend_from_slice(&attrs.parent_ids[start..end]);
                    scratch
                        .tmp_pairs
                        .extend_from_slice(&attrs.pairs[start..end]);
                }
            }
            CachedValAction::Set(new_vid) => {
                let dk = match *dst_kid {
                    Some(k) => k,
                    None => {
                        let k = intern_key(key_interner, dst_key)?;
                        *dst_kid = Some(k);
                        k
                    }
                };
                let mut replaced = false;
                for &pair in &attrs.pairs[start..end] {
                    if pair.0 == dk {
                        scratch.tmp_parent_ids.push(dp_id);
                        scratch.tmp_pairs.push((dk, new_vid));
                        replaced = true;
                    } else {
                        scratch.tmp_parent_ids.push(dp_id);
                        scratch.tmp_pairs.push(pair);
                    }
                }
                if !replaced {
                    scratch.tmp_parent_ids.push(dp_id);
                    scratch.tmp_pairs.push((dk, new_vid));
                }
            }
        }
    }

    std::mem::swap(&mut attrs.parent_ids, &mut scratch.tmp_parent_ids);
    std::mem::swap(&mut attrs.pairs, &mut scratch.tmp_pairs);
    Ok(())
}

fn delete_key_from_all_dps(
    dst_kid: u32,
    num_dp: &mut NumberDpTable,
    sum_dp: &mut SummaryDpTable,
    hist_dp: &mut HistogramDpTable,
) {
    for attrs in [&mut num_dp.attrs, &mut sum_dp.attrs, &mut hist_dp.attrs] {
        if attrs.pairs.is_empty() {
            continue;
        }
        let mut write = 0usize;
        for i in 0..attrs.pairs.len() {
            let pair = attrs.pairs[i];
            if pair.0 != dst_kid {
                attrs.parent_ids[write] = attrs.parent_ids[i];
                attrs.pairs[write] = pair;
                write += 1;
            }
        }
        attrs.parent_ids.truncate(write);
        attrs.pairs.truncate(write);
    }
}

fn upsert_uniform_attr_on_all_dps(
    dst_kid: u32,
    new_vid: u32,
    num_dp: &mut NumberDpTable,
    sum_dp: &mut SummaryDpTable,
    hist_dp: &mut HistogramDpTable,
    scratch: &mut Stage2Scratch,
) {
    for (num_dps, attrs) in [
        (num_dp.base.len(), &mut num_dp.attrs),
        (sum_dp.base.len(), &mut sum_dp.attrs),
        (hist_dp.base.len(), &mut hist_dp.attrs),
    ] {
        if num_dps == 0 {
            continue;
        }
        rewrite_attr_table_with_key(num_dps, attrs, dst_kid, new_vid, true, scratch);
    }
}

fn insert_missing_attr_on_all_dps(
    dst_kid: u32,
    default_vid: u32,
    num_dp: &mut NumberDpTable,
    sum_dp: &mut SummaryDpTable,
    hist_dp: &mut HistogramDpTable,
    scratch: &mut Stage2Scratch,
) {
    for (num_dps, attrs) in [
        (num_dp.base.len(), &mut num_dp.attrs),
        (sum_dp.base.len(), &mut sum_dp.attrs),
        (hist_dp.base.len(), &mut hist_dp.attrs),
    ] {
        if num_dps == 0 {
            continue;
        }
        rewrite_attr_table_with_key(num_dps, attrs, dst_kid, default_vid, false, scratch);
    }
}

fn rewrite_attr_table_with_key(
    num_dps: usize,
    attrs: &mut AttrTable,
    target_kid: u32,
    val_id: u32,
    overwrite_existing: bool,
    scratch: &mut Stage2Scratch,
) {
    scratch.tmp_parent_ids.clear();
    scratch.tmp_pairs.clear();
    scratch
        .tmp_parent_ids
        .reserve(attrs.parent_ids.len() + num_dps);
    scratch.tmp_pairs.reserve(attrs.pairs.len() + num_dps);

    let mut attr_pos = 0usize;
    let total_attrs = attrs.pairs.len();

    for dp_idx in 0..num_dps {
        let dp_id = dp_idx as u32;
        let mut saw_key = false;
        while attr_pos < total_attrs && attrs.parent_ids[attr_pos] == dp_id {
            let pair = attrs.pairs[attr_pos];
            attr_pos += 1;
            if pair.0 == target_kid {
                saw_key = true;
                scratch.tmp_parent_ids.push(dp_id);
                scratch.tmp_pairs.push(if overwrite_existing {
                    (target_kid, val_id)
                } else {
                    pair
                });
            } else {
                scratch.tmp_parent_ids.push(dp_id);
                scratch.tmp_pairs.push(pair);
            }
        }
        if !saw_key {
            scratch.tmp_parent_ids.push(dp_id);
            scratch.tmp_pairs.push((target_kid, val_id));
        }
    }

    std::mem::swap(&mut attrs.parent_ids, &mut scratch.tmp_parent_ids);
    std::mem::swap(&mut attrs.pairs, &mut scratch.tmp_pairs);
}

enum TargetUniformity {
    Unseen,
    Uniform(String),
    Diverged,
}

/// Exact Prometheus scalar fallback for general Stage 2 rules (multi-label `source_labels`,
/// `labelmap`, `keepequal`, `dropequal`, dynamic `$1` `target_label`, or `__name__` reads/writes).
#[allow(clippy::too_many_arguments)]
fn apply_general_rules(
    cfgs: &[Config],
    metrics: &mut MetricTable,
    key_interner: &mut StringInterner,
    val_interner: &mut StringInterner,
    num_dp: &mut NumberDpTable,
    sum_dp: &mut SummaryDpTable,
    hist_dp: &mut HistogramDpTable,
    scratch: &mut Stage2Scratch,
    target_labels_dirty: &mut bool,
) -> Result<bool, DecodeError> {
    let orig_targets: Vec<(String, String)> = scratch
        .effective_target_labels
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let mut target_states: Vec<TargetUniformity> = (0..orig_targets.len())
        .map(|_| TargetUniformity::Unseen)
        .collect();
    let mut renamed_metrics: HashMap<(u16, String), u16> = HashMap::new();
    let mut any_mutated = false;

    if !num_dp.base.is_empty() {
        let (dropped, renamed) = apply_general_rules_table(
            cfgs,
            &orig_targets,
            &mut target_states,
            &mut renamed_metrics,
            metrics,
            key_interner,
            val_interner,
            &mut num_dp.base.parent_ids,
            &mut num_dp.attrs,
            scratch,
        )?;
        if dropped {
            num_dp.compact(
                &scratch.dp_keep,
                &mut scratch.dp_remap,
                &mut scratch.ex_keep,
                &mut scratch.ex_remap,
            );
            any_mutated = true;
        }
        any_mutated |= renamed;
    }

    if !sum_dp.base.is_empty() {
        let (dropped, renamed) = apply_general_rules_table(
            cfgs,
            &orig_targets,
            &mut target_states,
            &mut renamed_metrics,
            metrics,
            key_interner,
            val_interner,
            &mut sum_dp.base.parent_ids,
            &mut sum_dp.attrs,
            scratch,
        )?;
        if dropped {
            sum_dp.compact(&scratch.dp_keep, &mut scratch.dp_remap);
            any_mutated = true;
        }
        any_mutated |= renamed;
    }

    if !hist_dp.base.is_empty() {
        let (dropped, renamed) = apply_general_rules_table(
            cfgs,
            &orig_targets,
            &mut target_states,
            &mut renamed_metrics,
            metrics,
            key_interner,
            val_interner,
            &mut hist_dp.base.parent_ids,
            &mut hist_dp.attrs,
            scratch,
        )?;
        if dropped {
            hist_dp.compact(
                &scratch.dp_keep,
                &mut scratch.dp_remap,
                &mut scratch.ex_keep,
                &mut scratch.ex_remap,
            );
            any_mutated = true;
        }
        any_mutated |= renamed;
    }

    // Re-hoist uniform surviving target labels back into `ResourceAttrs` and strip them from
    // `DpAttrs` so unchanged target labels are not duplicated onto every data-point row.
    if !orig_targets.is_empty() {
        scratch.key_keep_mask.clear();
        scratch.key_keep_mask.resize(key_interner.len(), true);
        let mut strip_any_key = false;

        for ((tk, orig_val), state) in orig_targets.iter().zip(target_states) {
            match state {
                TargetUniformity::Uniform(uniform_val) => {
                    if &uniform_val != orig_val {
                        scratch
                            .effective_target_labels
                            .insert(tk.clone(), uniform_val);
                        *target_labels_dirty = true;
                    }
                    if let Some(kid) = key_interner.lookup(tk.as_bytes()) {
                        scratch.key_keep_mask[kid as usize] = false;
                        strip_any_key = true;
                    }
                }
                TargetUniformity::Unseen | TargetUniformity::Diverged => {
                    if scratch
                        .effective_target_labels
                        .remove(tk.as_str())
                        .is_some()
                    {
                        *target_labels_dirty = true;
                    }
                }
            }
        }

        if strip_any_key {
            num_dp.attrs.filter_by_key_mask(&scratch.key_keep_mask);
            sum_dp.attrs.filter_by_key_mask(&scratch.key_keep_mask);
            hist_dp.attrs.filter_by_key_mask(&scratch.key_keep_mask);
        }
    }

    Ok(any_mutated)
}

#[allow(clippy::too_many_arguments)]
fn apply_general_rules_table(
    cfgs: &[Config],
    orig_targets: &[(String, String)],
    target_states: &mut [TargetUniformity],
    renamed_metrics: &mut HashMap<(u16, String), u16>,
    metrics: &mut MetricTable,
    key_interner: &mut StringInterner,
    val_interner: &mut StringInterner,
    dp_metric_ids: &mut [u16],
    attrs: &mut AttrTable,
    scratch: &mut Stage2Scratch,
) -> Result<(bool, bool), DecodeError> {
    let num_dps = dp_metric_ids.len();
    scratch.dp_keep.clear();
    scratch.dp_keep.reserve(num_dps);
    scratch.tmp_parent_ids.clear();
    scratch.tmp_pairs.clear();
    scratch.tmp_parent_ids.reserve(attrs.parent_ids.len());
    scratch.tmp_pairs.reserve(attrs.pairs.len());

    let mut attr_pos = 0usize;
    let total_attrs = attrs.pairs.len();
    let mut dropped_any = false;
    let mut renamed_any = false;

    for (dp_idx, metric_id_slot) in dp_metric_ids.iter_mut().enumerate() {
        let dp_id = dp_idx as u32;
        let orig_metric_id = *metric_id_slot;
        let orig_name = metrics.name(orig_metric_id);

        scratch.scalar_work.clear();
        scratch
            .scalar_work
            .insert(METRIC_NAME_LABEL.to_owned(), orig_name.to_owned());
        for (tk, tv) in orig_targets {
            scratch.scalar_work.insert(tk.clone(), tv.clone());
        }
        while attr_pos < total_attrs && attrs.parent_ids[attr_pos] == dp_id {
            let (kid, vid) = attrs.pairs[attr_pos];
            attr_pos += 1;
            scratch.scalar_work.insert(
                key_interner.get(kid).to_owned(),
                val_interner.get(vid).to_owned(),
            );
        }

        let kept = prometheus_relabel::process_in_place(&mut scratch.scalar_work, cfgs);
        if !kept || scratch.scalar_work.is_empty() {
            scratch.dp_keep.push(false);
            dropped_any = true;
            continue;
        }

        let Some(new_name) = scratch.scalar_work.remove(METRIC_NAME_LABEL) else {
            return Err(DecodeError::MissingMetricName);
        };
        if new_name.is_empty() {
            return Err(DecodeError::MissingMetricName);
        }

        if new_name != orig_name {
            let new_metric_id = if let Some(&cached_id) =
                renamed_metrics.get(&(orig_metric_id, new_name.clone()))
            {
                cached_id
            } else {
                let id = metrics.clone_with_name(orig_metric_id, &new_name)?;
                renamed_metrics.insert((orig_metric_id, new_name), id);
                id
            };
            *metric_id_slot = new_metric_id;
            renamed_any = true;
        }

        for ((tk, _), state) in orig_targets.iter().zip(target_states.iter_mut()) {
            match scratch.scalar_work.get(tk.as_str()) {
                Some(v) => match state {
                    TargetUniformity::Unseen => *state = TargetUniformity::Uniform(v.clone()),
                    TargetUniformity::Uniform(prev) if prev == v => {}
                    TargetUniformity::Uniform(_) | TargetUniformity::Diverged => {
                        *state = TargetUniformity::Diverged;
                    }
                },
                None => *state = TargetUniformity::Diverged,
            }
        }

        for (k, v) in &scratch.scalar_work {
            let kid = intern_key(key_interner, k)?;
            let vid = intern_val(val_interner, v)?;
            scratch.tmp_parent_ids.push(dp_id);
            scratch.tmp_pairs.push((kid, vid));
        }
        scratch.dp_keep.push(true);
    }

    std::mem::swap(&mut attrs.parent_ids, &mut scratch.tmp_parent_ids);
    std::mem::swap(&mut attrs.pairs, &mut scratch.tmp_pairs);
    Ok((dropped_any, renamed_any))
}

fn prune_unused_metrics(
    metrics: &mut MetricTable,
    num_dp: &mut NumberDpTable,
    sum_dp: &mut SummaryDpTable,
    hist_dp: &mut HistogramDpTable,
    scratch: &mut Stage2Scratch,
) {
    let num_metrics = metrics.len();
    scratch.metric_used.clear();
    scratch.metric_used.resize(num_metrics, false);
    for &id in &num_dp.base.parent_ids {
        scratch.metric_used[usize::from(id)] = true;
    }
    for &id in &sum_dp.base.parent_ids {
        scratch.metric_used[usize::from(id)] = true;
    }
    for &id in &hist_dp.base.parent_ids {
        scratch.metric_used[usize::from(id)] = true;
    }
    if scratch.metric_used.iter().all(|&u| u) {
        return;
    }
    metrics.compact(&scratch.metric_used, &mut scratch.metric_remap);
    for id in &mut num_dp.base.parent_ids {
        *id = scratch.metric_remap[usize::from(*id)];
    }
    for id in &mut sum_dp.base.parent_ids {
        *id = scratch.metric_remap[usize::from(*id)];
    }
    for id in &mut hist_dp.base.parent_ids {
        *id = scratch.metric_remap[usize::from(*id)];
    }
}
