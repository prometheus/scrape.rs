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

package main

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/prometheus/prometheus/model/exemplar"
	"github.com/prometheus/prometheus/model/histogram"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/textparse"
)

// promParseInputs are the Prometheus text fixtures, relative to testdata/. Each
// output is written to testdata/promparse/ under the same relative path, which is
// how src/parse/go_diff_tests.rs finds the input for each expected file.
var promParseInputs = []string{
	"textparse/TestPromParse.prom.txt",
	"textparse/alltypes.237mfs.prom.txt",
	"textparse/alltypes.237mfs.nometa.prom.txt",
	"expfmt/text",
}

// writePromParseExpected runs textparse.NewPromParser on each input and writes
// one line per entry to testdata/promparse/.
func writePromParseExpected(outRoot string) ([]string, error) {
	var written []string
	for _, input := range promParseInputs {
		err := writeExpected(outRoot, "promparse", input, func(data []byte) string {
			return renderEntries(textparse.NewPromParser(data, labels.NewSymbolTable(), false), false)
		})
		if err != nil {
			return nil, err
		}
		written = append(written, "promparse/"+input)
	}
	return written, nil
}

// writeExpected renders testdata/<input> and writes it to testdata/<outDir>/<input>.
func writeExpected(outRoot, outDir, input string, render func([]byte) string) error {
	data, err := os.ReadFile(filepath.Join(outRoot, input))
	if err != nil {
		return fmt.Errorf("read %s: %w", input, err)
	}
	dstPath := filepath.Join(outRoot, outDir, input)
	if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(dstPath), err)
	}
	if err := os.WriteFile(dstPath, []byte(render(data)), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", dstPath, err)
	}
	return nil
}

// renderEntries writes one line per entry, plus an st line per series when
// startTimestamps is set. src/parse/go_diff_tests.rs writes the same format.
func renderEntries(parser textparse.Parser, startTimestamps bool) string {
	var out strings.Builder
	var labelSet labels.Labels
	for {
		entry, err := parser.Next()
		if errors.Is(err, io.EOF) {
			return out.String()
		}
		if err != nil {
			out.WriteString("error\n")
			return out.String()
		}
		switch entry {
		case textparse.EntryHelp:
			name, text := parser.Help()
			fmt.Fprintf(&out, "help %s %s\n", quote(name), quote(text))
		case textparse.EntryType:
			name, metricType := parser.Type()
			fmt.Fprintf(&out, "type %s %s\n", quote(name), metricType)
		case textparse.EntryUnit:
			name, unit := parser.Unit()
			fmt.Fprintf(&out, "unit %s %s\n", quote(name), quote(unit))
		case textparse.EntryComment:
			fmt.Fprintf(&out, "comment %s\n", quote(parser.Comment()))
		case textparse.EntrySeries:
			series, timestampMillis, value := parser.Series()
			fmt.Fprintf(&out, "series %s %016x %s", quote(series), math.Float64bits(value), formatTimestamp(timestampMillis))
			parser.Labels(&labelSet)
			writeLabels(&out, labelSet)
			var ex exemplar.Exemplar
			if parser.Exemplar(&ex) {
				writeExemplar(&out, ex)
			}
			writeStartTimestamp(&out, parser, startTimestamps)
		case textparse.EntryHistogram:
			series, timestampMillis, h, fh := parser.Histogram()
			fmt.Fprintf(&out, "histogram %s %s", quote(series), formatTimestamp(timestampMillis))
			if h != nil {
				fmt.Fprintf(&out, " int schema=%d count=%d sum=%016x zero_threshold=%016x zero_count=%d hint=%d pos_spans=%s pos=%s neg_spans=%s neg=%s custom=%s",
					h.Schema, h.Count, math.Float64bits(h.Sum), math.Float64bits(h.ZeroThreshold), h.ZeroCount, h.CounterResetHint,
					formatSpans(h.PositiveSpans), formatInts(h.PositiveBuckets), formatSpans(h.NegativeSpans), formatInts(h.NegativeBuckets), formatFloats(h.CustomValues))
			} else {
				fmt.Fprintf(&out, " float schema=%d count=%016x sum=%016x zero_threshold=%016x zero_count=%016x hint=%d pos_spans=%s pos=%s neg_spans=%s neg=%s custom=%s",
					fh.Schema, math.Float64bits(fh.Count), math.Float64bits(fh.Sum), math.Float64bits(fh.ZeroThreshold), math.Float64bits(fh.ZeroCount), fh.CounterResetHint,
					formatSpans(fh.PositiveSpans), formatFloats(fh.PositiveBuckets), formatSpans(fh.NegativeSpans), formatFloats(fh.NegativeBuckets), formatFloats(fh.CustomValues))
			}
			parser.Labels(&labelSet)
			writeLabels(&out, labelSet)
			// Native histograms can have several exemplars.
			var ex exemplar.Exemplar
			for parser.Exemplar(&ex) {
				writeExemplar(&out, ex)
				ex = exemplar.Exemplar{}
			}
			writeStartTimestamp(&out, parser, startTimestamps)
		}
	}
}

func writeExemplar(out *strings.Builder, ex exemplar.Exemplar) {
	var exemplarTimestamp *int64
	if ex.HasTs {
		exemplarTimestamp = &ex.Ts
	}
	fmt.Fprintf(out, "exemplar %016x %s", math.Float64bits(ex.Value), formatTimestamp(exemplarTimestamp))
	writeLabels(out, ex.Labels)
}

func writeStartTimestamp(out *strings.Builder, parser textparse.Parser, startTimestamps bool) {
	// StartTimestamp peeks ahead and overwrites the series, offsets and
	// value, so it runs last.
	if startTimestamps {
		fmt.Fprintf(out, "st %d\n", parser.StartTimestamp())
	}
}

func formatSpans(spans []histogram.Span) string {
	parts := make([]string, len(spans))
	for i, span := range spans {
		parts[i] = fmt.Sprintf("%d:%d", span.Offset, span.Length)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func formatInts(buckets []int64) string {
	parts := make([]string, len(buckets))
	for i, bucket := range buckets {
		parts[i] = strconv.FormatInt(bucket, 10)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func formatFloats(buckets []float64) string {
	parts := make([]string, len(buckets))
	for i, bucket := range buckets {
		parts[i] = fmt.Sprintf("%016x", math.Float64bits(bucket))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func formatTimestamp(millis *int64) string {
	if millis == nil {
		return "-"
	}
	return strconv.FormatInt(*millis, 10)
}

// writeLabels ends the current line.
func writeLabels(out *strings.Builder, labelSet labels.Labels) {
	labelSet.Range(func(label labels.Label) {
		fmt.Fprintf(out, " %s=%s", quote([]byte(label.Name)), quote([]byte(label.Value)))
	})
	out.WriteString("\n")
}

// quote escapes bytes instead of runes so Rust can reproduce it without Go's
// strconv.Quote rules for non-printable Unicode.
func quote(raw []byte) string {
	var out strings.Builder
	out.WriteByte('"')
	for _, rawByte := range raw {
		switch {
		case rawByte == '\\' || rawByte == '"':
			out.WriteByte('\\')
			out.WriteByte(rawByte)
		case rawByte < 0x20 || rawByte == 0x7f:
			fmt.Fprintf(&out, `\x%02x`, rawByte)
		default:
			out.WriteByte(rawByte)
		}
	}
	out.WriteByte('"')
	return out.String()
}
