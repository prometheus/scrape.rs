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
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gogo/protobuf/proto"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/textparse"
	dto "github.com/prometheus/prometheus/prompb/io/prometheus/client"
)

// protobufParseTests maps each upstream test function to the delimited fixture
// built from its testMetricFamilies, relative to testdata/.
var protobufParseTests = map[string]string{
	"createTestProtoBuf":        "textparse/TestProtobufParse.pb",
	"TestProtobufParseWithNHCB": "textparse/TestProtobufParseWithNHCB.pb",
}

// protobufParseInputs are the delimited protobuf fixtures, relative to testdata/.
var protobufParseInputs = []string{
	"textparse/TestProtobufParse.pb",
	"textparse/TestProtobufParseWithNHCB.pb",
	"expfmt/protobuf",
	"expfmt/protobuf-multimessage",
}

func writeProtobufParseInputs(outRoot, srcFile string) ([]string, error) {
	var written []string
	for funcName, input := range protobufParseTests {
		families, err := extractFuncStringSlice(srcFile, funcName, "testMetricFamilies")
		if err != nil {
			return nil, err
		}
		if err := writeDelimited(filepath.Join(outRoot, input), families); err != nil {
			return nil, err
		}
		written = append(written, input)
	}
	return written, nil
}

// writeNHCBInputs marshals each hand-written tests/go-harness/testdata/nhcb/*.prototxt file,
// with metric families separated by "---" lines, to testdata/nhcb/*.pb.
func writeNHCBInputs(outRoot string) ([]string, error) {
	sources, err := filepath.Glob(filepath.Join("testdata", "nhcb", "*.prototxt"))
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(outRoot, "nhcb"), 0o755); err != nil {
		return nil, err
	}
	var written []string
	for _, source := range sources {
		text, err := os.ReadFile(source)
		if err != nil {
			return nil, err
		}
		input := "nhcb/" + strings.TrimSuffix(filepath.Base(source), ".prototxt") + ".pb"
		if err := writeDelimited(filepath.Join(outRoot, input), strings.Split(string(text), "\n---\n")); err != nil {
			return nil, fmt.Errorf("%s: %w", source, err)
		}
		written = append(written, input)
	}
	return written, nil
}

// writeDelimited marshals each text-format MetricFamily and writes them varint
// length-delimited to path.
func writeDelimited(path string, families []string) error {
	var out []byte
	for _, text := range families {
		var family dto.MetricFamily
		if err := proto.UnmarshalText(text, &family); err != nil {
			return fmt.Errorf("unmarshal text: %w", err)
		}
		data, err := proto.Marshal(&family)
		if err != nil {
			return fmt.Errorf("marshal %s: %w", family.GetName(), err)
		}
		out = binary.AppendUvarint(out, uint64(len(data)))
		out = append(out, data...)
	}
	return os.WriteFile(path, out, 0o644)
}

// writeProtobufParseExpected runs textparse.NewProtobufParser on each input with
// NHCB conversion on and writes one line per entry to testdata/protobufparse/.
func writeProtobufParseExpected(outRoot string, nhcbInputs []string) ([]string, error) {
	var written []string
	for _, input := range append(protobufParseInputs, nhcbInputs...) {
		err := writeExpected(outRoot, "protobufparse", input, func(data []byte) string {
			parser := textparse.NewProtobufParser(data, false, false, true, false, labels.NewSymbolTable())
			return renderEntries(parser, true)
		})
		if err != nil {
			return nil, err
		}
		written = append(written, "protobufparse/"+input)
	}
	return written, nil
}
