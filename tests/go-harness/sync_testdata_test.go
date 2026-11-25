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
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"
)

func TestExtractFuncInputLiteral(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		want    string
		wantErr bool
	}{
		{
			name: "appends top-level literals in order",
			body: "input := `a\n`\n\tinput += \"b\"\n\tinput += \"\\n# EOF\\n\"",
			want: "a\nb\n# EOF\n",
		},
		{
			name: "ignores nested assignments",
			body: "input := \"a\"\n\tt.Run(\"x\", func(t *testing.T) { input := \"z\"; input += \"y\" })\n\tif true { input += \"w\" }",
			want: "a",
		},
		{
			name:    "rejects non-literal append",
			body:    "input := \"a\"\n\tinput += strings.Repeat(\"b\", 2)",
			wantErr: true,
		},
		{
			name:    "rejects reassignment",
			body:    "input := \"a\"\n\tinput = input + \"b\"",
			wantErr: true,
		},
		{
			name:    "rejects non-literal define",
			body:    "input := \"a\" + tc.input\n\tinput += \"b\"",
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srcFile := filepath.Join(t.TempDir(), "x_test.go")
			src := "package x\n\nfunc TestX(t *testing.T) {\n\t" + tc.body + "\n}\n"
			if err := os.WriteFile(srcFile, []byte(src), 0o644); err != nil {
				t.Fatal(err)
			}
			got, err := extractFuncInputLiteral(srcFile, "TestX")
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestKeyedStringsRejectsNonLiteral(t *testing.T) {
	fset := token.NewFileSet()
	expr, err := parser.ParseExprFrom(fset, "", `[]tc{{input: "a"}, {input: strings.Repeat("b", 2)}}`, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := keyedStrings(fset, expr, "input"); err == nil {
		t.Fatalf("keyedStrings = %q, want an error for the non-literal input", got)
	}
}

func TestConfigExpectationsSynced(t *testing.T) {
	promMod, err := resolveModule("github.com/prometheus/prometheus")
	if err != nil {
		t.Fatal(err)
	}
	commonMod, err := resolveModule("github.com/prometheus/common")
	if err != nil {
		t.Fatal(err)
	}

	var out ConfigExpectations
	if err := parsePromConfigTests(filepath.Join(promMod.Dir, "config", "config_test.go"), &out); err != nil {
		t.Fatal(err)
	}
	if err := parseCommonHTTPConfigTests(filepath.Join(commonMod.Dir, "config", "http_config_test.go"), &out); err != nil {
		t.Fatal(err)
	}
	if err := parseCommonTLSConfigTests(filepath.Join(commonMod.Dir, "config", "tls_config_test.go"), &out); err != nil {
		t.Fatal(err)
	}

	if len(out.ExpectedErrors) == 0 {
		t.Fatal("expected non-empty ExpectedErrors from prometheus/config/config_test.go")
	}
	if len(out.GetScrapeConfigsCases) == 0 {
		t.Fatal("expected non-empty GetScrapeConfigsCases from prometheus/config/config_test.go")
	}
	if len(out.ValidationSettingsCases) == 0 {
		t.Fatal("expected non-empty ValidationSettingsCases from prometheus/config/config_test.go")
	}
	if len(out.EscapingSettingsCases) == 0 {
		t.Fatal("expected non-empty EscapingSettingsCases from prometheus/config/config_test.go")
	}
	if len(out.InvalidHTTPClientConfigs) == 0 {
		t.Fatal("expected non-empty InvalidHTTPClientConfigs from common/config/http_config_test.go")
	}
	if len(out.ValidTLSConfigs) == 0 {
		t.Fatal("expected non-empty ValidTLSConfigs from common/config/tls_config_test.go")
	}
	if len(out.InvalidTLSConfigs) == 0 {
		t.Fatal("expected non-empty InvalidTLSConfigs from common/config/tls_config_test.go")
	}
}
