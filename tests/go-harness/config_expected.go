package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type ConfigExpectations struct {
	ExpectedErrors            []ConfigErrorCase             `json:"expected_errors"`
	GetScrapeConfigsCases     []GetScrapeConfigsCase        `json:"get_scrape_configs_cases"`
	ValidationSettingsCases   []ValidationSettingsCase      `json:"validation_settings_cases"`
	EscapingSettingsCases     []EscapingSettingsCase        `json:"escaping_settings_cases"`
	InvalidHTTPClientConfigs  []ConfigErrorCase             `json:"invalid_http_client_configs"`
	ValidTLSConfigs           []ValidTLSConfigCase          `json:"valid_tls_configs"`
	InvalidTLSConfigs         []ConfigErrorCase             `json:"invalid_tls_configs"`
}

type ConfigErrorCase struct {
	Filename string `json:"filename"`
	ErrMsg   string `json:"err_msg"`
}

type GetScrapeConfigsCase struct {
	ConfigFile                     string   `json:"config_file"`
	ErrMsg                         string   `json:"err_msg,omitempty"`
	JobNames                       []string `json:"job_names,omitempty"`
	ScrapeProtocols                []string `json:"scrape_protocols,omitempty"`
	ScrapeNativeHistograms         *bool    `json:"scrape_native_histograms,omitempty"`
	AlwaysScrapeClassicHistograms  *bool    `json:"always_scrape_classic_histograms,omitempty"`
	ConvertClassicHistogramsToNHCB *bool    `json:"convert_classic_histograms_to_nhcb,omitempty"`
	ExtraScrapeMetrics             *bool    `json:"extra_scrape_metrics,omitempty"`
}

type ValidationSettingsCase struct {
	Name                   string `json:"name"`
	Filename               string `json:"filename"`
	ExpectValidationScheme string `json:"expect_validation_scheme"`
	ExpectEscapingScheme   string `json:"expect_escaping_scheme"`
}

type EscapingSettingsCase struct {
	Name                   string `json:"name"`
	Filename               string `json:"filename"`
	ExpectValidationScheme string `json:"expect_validation_scheme"`
	ExpectEscapingScheme   string `json:"expect_escaping_scheme"`
}

type ValidTLSConfigCase struct {
	Filename           string `json:"filename"`
	MinVersion         string `json:"min_version,omitempty"`
	MaxVersion         string `json:"max_version,omitempty"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty"`
}

func writeConfigExpected(outRoot, promDir, commonDir string) ([]string, error) {
	dstDir := filepath.Join(outRoot, "config_expected")
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", dstDir, err)
	}

	var out ConfigExpectations

	if err := parsePromConfigTests(filepath.Join(promDir, "config", "config_test.go"), &out); err != nil {
		return nil, fmt.Errorf("parse prometheus config_test.go: %w", err)
	}
	if err := parseCommonHTTPConfigTests(filepath.Join(commonDir, "config", "http_config_test.go"), &out); err != nil {
		return nil, fmt.Errorf("parse common http_config_test.go: %w", err)
	}
	if err := parseCommonTLSConfigTests(filepath.Join(commonDir, "config", "tls_config_test.go"), &out); err != nil {
		return nil, fmt.Errorf("parse common tls_config_test.go: %w", err)
	}

	outPath := filepath.Join(dstDir, "expectations.json")
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal %s: %w", outPath, err)
	}
	b = append(b, '\n')
	if err := os.WriteFile(outPath, b, 0o644); err != nil {
		return nil, fmt.Errorf("write %s: %w", outPath, err)
	}

	rel, err := filepath.Rel(outRoot, outPath)
	if err != nil {
		return nil, err
	}
	return []string{filepath.ToSlash(rel)}, nil
}

func parsePromConfigTests(testFile string, out *ConfigExpectations) error {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, testFile, nil, 0)
	if err != nil {
		return err
	}

	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok || len(vs.Names) == 0 || len(vs.Values) == 0 {
					continue
				}
				if vs.Names[0].Name == "expectedErrors" {
					out.ExpectedErrors = extractConfigErrorSlice(vs.Values[0], "filename", "errMsg")
				}
			}
		case *ast.FuncDecl:
			switch d.Name.Name {
			case "TestGetScrapeConfigs":
				out.GetScrapeConfigsCases = extractGetScrapeConfigsCases(d.Body)
			case "TestScrapeConfigNameValidationSettings":
				out.ValidationSettingsCases = extractValidationSettingsCases(d.Body)
			case "TestScrapeConfigNameEscapingSettings":
				out.EscapingSettingsCases = extractEscapingSettingsCases(d.Body)
			}
		}
	}
	return nil
}

func parseCommonHTTPConfigTests(testFile string, out *ConfigExpectations) error {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, testFile, nil, 0)
	if err != nil {
		return err
	}
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) == 0 || len(vs.Values) == 0 {
				continue
			}
			if vs.Names[0].Name == "invalidHTTPClientConfigs" {
				cases := extractConfigErrorSlice(vs.Values[0], "httpClientConfigFile", "errMsg")
				for i := range cases {
					cases[i].Filename = strings.TrimPrefix(cases[i].Filename, "testdata/")
				}
				out.InvalidHTTPClientConfigs = cases
			}
		}
	}
	return nil
}

func parseCommonTLSConfigTests(testFile string, out *ConfigExpectations) error {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, testFile, nil, 0)
	if err != nil {
		return err
	}
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) == 0 || len(vs.Values) == 0 {
				continue
			}
			switch vs.Names[0].Name {
			case "expectedTLSConfigs":
				out.ValidTLSConfigs = extractValidTLSConfigs(vs.Values[0])
			case "invalidTLSConfigs":
				out.InvalidTLSConfigs = extractConfigErrorSlice(vs.Values[0], "filename", "errMsg")
			}
		}
	}
	return nil
}

func extractConfigErrorSlice(expr ast.Expr, fileField, errField string) []ConfigErrorCase {
	comp, ok := expr.(*ast.CompositeLit)
	if !ok {
		return nil
	}
	var res []ConfigErrorCase
	for _, elt := range comp.Elts {
		item, ok := elt.(*ast.CompositeLit)
		if !ok {
			continue
		}
		var tc ConfigErrorCase
		for _, kvExpr := range item.Elts {
			kv, ok := kvExpr.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			ident, ok := kv.Key.(*ast.Ident)
			if !ok {
				continue
			}
			switch ident.Name {
			case fileField:
				tc.Filename = evalStringLiteral(kv.Value)
			case errField:
				tc.ErrMsg = evalStringLiteral(kv.Value)
			}
		}
		if tc.Filename != "" {
			res = append(res, tc)
		}
	}
	return res
}

func extractGetScrapeConfigsCases(body *ast.BlockStmt) []GetScrapeConfigsCase {
	var res []GetScrapeConfigsCase
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) == 0 || len(assign.Rhs) == 0 {
			return true
		}
		ident, ok := assign.Lhs[0].(*ast.Ident)
		if !ok || ident.Name != "testCases" {
			return true
		}
		comp, ok := assign.Rhs[0].(*ast.CompositeLit)
		if !ok {
			return false
		}
		for _, elt := range comp.Elts {
			item, ok := elt.(*ast.CompositeLit)
			if !ok {
				continue
			}
			var tc GetScrapeConfigsCase
			for _, kvExpr := range item.Elts {
				kv, ok := kvExpr.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				keyIdent, ok := kv.Key.(*ast.Ident)
				if !ok {
					continue
				}
				switch keyIdent.Name {
				case "configFile":
					tc.ConfigFile = strings.TrimPrefix(evalStringLiteral(kv.Value), "testdata/")
				case "expectedError", "errMsg":
					tc.ErrMsg = evalStringLiteral(kv.Value)
				case "expectedResult", "scrapeConfigs":
					extractExpectedScrapeConfigs(kv.Value, &tc)
				}
			}
			if tc.ConfigFile != "" {
				res = append(res, tc)
			}
		}
		return false
	})
	return res
}

func extractExpectedScrapeConfigs(expr ast.Expr, tc *GetScrapeConfigsCase) {
	comp, ok := expr.(*ast.CompositeLit)
	if !ok {
		return
	}
	for idx, elt := range comp.Elts {
		scComp := unwrapCompositeLit(elt)
		if scComp == nil {
			continue
		}
		for _, kvExpr := range scComp.Elts {
			kv, ok := kvExpr.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			keyIdent, ok := kv.Key.(*ast.Ident)
			if !ok {
				continue
			}
			switch keyIdent.Name {
			case "JobName":
				tc.JobNames = append(tc.JobNames, evalStringLiteral(kv.Value))
			case "ScrapeProtocols":
				if idx == 0 {
					tc.ScrapeProtocols = evalScrapeProtocolsExpr(kv.Value)
				}
			case "ScrapeNativeHistograms":
				if idx == 0 {
					tc.ScrapeNativeHistograms = evalBoolPtrExpr(kv.Value)
				}
			case "AlwaysScrapeClassicHistograms":
				if idx == 0 {
					tc.AlwaysScrapeClassicHistograms = evalBoolPtrExpr(kv.Value)
				}
			case "ConvertClassicHistogramsToNHCB", "ConvertClassicHistToNHCB":
				if idx == 0 {
					tc.ConvertClassicHistogramsToNHCB = evalBoolPtrExpr(kv.Value)
				}
			case "ExtraScrapeMetrics":
				if idx == 0 {
					tc.ExtraScrapeMetrics = evalBoolPtrExpr(kv.Value)
				}
			}
		}
	}
}

func unwrapCompositeLit(expr ast.Expr) *ast.CompositeLit {
	switch e := expr.(type) {
	case *ast.CompositeLit:
		return e
	case *ast.UnaryExpr:
		if c, ok := e.X.(*ast.CompositeLit); ok {
			return c
		}
	case *ast.CallExpr:
		if len(e.Args) == 1 {
			return unwrapCompositeLit(e.Args[0])
		}
	}
	return nil
}

func evalScrapeProtocolsExpr(expr ast.Expr) []string {
	switch e := expr.(type) {
	case *ast.Ident:
		switch e.Name {
		case "DefaultScrapeProtocols":
			return []string{"OpenMetricsText1.0.0", "OpenMetricsText0.0.1", "PrometheusText1.0.0", "PrometheusText0.0.4"}
		case "DefaultProtoFirstScrapeProtocols":
			return []string{"PrometheusProto", "OpenMetricsText1.0.0", "OpenMetricsText0.0.1", "PrometheusText1.0.0", "PrometheusText0.0.4"}
		}
	case *ast.CompositeLit:
		var res []string
		for _, elt := range e.Elts {
			if id, ok := elt.(*ast.Ident); ok {
				if p := mapProtocolIdent(id.Name); p != "" {
					res = append(res, p)
				}
			}
		}
		return res
	}
	return nil
}

func mapProtocolIdent(name string) string {
	switch name {
	case "PrometheusProto":
		return "PrometheusProto"
	case "PrometheusText0_0_4":
		return "PrometheusText0.0.4"
	case "PrometheusText1_0_0":
		return "PrometheusText1.0.0"
	case "OpenMetricsText0_0_1":
		return "OpenMetricsText0.0.1"
	case "OpenMetricsText1_0_0":
		return "OpenMetricsText1.0.0"
	case "OpenMetricsText2_0_0":
		return "OpenMetricsText2.0.0"
	}
	return ""
}

func evalBoolPtrExpr(expr ast.Expr) *bool {
	switch e := expr.(type) {
	case *ast.Ident:
		switch e.Name {
		case "true":
			v := true
			return &v
		case "false":
			v := false
			return &v
		}
	case *ast.CallExpr:
		if len(e.Args) == 1 {
			return evalBoolPtrExpr(e.Args[0])
		}
	}
	return nil
}

func extractValidationSettingsCases(body *ast.BlockStmt) []ValidationSettingsCase {
	var res []ValidationSettingsCase
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) == 0 || len(assign.Rhs) == 0 {
			return true
		}
		ident, ok := assign.Lhs[0].(*ast.Ident)
		if !ok || ident.Name != "tests" {
			return true
		}
		comp, ok := assign.Rhs[0].(*ast.CompositeLit)
		if !ok {
			return false
		}
		for _, elt := range comp.Elts {
			item, ok := elt.(*ast.CompositeLit)
			if !ok {
				continue
			}
			var tc ValidationSettingsCase
			for _, kvExpr := range item.Elts {
				kv, ok := kvExpr.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				keyIdent, ok := kv.Key.(*ast.Ident)
				if !ok {
					continue
				}
				switch keyIdent.Name {
				case "name":
					tc.Name = evalStringLiteral(kv.Value)
				case "inputFile":
					tc.Filename = evalStringLiteral(kv.Value) + ".yml"
				case "expectScheme":
					tc.ExpectValidationScheme = evalModelConstant(kv.Value)
				case "expectEscaping":
					tc.ExpectEscapingScheme = evalModelConstant(kv.Value)
				}
			}
			if tc.Filename != "" {
				res = append(res, tc)
			}
		}
		return false
	})
	return res
}

func extractEscapingSettingsCases(body *ast.BlockStmt) []EscapingSettingsCase {
	var res []EscapingSettingsCase
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) == 0 || len(assign.Rhs) == 0 {
			return true
		}
		ident, ok := assign.Lhs[0].(*ast.Ident)
		if !ok || ident.Name != "tests" {
			return true
		}
		comp, ok := assign.Rhs[0].(*ast.CompositeLit)
		if !ok {
			return false
		}
		for _, elt := range comp.Elts {
			item, ok := elt.(*ast.CompositeLit)
			if !ok {
				continue
			}
			var tc EscapingSettingsCase
			for _, kvExpr := range item.Elts {
				kv, ok := kvExpr.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				keyIdent, ok := kv.Key.(*ast.Ident)
				if !ok {
					continue
				}
				switch keyIdent.Name {
				case "name":
					tc.Name = evalStringLiteral(kv.Value)
				case "inputFile":
					tc.Filename = evalStringLiteral(kv.Value) + ".yml"
				case "expectValidationScheme":
					tc.ExpectValidationScheme = evalModelConstant(kv.Value)
				case "expectEscapingScheme":
					tc.ExpectEscapingScheme = evalStringLiteral(kv.Value)
				}
			}
			if tc.Filename != "" {
				res = append(res, tc)
			}
		}
		return false
	})
	return res
}

func evalModelConstant(expr ast.Expr) string {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	switch sel.Sel.Name {
	case "UTF8Validation":
		return "utf8"
	case "LegacyValidation":
		return "legacy"
	case "NoEscaping":
		return "allow-utf-8"
	case "UnderscoreEscaping":
		return "underscores"
	case "DotsEscaping":
		return "dots"
	case "ValueEncodingEscaping":
		return "values"
	}
	return sel.Sel.Name
}

func extractValidTLSConfigs(expr ast.Expr) []ValidTLSConfigCase {
	comp, ok := expr.(*ast.CompositeLit)
	if !ok {
		return nil
	}
	var res []ValidTLSConfigCase
	for _, elt := range comp.Elts {
		item, ok := elt.(*ast.CompositeLit)
		if !ok {
			continue
		}
		var tc ValidTLSConfigCase
		for _, kvExpr := range item.Elts {
			kv, ok := kvExpr.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			keyIdent, ok := kv.Key.(*ast.Ident)
			if !ok {
				continue
			}
			switch keyIdent.Name {
			case "filename":
				tc.Filename = evalStringLiteral(kv.Value)
			case "config":
				cfgComp := unwrapCompositeLit(kv.Value)
				if cfgComp == nil {
					continue
				}
				for _, ckvExpr := range cfgComp.Elts {
					ckv, ok := ckvExpr.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					ckIdent, ok := ckv.Key.(*ast.Ident)
					if !ok {
						continue
					}
					switch ckIdent.Name {
					case "MinVersion":
						tc.MinVersion = evalTLSVersionExpr(ckv.Value)
					case "MaxVersion":
						tc.MaxVersion = evalTLSVersionExpr(ckv.Value)
					case "InsecureSkipVerify":
						if id, ok := ckv.Value.(*ast.Ident); ok && id.Name == "true" {
							tc.InsecureSkipVerify = true
						}
					}
				}
			}
		}
		if tc.Filename != "" {
			res = append(res, tc)
		}
	}
	return res
}

func evalTLSVersionExpr(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return strings.TrimPrefix(e.Name, "Version")
	case *ast.SelectorExpr:
		return strings.TrimPrefix(e.Sel.Name, "Version")
	}
	return ""
}

func evalStringLiteral(expr ast.Expr) string {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return ""
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return ""
	}
	return s
}
