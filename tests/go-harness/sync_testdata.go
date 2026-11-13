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

//go:generate go run .

// Command sync_testdata resolves the pinned github.com/prometheus/common and
// github.com/prometheus/prometheus modules from go.mod, copies their expfmt and
// model/textparse testdata files, and extracts canonical parser test inputs from
// model/textparse/*_test.go into the repository's top-level testdata/ directory.
// It also writes the entries textparse.NewPromParser returns for each Prometheus
// text fixture to testdata/promparse/, and the entries
// textparse.NewOpenMetricsParser returns for each OpenMetrics fixture to
// testdata/omparse/. It also marshals the createTestProtoBuf and
// TestProtobufParseWithNHCB inputs from protobufparse_test.go into
// testdata/textparse/TestProtobufParse.pb and TestProtobufParseWithNHCB.pb, and writes
// the entries textparse.NewProtobufParser returns to testdata/protobufparse/, with
// classic histograms converted to NHCB. It also marshals the hand-written NHCB
// cases from testdata/nhcb/*.prototxt to testdata/nhcb/*.pb.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	_ "github.com/prometheus/common/expfmt"
)

type moduleInfo struct {
	Path    string `json:"path"`
	Version string `json:"version"`
	Dir     string `json:"dir"`
}

type manifest struct {
	Modules map[string]string `json:"modules"`
	Files   []string          `json:"files"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "sync_testdata: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	commonMod, err := resolveModule("github.com/prometheus/common")
	if err != nil {
		return err
	}
	promMod, err := resolveModule("github.com/prometheus/prometheus")
	if err != nil {
		return err
	}

	outRoot := filepath.Clean(filepath.Join("..", "..", "testdata"))
	if err := os.RemoveAll(outRoot); err != nil {
		return fmt.Errorf("clean %s: %w", outRoot, err)
	}

	var synced []string

	expfmtSrc := filepath.Join(commonMod.Dir, "expfmt", "testdata")
	expfmtDst := filepath.Join(outRoot, "expfmt")
	expfmtFiles, err := copyDirFiles(expfmtSrc, expfmtDst, outRoot)
	if err != nil {
		return err
	}
	synced = append(synced, expfmtFiles...)

	textparseSrc := filepath.Join(promMod.Dir, "model", "textparse", "testdata")
	textparseDst := filepath.Join(outRoot, "textparse")
	textparseFiles, err := copyDirFiles(textparseSrc, textparseDst, outRoot)
	if err != nil {
		return err
	}
	synced = append(synced, textparseFiles...)

	omErrorFiles, err := copyDirFiles(filepath.Join("testdata", "omerrors"), filepath.Join(outRoot, "omerrors"), outRoot)
	if err != nil {
		return err
	}
	synced = append(synced, omErrorFiles...)

	astExtracts := []struct {
		srcFile  string
		funcName string
		outName  string
	}{
		{
			srcFile:  filepath.Join(promMod.Dir, "model", "textparse", "promparse_test.go"),
			funcName: "TestPromParse",
			outName:  "TestPromParse.prom.txt",
		},
		{
			srcFile:  filepath.Join(promMod.Dir, "model", "textparse", "openmetricsparse_test.go"),
			funcName: "TestOpenMetricsParse",
			outName:  "TestOpenMetricsParse.om.txt",
		},
		{
			srcFile:  filepath.Join(promMod.Dir, "model", "textparse", "openmetricsparse_test.go"),
			funcName: "TestOpenMetricsParse_UTF8",
			outName:  "TestOpenMetricsParse_UTF8.om.txt",
		},
		{
			srcFile:  filepath.Join(promMod.Dir, "model", "textparse", "openmetrics2parse_test.go"),
			funcName: "TestOpenMetrics2Parse",
			outName:  "TestOpenMetrics2Parse.om2.txt",
		},
	}

	for _, ex := range astExtracts {
		input, err := extractFuncInputLiteral(ex.srcFile, ex.funcName)
		if err != nil {
			return err
		}
		dstPath := filepath.Join(textparseDst, ex.outName)
		if err := os.WriteFile(dstPath, []byte(input), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", dstPath, err)
		}
		rel, err := filepath.Rel(outRoot, dstPath)
		if err != nil {
			return err
		}
		synced = append(synced, filepath.ToSlash(rel))
	}

	protobufInputs, err := writeProtobufParseInputs(outRoot, filepath.Join(promMod.Dir, "model", "textparse", "protobufparse_test.go"))
	if err != nil {
		return err
	}
	synced = append(synced, protobufInputs...)

	nhcbInputs, err := writeNHCBInputs(outRoot)
	if err != nil {
		return err
	}
	synced = append(synced, nhcbInputs...)

	promParseFiles, err := writePromParseExpected(outRoot)
	if err != nil {
		return err
	}
	synced = append(synced, promParseFiles...)

	omParseFiles, err := writeOMParseExpected(outRoot)
	if err != nil {
		return err
	}
	synced = append(synced, omParseFiles...)

	protobufParseFiles, err := writeProtobufParseExpected(outRoot, nhcbInputs)
	if err != nil {
		return err
	}
	synced = append(synced, protobufParseFiles...)

	sort.Strings(synced)
	m := manifest{
		Modules: map[string]string{
			commonMod.Path: commonMod.Version,
			promMod.Path:   promMod.Version,
		},
		Files: synced,
	}
	manifestBytes, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := os.WriteFile(filepath.Join(outRoot, "manifest.json"), manifestBytes, 0o644); err != nil {
		return fmt.Errorf("write manifest.json: %w", err)
	}

	return nil
}

func resolveModule(modPath string) (moduleInfo, error) {
	// Ensure module source is downloaded in the local module cache.
	dlCmd := exec.Command("go", "mod", "download", "-json", modPath)
	var dlOut bytes.Buffer
	dlCmd.Stdout = &dlOut
	dlCmd.Stderr = os.Stderr
	if err := dlCmd.Run(); err != nil {
		return moduleInfo{}, fmt.Errorf("go mod download %s: %w", modPath, err)
	}
	var info moduleInfo
	if err := json.Unmarshal(dlOut.Bytes(), &info); err != nil {
		return moduleInfo{}, fmt.Errorf("unmarshal module info for %s: %w", modPath, err)
	}
	if info.Dir == "" {
		return moduleInfo{}, fmt.Errorf("empty module dir for %s", modPath)
	}
	return info, nil
}

func copyDirFiles(srcDir, dstDir, outRoot string) ([]string, error) {
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", dstDir, err)
	}
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return nil, fmt.Errorf("readdir %s: %w", srcDir, err)
	}
	var copied []string
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), "json") {
			continue
		}
		srcPath := filepath.Join(srcDir, entry.Name())
		data, err := os.ReadFile(srcPath)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", srcPath, err)
		}
		dstPath := filepath.Join(dstDir, entry.Name())
		if err := os.WriteFile(dstPath, data, 0o644); err != nil {
			return nil, fmt.Errorf("write %s: %w", dstPath, err)
		}
		rel, err := filepath.Rel(outRoot, dstPath)
		if err != nil {
			return nil, err
		}
		copied = append(copied, filepath.ToSlash(rel))
	}
	return copied, nil
}

// extractFuncInputLiteral parses srcFile with go/parser and extracts the string literal
// assigned to `input := ...` at the top level of funcName, followed by every top-level
// `input += ...` literal, in source order. Assignments inside nested blocks are ignored
// because they belong to subtests or conditional paths, not to the shared input.
func extractFuncInputLiteral(srcFile, funcName string) (string, error) {
	fset, assigns, err := topLevelAssigns(srcFile, funcName, "input")
	if err != nil {
		return "", err
	}
	var extracted string
	var found bool
	for _, assign := range assigns {
		pos := fset.Position(assign.Pos())
		if !found && assign.Tok != token.DEFINE {
			continue
		}
		if found && assign.Tok != token.ADD_ASSIGN {
			return "", fmt.Errorf("%s: unsupported input %s in %s", pos, assign.Tok, funcName)
		}
		val, ok := evalStringExpr(assign.Rhs[0])
		if !ok {
			return "", fmt.Errorf("%s: input %s with a non-literal expression in %s", pos, assign.Tok, funcName)
		}
		extracted += val
		found = true
	}
	if !found {
		return "", fmt.Errorf("could not find input literal in %s (%s)", funcName, srcFile)
	}
	return extracted, nil
}

// topLevelAssigns returns the single-value assignments to varName in the body of
// funcName, in source order, skipping nested blocks.
func topLevelAssigns(srcFile, funcName, varName string) (*token.FileSet, []*ast.AssignStmt, error) {
	fset := token.NewFileSet()
	fileNode, err := parser.ParseFile(fset, srcFile, nil, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("parse %s: %w", srcFile, err)
	}
	var assigns []*ast.AssignStmt
	for _, decl := range fileNode.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != funcName || fn.Body == nil {
			continue
		}
		for _, stmt := range fn.Body.List {
			assign, ok := stmt.(*ast.AssignStmt)
			if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
				continue
			}
			if ident, ok := assign.Lhs[0].(*ast.Ident); ok && ident.Name == varName {
				assigns = append(assigns, assign)
			}
		}
	}
	return fset, assigns, nil
}

func evalStringExpr(expr ast.Expr) (string, bool) {
	switch typedExpr := expr.(type) {
	case *ast.BasicLit:
		if typedExpr.Kind != token.STRING {
			return "", false
		}
		unquoted, err := strconv.Unquote(typedExpr.Value)
		if err != nil {
			return "", false
		}
		return unquoted, true
	case *ast.BinaryExpr:
		if typedExpr.Op != token.ADD {
			return "", false
		}
		left, ok := evalStringExpr(typedExpr.X)
		if !ok {
			return "", false
		}
		right, ok := evalStringExpr(typedExpr.Y)
		if !ok {
			return "", false
		}
		return left + right, true
	default:
		return "", false
	}
}

// extractFuncStringSlice returns the elements of the []string literal assigned to
// varName at the top level of funcName.
func extractFuncStringSlice(srcFile, funcName, varName string) ([]string, error) {
	fset, assigns, err := topLevelAssigns(srcFile, funcName, varName)
	if err != nil {
		return nil, err
	}
	if len(assigns) == 0 {
		return nil, fmt.Errorf("could not find %s in %s (%s)", varName, funcName, srcFile)
	}
	lit, ok := assigns[0].Rhs[0].(*ast.CompositeLit)
	if !ok {
		return nil, fmt.Errorf("%s: %s is not a composite literal", fset.Position(assigns[0].Pos()), varName)
	}
	var out []string
	for _, elt := range lit.Elts {
		val, ok := evalStringExpr(elt)
		if !ok {
			return nil, fmt.Errorf("%s: non-literal element in %s", fset.Position(elt.Pos()), varName)
		}
		out = append(out, val)
	}
	return out, nil
}
