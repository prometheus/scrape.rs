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
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/textparse"
)

const om2TestPrefix = "TestOpenMetrics2Parse"

// om2ParseInputGlobs match the OpenMetrics 2.0 fixtures, relative to testdata/.
var om2ParseInputGlobs = []string{
	"textparse/*.om2.txt",
	"om2errors/*.om2.txt",
}

// writeOM2Cases writes the top-level input literal of every TestOpenMetrics2Parse*
// function to testdata/textparse/<func>.om2.txt, and each input of
// TestOpenMetrics2ParseErrors to testdata/om2errors/<index>.om2.txt. Functions
// without a top-level input literal are skipped.
func writeOM2Cases(outRoot, srcFile string) ([]string, error) {
	fset := token.NewFileSet()
	fileNode, err := parser.ParseFile(fset, srcFile, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", srcFile, err)
	}
	var written []string
	write := func(rel, input string) error {
		dstPath := filepath.Join(outRoot, rel)
		if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(dstPath, []byte(input), 0o644); err != nil {
			return err
		}
		written = append(written, rel)
		return nil
	}
	for _, decl := range fileNode.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		// TestOpenMetrics2Parse itself is already in astExtracts.
		if !ok || !strings.HasPrefix(fn.Name.Name, om2TestPrefix) || fn.Name.Name == om2TestPrefix {
			continue
		}
		if fn.Name.Name == om2TestPrefix+"Errors" {
			for index, input := range keyedStrings(fn.Body, "input") {
				if err := write(fmt.Sprintf("om2errors/%02d.om2.txt", index), input); err != nil {
					return nil, err
				}
			}
			continue
		}
		input, err := extractFuncInputLiteral(srcFile, fn.Name.Name)
		if err != nil {
			continue
		}
		if err := write("textparse/"+fn.Name.Name+".om2.txt", input); err != nil {
			return nil, err
		}
	}
	return written, nil
}

// keyedStrings returns the string literal values of every `key: "..."` field in
// the composite literals under node, in source order.
func keyedStrings(node ast.Node, key string) []string {
	var out []string
	ast.Inspect(node, func(n ast.Node) bool {
		kv, ok := n.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		if ident, ok := kv.Key.(*ast.Ident); ok && ident.Name == key {
			if val, ok := evalStringExpr(kv.Value); ok {
				out = append(out, val)
			}
		}
		return true
	})
	return out
}

// writeOM2ParseExpected runs textparse.NewOpenMetrics2Parser with default options
// on each input and writes its entries, with a start timestamp per series, to
// testdata/om2parse/.
func writeOM2ParseExpected(outRoot string) ([]string, error) {
	var inputs []string
	for _, glob := range om2ParseInputGlobs {
		matches, err := filepath.Glob(filepath.Join(outRoot, glob))
		if err != nil {
			return nil, fmt.Errorf("glob %s: %w", glob, err)
		}
		for _, match := range matches {
			rel, err := filepath.Rel(outRoot, match)
			if err != nil {
				return nil, err
			}
			inputs = append(inputs, filepath.ToSlash(rel))
		}
	}
	sort.Strings(inputs)

	var written []string
	for _, input := range inputs {
		err := writeExpected(outRoot, "om2parse", input, func(data []byte) string {
			parser := textparse.NewOpenMetrics2Parser(data, labels.NewSymbolTable(), textparse.ParserOptions{})
			return renderEntries(parser, true)
		})
		if err != nil {
			return nil, err
		}
		written = append(written, "om2parse/"+input)
	}
	return written, nil
}
