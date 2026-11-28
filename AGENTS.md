# AGENTS.md

Rust libraries for Prometheus and OpenMetrics scrape pipelines. See [README.md](README.md) for scope and layout.

## Build tools

Builds and checks run through the root [`mise.toml`](mise.toml) tasks, which compile with
[mbx](https://mr-boxington.jdx.dev/)'s shared compiler cache. `rust-toolchain.toml` owns the
compiler pin for rustup, mise, and CI; `Cargo.toml` records the MSRV. Set up a checkout with:

```sh
mise trust
mise install
```

Use `mise tasks` to list tasks. Plain Cargo still works, it just misses mbx's cache. After
changing a tool version, run `mise lock` and commit the updated `mise.lock`.

## Verify your change

Run these before you push. CI runs the same tasks, see [.github/workflows/ci.yml](.github/workflows/ci.yml).

```sh
mise run fmt-check
mise run lint
mise run lint-no-default
mise run test
mise run test-no-default
```

`mise run ci` runs all of them in CI order, plus the OTAP compatibility suite below.

If you touch `crates/expfmt/src/arrow`, also run the OTAP compatibility suite. It is a separate
workspace with its own manifest:

```sh
mise run otap-lint
mise run otap-test
```

Do not use Rust language or std features newer than `rust-version` in `Cargo.toml`. The pinned
toolchain is far newer than the MSRV, so a feature that compiles locally can still break the
`msrv` CI job.

## Spec

[specs/SPEC.md](specs/SPEC.md) is the specification contract for `scrape.rs` (`prometheus-expfmt`, `prometheus-relabel`, and `prometheus-scrape-manager`). If you change behavior the spec describes, update the spec in the same PR.

## Test data

Do not edit files under `testdata/` by hand. They are generated from the Go modules pinned in `tests/go-harness/go.mod`. To regenerate them (requires Go):

```sh
cd tests/go-harness && go generate ./... && go test ./...
```

CI regenerates them and fails if `git diff --exit-code testdata` shows a change.

## Go is the reference

The Go code in `prometheus/prometheus` (`model/textparse`) and `prometheus/common` (`expfmt`) is the reference. Expected outputs in `testdata/` come from running the Go parsers. If Rust and Go disagree, fix the Rust code, not the fixture.

If Rust must differ from Go on purpose, explain each difference in the PR body with a permalink to the Go code.

## Performance and benchmarks

- Write all benchmarks with [`benchfmt.rs`](https://github.com/bwplotka/benchfmt.rs) using `benchfmt::Suite` and `benchfmt::CountingAlloc` in `harness = false` `[[bench]]` targets so every benchmark emits Go [Benchmark Data Format](https://go.googlesource.com/proposal/+/master/design/14313-benchmark-format.md) lines with `ns/op`, `MB/s`, `B/op`, and `allocs/op` for [`benchstat`](https://pkg.go.dev/golang.org/x/perf/cmd/benchstat). Do not use Criterion or custom benchmark output formats.
- Name benchmarks with `/key=value` sub-benchmark dimensions such as `Decode/case=alltypes.237mfs/mode=decode`, call `b.report_allocs()` and `while b.keep_running()`, and include a `Recommended CLI invocation:` doc comment at the top of each benchmark file.
- Performance improvements and hot-path changes require running benchmarks before and after the change, for example `mise run bench -p prometheus-expfmt --bench decode -- -- -bench '^BenchmarkDecode' -benchtime 1s -count 6 -cpu 2 -benchmem | tee ${bench}.txt` (mise eats the first `--`, so benchmark flags need two), and comparing with `benchstat before.txt after.txt`.
- Always output benchmark results in raw `benchstat` format in the PR body and review comments, and always include links to the exact `before` and `after` commits that the benchmark refers to. Rerun benchmarks and update the commit links whenever addressing review comments that touch benchmarked code or benchmarks.
- If a subset of benchmark results shows a regression, address it or explain in the PR body why that case is not important.
- Reuse allocations in hot paths where possible, such as `Vec::clear`, scratch buffers, and interner arenas. When reusing buffers exposed through APIs or traits, document lifetime and copy requirements on the trait or type definition.

## Commits and PRs

- Sign off every commit with `git commit -s` (DCO).
- PR titles use `<area>: <summary>`, for example `parse: add OpenMetrics 1.0 parser`.
- Link the GitHub issue the PR closes.
