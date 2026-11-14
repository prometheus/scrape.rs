# AGENTS.md

Rust libraries for Prometheus and OpenMetrics scrape pipelines. See [README.md](README.md) for scope and layout.

## Verify your change

Run these before you push. CI runs the same commands, see [.github/workflows/ci.yml](.github/workflows/ci.yml).

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo clippy --workspace --all-targets --no-default-features -- -D warnings
cargo test --workspace --all-features
cargo test --workspace --no-default-features
```

If you touch `crates/expfmt/src/arrow`, also run the OTAP compatibility suite. It has its own manifest:

```sh
cargo test --manifest-path tests/otap-compat/Cargo.toml
```

Do not use Rust language or std features newer than `rust-version` in `Cargo.toml`.

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
- Performance improvements and hot-path changes require running benchmarks before and after the change, for example `cargo bench -p prometheus-expfmt --bench decode -- -bench '^BenchmarkDecode' -benchtime 1s -count 6 -cpu 2 -benchmem | tee ${bench}.txt`, and comparing with `benchstat before.txt after.txt`.
- Always output benchmark results in raw `benchstat` format in the PR body and review comments, and always include links to the exact `before` and `after` commits that the benchmark refers to. Rerun benchmarks and update the commit links whenever addressing review comments that touch benchmarked code or benchmarks.
- If a subset of benchmark results shows a regression, address it or explain in the PR body why that case is not important.
- If the measured spread is wider than the effect you are claiming, still include the raw `benchstat` output, but do not present the delta as a result: say that no difference is measurable at that noise level, and cite `B/op` and `allocs/op`, which are usually stable across runs. An interval that overlaps the change is not evidence, and publishing it as a delta makes it read as one.
- Reuse allocations in hot paths where possible, such as `Vec::clear`, scratch buffers, and interner arenas. When reusing buffers exposed through APIs or traits, document lifetime and copy requirements on the trait or type definition.

## Commits and PRs

- Sign off every commit with `git commit -s` (DCO).
- PR titles use `<area>: <summary>`, for example `parse: add OpenMetrics 1.0 parser`.
- Link the GitHub issue the PR closes.

### Before you open the PR

Run these three audits once the checks in `Verify your change` pass. Each is one command or one read, and each catches a class of mistake that reviewing the diff cannot see.

- **Tree audit.** Run `git grep -n <the identifier you added or renamed>` over the whole workspace: code, tests, comments, TODOs, `specs/`, and this file. Anything that keys off the old name or the old assumption — a second call site, a TODO pointing at an issue this PR closes — shows up here and nowhere else.
- **Claims audit.** Make sure you can point at the line you read or the command you ran for every claim the PR body makes about behaviour. Drop or qualify the ones you cannot. "No intentional differences from Go" is a claim about an enumeration: write the enumeration, or delete the sentence.
- **Issue audit.** Use `Fixes #N` only when the diff satisfies every acceptance criterion in #N. If part of the issue needs another PR, use `Refs #N`, and repoint the TODOs and docs that name #N at the follow-up. A body that lists work as out of scope cannot also close the issue that asks for it.

For a change of a few hundred lines or more, treat the three as a loop: fix, re-audit, repeat until a pass turns up nothing.
