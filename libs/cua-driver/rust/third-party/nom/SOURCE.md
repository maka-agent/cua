# nom 1.2.4 source provenance

This directory contains the published MIT-licensed `nom 1.2.4` source used by
`meval 0.2.0`, with local compiler-compatibility fixes. It retains the existing
math-expression parser and evaluator used
for function trajectories.

- Upstream repository: <https://github.com/Geal/nom>.
- Upstream release tag: <https://github.com/Geal/nom/tree/1.2.4>.
- Published package: <https://static.crates.io/crates/nom/nom-1.2.4.crate>.
- Official registry record: <https://index.crates.io/3/n/nom>.
- Archive SHA-256: `a5b8c256fd9471521bcb84c3cdba98921497f1a331cbc15b8030fc63b82050ce`.
- Archive size: 68,547 bytes; 26 regular files; 401,321 unpacked bytes.
- License: `LICENSE`, copyright 2015 Geoffroy Couprie, retained verbatim.

All 26 files were extracted from the checksum-verified published package and
remain present. The source and manifest adaptations are listed below, and the
published-file inventory preserves every original file hash. `SOURCE.md` is the
added local provenance record. No whole-file reformatting or dependency-cache
changes are part of this adaptation.

## Expression-macro semicolons

Expression-forwarding macros must preserve the nested macro's return value.
Remove only the expansion's final semicolon so the parser result
remains the expression's value. Adding semicolons at the callers would discard
required return values.

| Original package file | Original expression-macro lines repaired |
| --- | --- |
| `src/macros.rs` | 350, 476, 482, 510, 785, 803, 868, 936, 1030, 1057, 1221, 1268, 1608, 1784, 1805, 1834, 1863, 1884, 2064, 2142, 2283, 2344, 2497 |
| `src/bytes.rs` | 450, 479, 499 |
| `src/bits.rs` | 35 |
| `src/str.rs` | 191, 232, 261 |

See the [Rust compiler lint explanation](https://doc.rust-lang.org/rustc/lints/listing/deny-by-default.html#semicolon-in-expressions-from-macros)
for the language rule. The repairs cover the listed macro forms; optional
features and future compiler versions may require additional adaptations.

`meval 0.2.0` requires `nom 1.x`. This adaptation retains that parser and its
public contract rather than migrating to a different major version.

## Additional compiler-compatibility changes

The following adaptations preserve the edition and parser without suppressing
warnings. Line numbers refer to the original package.

| File and original lines | Exact adaptation and reason |
| --- | --- |
| `src/lib.rs`: 114-117, 129-130 | Remove five empty public glob imports from `macros`, `methods`, `bytes`, `bits`, and `str`, together with the `str` import's now-unused condition. These modules expose macros through `#[macro_export]`, which already publishes them at the crate root. Keep every module and `#[macro_use]` declaration, and every exported macro. |
| `src/util.rs`: 27, 60, 62, 64, 66, 68, 70 | Remove `#[inline]` from seven required trait methods without bodies. Retain all methods and the inline attributes on their implementations. |
| `src/nom.rs`: 21; `src/stream.rs`: 80, 83, 99, 148, 310 | Add explicit `dyn` to six existing trait-object types. Their types and dispatch behavior are unchanged. |
| `src/nom.rs`: 18, 446-498 | Replace four integer-to-float transmutes with `f32::from_bits` or `f64::from_bits`, and remove the now-unused transmute import and four unsafe blocks. These safe operations preserve the same floating-point bit patterns and existing endian decoding. |
| `src/stream.rs`: 83, 127 | Spell out the already-inferred `'b` output-reference lifetime on `Producer::run` and the `'x` lifetime on `MemProducer::new`'s return type. |
| `src/stream.rs`: 231-240 | Retain the private `FileProducer::size` value and its initialization. Replace only this type's derived `Debug` with an explicit implementation that reads and formats all seven original fields in declaration order: `size`, `file`, `position`, `v`, `start`, `end`, `state`. This preserves its normal and alternate debug output, including the historical initial `size` value after buffer resizing, while resolving the unread-field warning. Buffering and resize operations are unchanged. |

The [Rust Reference](https://doc.rust-lang.org/reference/macros-by-example.html#the-macro_export-attribute)
documents root visibility for `#[macro_export]`. The standard-library
[`f32::from_bits`](https://doc.rust-lang.org/std/primitive.f32.html#method.from_bits)
and [`f64::from_bits`](https://doc.rust-lang.org/std/primitive.f64.html#method.from_bits)
operations preserve the raw integer bit representation. No public parser,
function, trait method, macro, or debug field is removed by these adaptations.

## Default-feature library-test repairs

Library-test adaptations remove redundant semicolons and unused imports, use
explicit trait objects and lifetimes, and replace invalid uninitialized arrays
in `count_fixed!` with initialized storage.

| Original package file and lines | Exact adaptation and reason |
| --- | --- |
| `src/macros.rs`: 2764, 2765, 2787, 2788, 2819, 2841, 3472, 3492, 3513 | Remove the redundant semicolon after each nested test-function definition. |
| `src/nom.rs`: 570-571 | Remove two unused test glob imports; the same variants remain available through the existing parent-module imports. |
| `src/macros.rs`: 3109, 3110, 3126, 3127; `src/nom.rs`: 888 | Add `dyn` to the five existing boxed test trait objects. |
| `src/macros.rs`: 142 | Spell the already-inferred input lifetime `'a` on both output slices in the public untyped `named!` arm. |
| `src/macros.rs`: 2316-2339 | Replace the invalid uninitialized typed array in `count_fixed!` with a fully initialized typed array of `Option` slots. Store each child-parser output in `Some` before advancing `cnt`. Only after `cnt == count`, safely map the array to its values; the `expect` states that initialization invariant. |
| `src/macros.rs`: original `count_fixed` test at 3391 | Retain its reference-array success, exact Count errors, and incomplete assertions, and extend this owner test with real `le_u16` parsing, exact integer values and remainder, short parses before and after one result, and zero-length reference/integer arrays on empty and short inputs. No old test is skipped. |

Every fixed-array slot is now valid throughout parsing. Error, incomplete, and
panic exits use ordinary safe cleanup. The existing repeat-array expression
retains the documented `Copy` contract and stack allocation; it adds no heap,
unsafe helper, count limit, or parser replacement. The temporary `Option` array
can use more stack space than the final array for some element types. Zero count
still succeeds without parsing or consuming input; child errors still return
`Error(Position(ErrorKind::Count, original_input))`; incomplete children still
return `Incomplete(Needed::Unknown)`. Successful parsing retains the same output
order and unconsumed input.

The [array repeat rules](https://doc.rust-lang.org/reference/expressions/array-expr.html),
[`Option<T>` copy implementation](https://doc.rust-lang.org/std/option/enum.Option.html#impl-Copy-for-Option%3CT%3E),
and [safe array mapping](https://doc.rust-lang.org/std/primitive.array.html#method.map)
provide the relevant language and library contracts. Default library tests need
the upstream `assets/testfile.txt`, which is omitted from the published package,
and its `LICENSE`. Integration MP4 fixtures and optional-feature suites require
their corresponding upstream assets.

## Manifest integration

The manifest adaptation is an explicit `edition = "2015"` field. This declares
the same edition Cargo previously selected implicitly and removes the
standalone manifest warning; it does not migrate the edition or dependencies.
The manifest includes that field. Its final checksum is recorded alongside the
adapted source hashes below.

## Imported whitespace cleanup

Local whitespace cleanup removes trailing spaces from two documentation lines and one
blank line in `src/macros.rs`, and from four lines in `src/methods.rs`. Remove
extra blank lines at the ends of `Cargo.toml`,
`tests/cross_function_backtracking.rs`, and `tests/mp4.rs`, retaining one final
newline in each. These edits change no non-whitespace bytes, parser logic,
assertions, or test selection. The published-file inventory below remains the
unchanged record of the original package; the adapted hashes include this cleanup.

## Workspace and downstream integration

Cua's Cargo workspace root must select this directory with its root
`[patch.crates-io]` entry. A dependent application's root must also select the
patched `nom` package: Cargo ignores patch declarations in dependencies. For a
Git-based Cua dependency, the downstream root patch must use the Cua repository
and the same pinned Cua revision that contains this directory. Updating only the
Cua workspace patch does not repair a downstream build. See
[Cargo's patch rules](https://doc.rust-lang.org/cargo/reference/overriding-dependencies.html#the-patch-section).

Validate the resolved source and a fresh dependency build in both workspaces,
and exercise `meval` function trajectories through the existing Linux tests and
behavior comparisons. No parser replacement or warning suppression is part of
this adaptation.

## Modified file checksums

The published-file inventory below retains every original checksum. These hashes
identify all adapted source, test, and manifest files, including the whitespace
cleanup above.

| File | Adapted bytes | Adapted SHA-256 |
| --- | ---: | --- |
| `Cargo.toml` | 762 | `9d11fe4cc8935694bddf9a189a06f6b5ae7b2dba37cee29669ca46fc3a56455a` |
| `src/bits.rs` | 8183 | `37a52a6fe9dd33bb41f47cb4e878d6065eba9758e39554cb22caa0cef42c86f9` |
| `src/bytes.rs` | 30187 | `7bde317ea5cfe640050bb5c64515232fd10a189e9495bbeb146fc1b1504dc39a` |
| `src/lib.rs` | 3508 | `f86a9f2970aa5f8f6fddee7d36405b0662cd83c9ca395875477fa9e51aca6737` |
| `src/macros.rs` | 121603 | `ce1291f4d46cd93528d1cd67b3fcc13169017cc66ae2913a4fa0977a90376c1e` |
| `src/methods.rs` | 18449 | `fbc59de6da647c37184bc0a370e10eddd58ba39bcfcdf8087353ead636122916` |
| `src/nom.rs` | 29481 | `ec8dfdc3450cc76d3c91e57b45300ff9ffa4beee1a195898b720180b6c854f23` |
| `src/str.rs` | 24667 | `014581a15f29e4a2d0e2e5648ba28176800b039169dc833f814a3d04daad3863` |
| `src/stream.rs` | 33633 | `02eb0d2b13d370f76fa966003b1fef2040afccbed757f392e764a6d7fd43e998` |
| `src/util.rs` | 21547 | `17f23cc280d5031c3bb2771a009eb1f4ec02317dbb21c299bd90c7f7633168b1` |
| `tests/cross_function_backtracking.rs` | 4944 | `078cd2af2bf3e24e15540b9533133a06612b093b52408bf0586ab48ffba1141b` |
| `tests/mp4.rs` | 15572 | `dbd8043b96834532039c9eec18b359885a2f00425fd161494769af3205bbe2c0` |

## Published file inventory

These hashes describe the original package files, before the local adaptations.

| File | Original bytes | Original SHA-256 |
| --- | ---: | --- |
| `.gitignore` | 99 | `7bfb566b7f653af2deb960af86cb098f21a6d0007e1d823d230cc9881b9d97ef` |
| `.travis.yml` | 1104 | `6d4e81838b10c5e330749857c72c2f2b1a2e575e71abcd11c094f3b612347b2a` |
| `Cargo.toml` | 746 | `aebcb999933c3425db85012bea19f9ce78da8e7834dbab54d4a2966e8bc62149` |
| `CHANGELOG.md` | 23387 | `d4722e028b2a5b88c466b0d759e463b90bdcfa1b79181a1c76cd313b0a27c615` |
| `LICENSE` | 1060 | `de730187d5563a81342a3c011d968f78dff37c934fac9b3701e8c762b6118a55` |
| `src/bits.rs` | 8184 | `97c9148f63e175489bb6199d039c594ddc56bdf0b7491b9f38b8d74e898bca80` |
| `src/bytes.rs` | 30190 | `8f29b976a5e8e6500eb618a9dead7f212688ba9eb06c7066a4016e2db99fed00` |
| `src/character.rs` | 4068 | `9ee081f56b508212231ff70d7455b1b85ae44722a39aa60223e8cd95c6570859` |
| `src/internal.rs` | 9814 | `ada499b9c178be2a7f9b56319ffb10a778f25fafcda39c78d26b364d89debd72` |
| `src/lib.rs` | 3659 | `34efb051214acfde2053e93a7ba718a4fd41b6e0d9edd65a1737605d99b994ab` |
| `src/macros.rs` | 120768 | `d39ce3a2cd2b1cb9dd57ce90c06a1ca84720a2dc75e6332cffebba6086cb75d3` |
| `src/methods.rs` | 18453 | `24bdbcb0e3570c8bf3fa270dd8d79dd6dfcb982276c82180a89a1e73c5e38019` |
| `src/nom.rs` | 29734 | `b0a9c7ce0d09388179bce8f8e23bf57df76b504d925815583c249ec3fc04baab` |
| `src/regexp.rs` | 22935 | `8fdae52b761dbad90179e6be87e0e66357fefa34d76af541fb0fcf550fd6ec08` |
| `src/str.rs` | 24670 | `198fa15d45c3636289d92c0a592002a07e5a04a431e8cfdf724266e44d484be2` |
| `src/stream.rs` | 33220 | `c1bd5b8e7a2061ff66eb2c954033146001f1d65a26d12efa06af8cf93ffa53e4` |
| `src/util.rs` | 21643 | `da40ebac865d3176567d3a37b01170234398a03e938553720ce30aa1f6005b6d` |
| `tests/arithmetic.rs` | 2112 | `b98936b7fa0228835ca022f6db5342b72a9c01cc3f16a4e05263bbe6424ba3e9` |
| `tests/arithmetic_ast.rs` | 4097 | `b18b9a46ba573ae13c40a31217425f6e8cf8fade09a75cdbbfa7146ec668f0b2` |
| `tests/cross_function_backtracking.rs` | 4945 | `b071d13031c1f12195473186e3775943991496b10f4590db3f36d511e9f98a1c` |
| `tests/ini.rs` | 6068 | `776f681542028564899e55f71533b3bcda5ed1bbb971f24b5b1b9578111ba0cb` |
| `tests/ini_str.rs` | 6335 | `315046d9b6dc38d6d306d3562d7ac6518c9ecce9aabcc58fb80c07577ad99789` |
| `tests/issues.rs` | 2492 | `2193c219397b7a417cc009b72c13adc42471e7a4917a2a4009aa0fca23c6ea8c` |
| `tests/mp4.rs` | 15575 | `b4bf0514fd645160851cc4da9ad6bf81d571cd14865bf134837c19578caaf6e6` |
| `tests/omnom.rs` | 4957 | `409d2349fa24f3503bd02e0079c1554a58ce3d40dd7eb0e5d4bb63b588afdae4` |
| `tests/test1.rs` | 1006 | `3e0c187bad91d822ebc113eb5cf30fc6585e53a961728304ac24e05ab2123d10` |
