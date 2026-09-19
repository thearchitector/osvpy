# osvpy

![PyPI Downloads](https://img.shields.io/pypi/dm/osvpy?style=flat)
![Made with AI](https://img.shields.io/badge/%E2%9C%A8-Made_with_AI-8A2BE2?style=flat)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/thearchitector/osvpy/ci.yaml?style=flat)

Scan container images for vulnerabilities and license incompatibilities.

Built with [osvscanner](https://github.com/google/osv-scanner). In-process, no external dependencies.

Supports Python 3.13+ on Linux, WSL, or macOS 13+.

## Installation

```bash
python -m pip install osvpy
# or
uv add osvpy
```

## Scan images

```python
import asyncio

import osvpy

batch = await osvpy.scan("ubuntu:latest", "python:3.12-slim", workers=2)


for image in batch.images:
    if not image.complete:
        for diagnostic in image.diagnostics:
            print(image.requested, diagnostic.code, diagnostic.message)
        continue

    for finding in image.findings:
        package = finding.occurrence.package
        print(
            image.requested,
            package.name,
            package.version,
            finding.vulnerability.id,
            tuple(finding.fix_evidence.versions),
            finding.fix_evidence.status,
        )
```

`scan()` returns a `BatchResult` with one image result per input, in input order.
Repeated inputs have separate image results. Calling `scan()` without images
raises `ValueError`. The examples below use `await` inside an async function
or notebook.

### Scan options

Keyword options apply to every image in the call.

| Option             | Default                | Purpose                                                                                              |
| ------------------ | ---------------------- | ---------------------------------------------------------------------------------------------------- |
| `workers`          | `None` (auto)          | Maximum number of images scanned concurrently; a positive integer or `None` for automatic selection. |
| `all_packages`     | `False`                | Include packages without vulnerability or license findings.                                          |
| `languages`        | `None`                 | Select language families or individual package formats.                                              |
| `allowed_licenses` | `None`                 | Evaluate packages against an SPDX license allowlist.                                                 |
| `auth`             | `None`                 | Supply registry credentials with `RegistryAuth`.                                                     |
| `platform`         | `None` (`linux/amd64`) | Select the image platform, such as `"linux/arm64"`.                                                  |

### Private registries and platforms

```python
batch = await osvpy.scan(
    "registry.example.com/team/app:latest",
    auth=osvpy.RegistryAuth("reader", "password"),
    platform="linux/arm64",
    all_packages=True,
)
print(batch.images[0].status)
```

Registry references accept tags or digests. Supply credentials through
`RegistryAuth`; Docker credential helpers are not used.

## Concurrency and cancellation

Use `workers` to limit concurrency within a batch. Separate calls can run
concurrently, and completed results can be read from multiple threads.
Concurrency limits apply to each call separately. `None` selects the usable CPU
count bounded between two and four, then capped at the number of input images.
If the CPU count is unavailable, the automatic limit is two before the image
count cap. Set `workers=1` for serial scanning; zero and negative values raise
`ValueError`.

Set a deadline with `asyncio.timeout()` or `asyncio.wait_for()`:

```python
import asyncio

async with asyncio.timeout(30):
    batch = await osvpy.scan("debian:12-slim")
```

Cancel an active scan with `task.cancel()`. Cancellation raises
`asyncio.CancelledError` after the scan stops; it does not return a partial batch.
Timeouts raise `TimeoutError` and may take longer than the requested deadline
while the scan stops. Repeated cancellation and `asyncio.TaskGroup` are supported.

## Language coverage

Combine families with `|`, or select individual formats such as `PYTHON_UV`:

```python
batch = await osvpy.scan(
    "python:3.12-slim",
    languages=osvpy.LanguageSelection.PYTHON | osvpy.LanguageSelection.JAVA,
)
```

Family selections include supported manifests and lockfiles. Individual format
names combine the family and suffix, such as `JAVA_MAVEN`.

| Family     | Format suffixes                                                 |
| ---------- | --------------------------------------------------------------- |
| CPP        | CONAN                                                           |
| DART       | PUBSPEC                                                         |
| DOTNET     | PROJECT, DEPS, CENTRAL_PACKAGES, PACKAGES_CONFIG, PACKAGES_LOCK |
| ELIXIR     | MIX                                                             |
| GO         | BINARY, MODULES                                                 |
| HASKELL    | CABAL, STACK                                                    |
| JAVA       | ARCHIVE, GRADLE_LOCK, GRADLE_VERIFICATION, MAVEN                |
| JAVASCRIPT | INSTALLED, NPM, PNPM, YARN, BUN                                 |
| PHP        | COMPOSER                                                        |
| PYTHON     | INSTALLED, REQUIREMENTS, POETRY, PIPFILE, PDM, PYLOCK, UV       |
| R          | RENV                                                            |
| RUBY       | GEMFILE                                                         |
| RUST       | BINARY, CARGO                                                   |
| SWIFT      | PACKAGE_RESOLVED                                                |

- `None` or `LanguageSelection.INSTALLED`: installed Python and JavaScript packages, Java archives, and Go and Rust binaries.
- `LanguageSelection.ALL`: every format listed above.
- `LanguageSelection.NONE`: OS packages only.

OS package scanning remains enabled with every language selection. Standalone
source directories, lockfiles, and SBOM files are not accepted as scan inputs.

## Read results

Access fields directly, such as `package.name` or `image.status`.

| Object            | Data and relationships                                                                                                                                           |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `batch`           | `images`, `packages`, `vulnerabilities`, `advisory_sources`, `findings`, `complete`, `errors`                                                                    |
| `image`           | `requested`, `os`, `status`, `diagnostics`, `complete`, `packages`, `occurrences`, `vulnerable_packages`, `noncompliant_packages`, `vulnerabilities`, `findings` |
| `package`         | `name`, `version`, `ecosystem`, `commit`, `os_package_name`, `purl`, `present_images`, `vulnerable_images`, `noncompliant_images`, `affected_images`, `findings` |
| `vulnerability`   | `id`, `aliases`, `affected_images`, `findings`                                                                                                                   |
| `advisory_source` | `id`, `aliases`, `summary`, `severities`, `references`, `modified`, `published`, `withdrawn`, `affected_images`, `findings`                                      |
| `occurrence`      | `image`, `package`, `context`, `license_assessment`, `findings`                                                                                                  |
| `finding`         | `occurrence`, `vulnerability`, `advisory_source`, `assessment`, `fix_evidence`                                                                                   |

An occurrence describes a package in a particular image and location. Its
`context` includes the path, source type, layer digest, and dependency groups.
Package `affected_images` combines vulnerability-affected and license-noncompliant
images; `present_images` includes every image reporting that package.

Vulnerabilities group related advisory identifiers, preferring a CVE identifier
when available. Individual advisories provide their own summaries, severity
information, references, and dates.

### Fix evidence

`finding.fix_evidence.versions` contains reported package-specific, non-Git fix
versions. When version ordering is supported, fixes at or below the installed
version are excluded.

| `finding.fix_evidence.status` | Meaning                                                        |
| ----------------------------- | -------------------------------------------------------------- |
| `reported`                    | Applicable fix versions were reported.                         |
| `no_reported_fix`             | No applicable explicit fix version was reported.               |
| `unknown`                     | Fix applicability or version ordering could not be determined. |

Unknown ordering preserves reported version strings. An empty collection does
not establish that no fix exists. Reported fixes are not upgrade recommendations
or a guarantee that later versions are unaffected.

### Collections and equality

Collections support iteration, `len()`, negative indexing, and slicing. Slices
return tuples. Use `tuple(values)` to collect all items into a tuple.

Results are read-only and cannot be pickled. References to the same record within
a batch compare equal and have the same hash. Records from separate scans compare
unequal; compare their fields when checking for matching contents. A package,
finding, or collection remains usable after its original batch variable is deleted.

## License policies

```python
batch = await osvpy.scan("python:3.12-slim", allowed_licenses={"MIT", "Apache-2.0"})

for occurrence in batch.images[0].occurrences:
    assessment = occurrence.license_assessment
    print(occurrence.package.name, assessment.status, tuple(assessment.violations))
```

`allowed_licenses=None` disables license evaluation. An empty collection allows
no licenses. Policies support SPDX expressions. `assessment.policy` is `None`
when evaluation was not requested, or an empty sequence for an empty allowlist.

License assessment statuses are `not_evaluated`, `compliant`, `noncompliant`,
and `unknown`. Packages can have license violations without vulnerabilities.

## Failures and diagnostics

An image download or scan failure produces a failed image result; remaining
inputs are still scanned. `batch.complete` is false if any image failed.

```python
for image_index, diagnostic in batch.errors:
    print(batch.images[image_index].requested)
    print(diagnostic.code, diagnostic.message)
```

Error codes include `registry_authentication`, `image_not_found`, `invalid_image`,
and `scan_error`. Failed images represent unknown results.
Successful images may also contain diagnostics in `image.diagnostics`.

Batch-level failures raise `osvpy.NativeLibraryError` and abort the batch.
Library exceptions derive from `osvpy.OSVError`.

## Comparison

Features available out of the box when integrating with Python:

| Feature                                                                                    | osvpy | OSV-Scanner CLI                 |
| ------------------------------------------------------------------------------------------ | ----- | ------------------------------- |
| Container vulnerability and license scanning                                               | ✅    | ✅                              |
| [Source directory, lockfile, and SBOM inputs](https://google.github.io/osv-scanner/usage/) | ❌    | ✅                              |
| Typed Python results                                                                       | ✅    | ❌ Parse JSON yourself          |
| Cross-image result relationships                                                           | ✅    | ❌ Build relationships yourself |
| [HTML and SARIF reports](https://google.github.io/osv-scanner/output/)                     | ❌    | ✅                              |
| In-process scanning, no separate executable                                                | ✅    | ❌ Install scanner separately   |
| Async Python API with cancellation                                                         | ✅    | ❌ Write subprocess handling    |
| Batch scanning                                                                             | ✅    | ❌ Write batch orchestration    |

## Building distributions

Source builds require Go (see `go/go.mod`), Git, and a C compiler. `uv build`
builds a source archive and then a wheel from that archive.

Linux wheels need [repairing for PyPI](https://scikit-build-core.readthedocs.io/en/stable/guide/build.html#repairing):

```bash
uv build
uvx --with patchelf auditwheel repair dist/*.whl --wheel-dir wheelhouse
uv publish --dry-run dist/*.tar.gz wheelhouse/*.whl
uv publish dist/*.tar.gz wheelhouse/*.whl
```

Publish the repaired wheel from `wheelhouse`. Its minimum glibc version depends
on the build environment; use a manylinux container to target older Linux
systems. On macOS, publish the wheel in `dist` directly.
