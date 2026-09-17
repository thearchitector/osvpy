# osvpy

![PyPI Downloads](https://img.shields.io/pypi/dm/osvpy?style=flat)
![Made with AI](https://img.shields.io/badge/%E2%9C%A8-Made_with_AI-8A2BE2?style=flat)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/thearchitector/osvpy/ci.yaml?style=flat)

Scan container images for vulnerabilities and license incompatibilities.

Built with [osvscanner](https://github.com/google/osv-scanner). In-process, no external dependencies.

Requires Python 3.13+ on Linux, WSL, or macOS 13+, on x86_64 or arm64.

## Installation

```bash
python -m pip install osvpy
# or
uv add osvpy
```

## Scan images

```python
import osvpy

batch = osvpy.scan_image("ubuntu:latest", "python:3.12-slim")

for image in batch.images:
    if not image.complete:
        print(image.data.requested, image.data.diagnostics)
        continue

    for finding in image.findings:
        package = finding.occurrence.package.data
        print(
            package.name,
            package.version,
            finding.vulnerability.data.id,
            finding.fix_evidence.versions,
            finding.fix_evidence.status,
        )
```

Both scan functions return a `BatchResult`. Images appear in input order;
repeated inputs have separate results. One input produces one image result;
zero inputs produce an empty batch. Keyword options apply to every input.

By default, reports include packages relevant to vulnerability or license
findings. Use `all_packages=True` to include packages without findings.

### Private registries and platforms

```python
batch = osvpy.scan_image(
    "registry.example.com/team/app:latest",
    auth=osvpy.RegistryAuth("reader", "password"),
    platform="linux/arm64",
    all_packages=True,
)
print(batch.images[0].data.metadata.image_digest)
```

Registry references accept tags or digests. The default platform is
`linux/amd64`. Supply credentials through `RegistryAuth`; Docker credential
helpers are not used.

### Docker-save archives

```python
from pathlib import Path

batch = osvpy.scan_docker_archive(Path("one.tar"), Path("two.tar"), all_packages=True)
```

Paths accept strings or `os.PathLike` objects. Each archive must contain one
Docker-save image. A Docker daemon is not required. OCI-layout archives and
multi-image archives are not supported.

### Offline scanning

```python
batch = osvpy.scan_docker_archive("one.tar", offline=True, database_path="/srv/osv-db")
```

The database directory must contain the relevant OSV database ZIPs, such as
`/srv/osv-db/osv-scalibr/Ubuntu/all.zip`. Offline scans do not download databases
or use the network. Registry scans and license checks require online mode.

A missing, unreadable, or invalid required ZIP produces an `offline_unavailable`
failed image slot, discards that image's partial findings, and allows later images
to continue. This also applies when `all_packages=False`. Empty images require no
ecosystem ZIP. Validation checks archive structure and checksums, not every
advisory record. Keep database files unchanged throughout active scans.

## Read results

Results are read-only. Package, vulnerability, advisory, and image fields are
available through `.data`.

| Object            | Available data and relationships                                                                                                                                                                      |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `batch`           | `images`, `packages`, `vulnerabilities`, `advisory_sources`, `findings`, `complete`, `errors`                                                                                                         |
| `image`           | `data.requested`, `data.os`, `data.metadata`, `data.status`, `data.diagnostics`, `complete`, `packages`, `occurrences`, `vulnerable_packages`, `noncompliant_packages`, `vulnerabilities`, `findings` |
| `package`         | `data.name`, `data.version`, `data.ecosystem`, `data.commit`, `data.os_package_name`, `data.purl`, `present_images`, `vulnerable_images`, `noncompliant_images`, `affected_images`, `findings`        |
| `vulnerability`   | `data.id`, `data.aliases`, `affected_images`, `findings`                                                                                                                                              |
| `advisory_source` | `data.id`, `data.summary`, `data.severities`, `data.references`, `data.modified`, `data.published`, `data.withdrawn`, `affected_images`, `findings`                                                   |
| `occurrence`      | `image`, `package`, `context`, `license_assessment`, `findings`                                                                                                                                       |
| `finding`         | `occurrence`, `vulnerability`, `advisory_source`, `assessment`, `fix_evidence`                                                                                                                        |

An occurrence describes a package in a particular image and location. Its
`context` includes the path, source type, layer digest, and dependency groups.
Package `affected_images` combines vulnerability-affected and license-noncompliant
images; `present_images` includes every image reporting that package.

Vulnerabilities group related advisory identifiers, preferring a CVE identifier
when available. Source advisories retain their individual reporting facts.

### Fix evidence

`finding.fix_evidence.versions` contains reported package-specific, non-Git fix
versions. When version ordering is supported, fixes at or below the installed
version are excluded.

| `finding.fix_evidence.status` | Meaning                                                        |
| ----------------------------- | -------------------------------------------------------------- |
| `reported`                    | Applicable fix versions were reported.                         |
| `no_reported_fix`             | No applicable explicit fix version was reported.               |
| `unknown`                     | Fix applicability or version ordering could not be determined. |

Unknown ordering preserves reported version strings. An empty collection of fixes
does not establish that no fix exists. Fix evidence is not an upgrade
recommendation or a guarantee that later versions are unaffected.

## Memory usage

Result memory depends on the number of packages, findings, and distinct advisory
facts. Scanning related images in one batch can use less result memory than
keeping separate scan results, particularly when the images share packages and
vulnerabilities.

In a synthetic benchmark with 2,000 package occurrences per image:

| Workload                                                  | Memory retained by results |
| --------------------------------------------------------- | -------------------------: |
| One image                                                 |                   ~1.7 MiB |
| Ten images with fully overlapping packages and advisories |                   ~3.3 MiB |
| Ten images with partial overlap                           |                  ~10.7 MiB |
| Ten images with no overlap                                |                  ~17.3 MiB |

These figures measure retained results, not total process memory or peak memory
during a scan. Image scanning and vulnerability databases require additional
memory.

## License policies

```python
batch = osvpy.scan_image("python:3.12-slim", allowed_licenses={"MIT", "Apache-2.0"})

for occurrence in batch.images[0].occurrences:
    assessment = occurrence.license_assessment
    print(occurrence.package.data.name, assessment.status, assessment.violations)
```

`allowed_licenses=None` disables license evaluation. An empty collection allows
no licenses. Policies support SPDX expressions.

License assessment statuses are `not_evaluated`, `compliant`, `noncompliant`,
and `unknown`. Packages can have license violations without vulnerabilities.

## Failures and diagnostics

An acquisition or scan failure produces a failed image result; remaining inputs
are still scanned. `batch.complete` is false if any image failed.

```python
for image_index, diagnostic in batch.errors:
    print(batch.images[image_index].data.requested)
    print(diagnostic.code, diagnostic.message)
```

Error codes include `registry_authentication`, `image_not_found`, `invalid_image`,
`offline_unavailable`, and `scan_error`. Failed images represent unknown results.
Successful images may also contain diagnostics in `image.data.diagnostics`.

Unsupported offline option combinations raise `OfflineDatabaseError`. Native
operation failures raise `NativeLibraryError` and abort the batch. Library
exceptions derive from `osvpy.OSVError`.
