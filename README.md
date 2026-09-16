# osvpy

![PyPI Downloads](https://img.shields.io/pypi/dm/osvpy?style=flat)
![Made with AI](https://img.shields.io/badge/%E2%9C%A8-Made_with_AI-8A2BE2?style=flat)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/thearchitector/osvpy/ci.yaml?style=flat)

Scan container images for vulnerabilities and license incompatibilities. Built on OSV-Scanner.

Requires Python 3.13+ on Linux, WSL, or macOS 13+, on x86_64 or arm64.

## Installation

```bash
python -m pip install osvpy
# or
uv add osvpy
```

## Quick start

```python
import osvpy

result = osvpy.scan_image("ubuntu:latest")

for vuln in result.vulnerabilities:
    print(vuln.id, vuln.severity.score, vuln.severity.rating, vuln.packages)

for package in result.packages:
    for finding in package.vulnerabilities:
        print(
            package.name, package.installed_version, finding.id, finding.fixed_versions
        )
```

## Scanning images

```python
result = osvpy.scan_image("ubuntu:latest")  # Anonymous Docker Hub access
result = osvpy.scan_image("ghcr.io/org/project:tag")
result = osvpy.scan_image("registry.example.com/team/app@sha256:...")

result = osvpy.scan_image(
    "python:3.12-slim",
    all_packages=True,  # Include packages without findings
    platform="linux/arm64",  # Default: linux/amd64
)

print(result.metadata.image_digest)
```

Linux container images; registry tags and digests. Synchronous scans; no cancellation.

## Registry authentication

```python
import os
from osvpy import RegistryAuth, scan_image

result = scan_image(
    "registry.example.com/team/app:latest",
    auth=RegistryAuth(
        username=os.environ["REGISTRY_USERNAME"],
        password=os.environ["REGISTRY_PASSWORD"],
    ),
)
```

Explicit credentials only; no automatic credential discovery.

## Results and reports

Compact reports by default:

| Field                    | Contents                                                                    |
| ------------------------ | --------------------------------------------------------------------------- |
| `result.vulnerabilities` | Unique vulnerability groups: ID, aliases, severity, affected package IDs    |
| `result.packages`        | Package ID, name, installed version, ecosystem, and vulnerability/fix pairs |
| `result.metadata`        | Scanner version, image digest/platform, scan options, and duration          |
| `result.licenses`        | Requested allowlist and violations, or `None` when not requested            |

```python
result = osvpy.scan_image("ubuntu:latest")

report = result.model_dump()
print(result.model_dump_json(indent=2))

critical = [v for v in result.vulnerabilities if v.severity.rating == "critical"]

packages = {package.id: package for package in result.packages}
for vuln in critical:
    print(vuln.id, vuln.aliases, vuln.severity.score)
    for package_id in vuln.packages:
        package = packages[package_id]
        print(package.name, package.installed_version)
```

Vulnerabilities are grouped by aliases, with CVE identifiers preferred. Severity
is the highest reported CVSS score; unavailable scores are `None` / `unknown`.
Ratings: `none`, `low`, `medium`, `high`, `critical`, `unknown`.

Fix versions are per package and vulnerability. An empty list means no reported
fix; multiple versions may belong to different release branches.

### Full details

```python
full = osvpy.scan_image("ubuntu:latest", detail="full")
for finding in full.vulnerabilities:
    print(finding.id, finding.package, finding.installed_version, finding.fixed_version)
    print(finding.advisory, finding.source, finding.image_layer)

print(full.model_dump_json(indent=2, exclude_computed_fields=True))
```

Includes:

- advisories
- affected ranges
- references
- credits
- timestamps
- severity
- assessments
- source paths
- layers
- analysis
- license metadata

`full.sources` groups packages and advisories by source; `full.packages` and
`full.vulnerabilities` provide flattened views.

Full-report fix versions include advisory events for the exact package/ecosystem;
compact reports filter fixes against the installed version where supported.

### License policy

```python
result = osvpy.scan_image("python:3.12-slim", allowed_licenses={"MIT", "Apache-2.0"})
packages = {package.id: package for package in result.packages}
for violation in result.licenses.violations:
    package = packages[violation.package]
    print(package.name, violation.licenses, violation.forbidden)
```

| `allowed_licenses`      | Policy                                  |
| ----------------------- | --------------------------------------- |
| `None` (default)        | No license checks                       |
| `{"MIT", "Apache-2.0"}` | Allow matching SPDX license expressions |
| `set()`                 | Allow no licenses                       |

Online only. License violations include packages without vulnerabilities.
Missing license information is `UNKNOWN` and fails the policy; coverage varies
by ecosystem. License lookup failures raise `ScanError`.

## Archives and offline scans

```python
result = osvpy.scan_docker_archive("image.tar", all_packages=True)
result = osvpy.scan_docker_archive(
    "image.tar", offline=True, database_path="/srv/osv-db"
)
```

Single-image Docker-save archives only; no OCI-layout archives.
`detail` and `allowed_licenses` are also supported for online archive scans.

Offline scans require local database ZIPs for each image ecosystem:

```text
/srv/osv-db/osv-scalibr/Ubuntu/all.zip
/srv/osv-db/osv-scalibr/Debian/all.zip
/srv/osv-db/osv-scalibr/PyPI/all.zip
```

Download: `https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip`.

Offline mode: local archives only, no database downloads, no license checks.

## Errors

All library errors derive from `osvpy.OSVError` and expose a `code`.
Specific exceptions include `ImageNotFoundError`, `RegistryAuthenticationError`,
`InvalidImageError`, `OfflineDatabaseError`, `ScanError`, and `NativeLibraryError`.

```python
try:
    result = osvpy.scan_image("ubuntu:latest")
except osvpy.RegistryAuthenticationError:
    print("Check registry credentials and pull permissions")
except osvpy.OSVError as error:
    print(error.code, str(error))
```
