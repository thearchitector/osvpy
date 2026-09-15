# pyosv

Scan container images for vulnerabilities in Python. Built on OSV-Scanner.

It supports:

- Docker Hub and other OCI registries, by tag or digest
- anonymous access and explicit registry credentials
- Linux image platform selection
- Docker-save archives and offline vulnerability databases
- typed findings with package, advisory, fix, severity, and image-layer information
- JSON reports and custom output formats

Requires Python 3.13+ on Linux, WSL, or macOS 13+, on x86_64 or arm64.

## Installation

```bash
python -m pip install pyosv
# or
uv add pyosv
```

## Quick start

```python
import pyosv

result = pyosv.scan_image("ubuntu:latest")

for vuln in result.vulnerabilities:
    print(
        vuln.id, vuln.package, vuln.installed_version, vuln.fixed_version, vuln.severity
    )
```

## Scanning images

Use `all_packages=True` to include packages without findings, and `platform` to
select the image architecture:

```python
result = pyosv.scan_image("python:3.12-slim", all_packages=True, platform="linux/arm64")
```

Image references accept Docker Hub shorthand, full registry paths, tags, and
`@sha256:...` digests. The default platform is `linux/amd64`.
`result.metadata.image_digest` contains the resolved manifest digest.

Calls are synchronous. Concurrent scans are serialized; cancellation is not supported.

## Registry authentication

Omit `auth` for anonymous access. For private registries or authenticated Docker
Hub pulls, pass a username and password or access token:

```python
import os
from pyosv import RegistryAuth, scan_image

result = scan_image(
    "registry.example.com/team/app:latest",
    auth=RegistryAuth(
        username=os.environ["REGISTRY_USERNAME"],
        password=os.environ["REGISTRY_PASSWORD"],
    ),
)
```

Credentials must be supplied explicitly; Docker and AWS credentials are not
discovered automatically.

### Amazon ECR

Decode the `authorizationToken` returned by ECR's `GetAuthorizationToken` API
and pass the resulting username and password as ordinary registry credentials:

```python
import base64
import os
from pyosv import RegistryAuth, scan_image

username, password = (
    base64
    .b64decode(os.environ["ECR_AUTHORIZATION_TOKEN"])
    .decode("utf-8")
    .split(":", 1)
)

result = scan_image(
    "123456789012.dkr.ecr.us-east-1.amazonaws.com/app:latest",
    auth=RegistryAuth(username=username, password=password),
)
```

## Results and reports

`ScanResult` and its nested records are Pydantic models.

| Field                     | Contents                                                                  |
| ------------------------- | ------------------------------------------------------------------------- |
| `result.vulnerabilities`  | Flat findings with installed-package context and report properties        |
| `result.packages`         | Package identities, advisories, dependency groups, licenses, and analysis |
| `result.sources`          | Packages grouped by source, with exploitability signals                   |
| `result.image_metadata`   | Image OS, layers, and base-image groups                                   |
| `result.metadata`         | Scan options, duration, scanner version, and image identity               |
| `result.generic_findings` | Additional non-package findings                                           |
| `result.license_summary`  | License counts                                                            |
| `result.analysis_config`  | Analysis settings                                                         |

Each finding exposes `advisory`, `installed`, `source`, and `image_layer`.
The advisory includes affected ranges, references, credits, aliases, original
severity assessments, and timestamps. Timestamps retain RFC 3339 precision.

`severity` is the highest available CVSS v2/v3/v4 base score, or `None`.
`fixed_versions` contains explicit fixes for the installed package.
`fixed_version` is populated only when there is one distinct fix.

Filter findings and choose your own report fields:

```python
import json

report = [
    {"id": v.id, "package": v.package, "installed": v.installed_version}
    for v in result.vulnerabilities
    if v.severity is not None and v.severity >= 9
]
print(json.dumps(report, indent=2))
```

Use `result.model_dump()` for a dictionary or `result.model_dump_json()` for JSON.
To export all source-grouped data without duplicating the flattened views:

```python
print(result.model_dump_json(indent=2, exclude_computed_fields=True))
```

## Archives and offline scans

```python
result = pyosv.scan_docker_archive("image.tar", all_packages=True)
result = pyosv.scan_docker_archive(
    "image.tar", offline=True, database_path="/srv/osv-db"
)
```

Archives must use the single-image Docker-save format. OCI-layout archives are
not supported. Offline scans require a local archive and pre-populated OSV
database ZIPs for the image's ecosystems:

```text
/srv/osv-db/osv-scalibr/Ubuntu/all.zip
/srv/osv-db/osv-scalibr/Debian/all.zip
/srv/osv-db/osv-scalibr/PyPI/all.zip
```

Database exports are available at
`https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip`.
Offline mode disables vulnerability-service access and database downloads;
remote image references cannot be scanned offline.

## Errors

All library errors derive from `pyosv.OSVError` and expose a `code`.
Specific exceptions include `ImageNotFoundError`, `RegistryAuthenticationError`,
`InvalidImageError`, `OfflineDatabaseError`, `ScanError`, and `NativeLibraryError`.

```python
try:
    result = pyosv.scan_image("ubuntu:latest")
except pyosv.RegistryAuthenticationError:
    print("Check registry credentials and pull permissions")
except pyosv.OSVError as error:
    print(error.code, str(error))
```
