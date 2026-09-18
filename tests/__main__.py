"""Run pytest with controlled external services configured before Go starts."""

import os
import subprocess
import sys

from .advisories import advisory_proxy


def main() -> int:
    with advisory_proxy() as (proxy, cert):
        return subprocess.call(
            [sys.executable, "-m", "pytest", *sys.argv[1:]],
            env=os.environ
            | {
                "HTTPS_PROXY": proxy,
                "SSL_CERT_FILE": cert,
                "NO_PROXY": "127.0.0.1,localhost",
                "OSVPY_TEST_SERVICES": "1",
            },
        )


if __name__ == "__main__":
    raise SystemExit(main())
