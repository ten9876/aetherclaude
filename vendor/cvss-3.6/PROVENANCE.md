# cvss 3.6 (vendored)

CVSS v2, v3.x and v4.0 score calculation, used by `bin/cpp-aibom` to turn
the CVSS vectors OSV.dev publishes into base scores.

- Upstream: https://github.com/RedHatProductSecurity/cvss
- Release: cvss 3.6 on PyPI, sdist `cvss-3.6.tar.gz`
  (uploaded 2025-08-04), sha256
  `f21d18224efcd3c01b44ff1b37dec2e3208d29a6d0ce6c87a599c73c21ee1a99`
- License: LGPL-3.0-or-later (`LICENSE`)
- Contents: the `cvss/` package directory from that sdist, unmodified.
  Standard library only; supports Python 3.6+ (the mini's system Python
  is 3.9).

Vendored rather than installed because the launchd job runs the system
`python3` (PATH `/usr/bin:/bin:/usr/sbin:/sbin`), which has no packages.
