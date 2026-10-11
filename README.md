# eMule — source code

> **Looking for a download?** This repository contains **source code only** and publishes no binaries.
> Ready-to-use builds are on the **[latest eMule-build release](https://github.com/avwarez/eMule-build/releases/latest)**.

## What's here

This repository keeps the eMule source code, one branch per version:

| Branch | Contents |
| --- | --- |
| [`v0.72a`](https://github.com/avwarez/eMule/tree/v0.72a) | eMule 0.72a, the version current builds are made from |
| `v0.70*`, `v0.60*`, `v0.51*` | earlier versions |
| [`v0.50b`](https://github.com/avwarez/eMule/tree/v0.50b) | 0.50b development snapshot (0.50.1.16), never released |
| [`v0.50a`](https://github.com/avwarez/eMule/tree/v0.50a) | eMule 0.50a, the last official release from the original project |

The `master` branch contains only this file.

## Building

Builds are produced by **[eMule-build](https://github.com/avwarez/eMule-build)**, a CMake pipeline
that fetches this source code and its dependencies, applies the build patches and compiles eMule
for x64, Win32 and ARM64 on GitHub Actions. To build it yourself, start from there.

## License

eMule is free software, distributed under the terms of the GNU General Public License.
