# takoyaki

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![release](https://img.shields.io/github/v/release/ternbusty/takoyaki)](https://github.com/ternbusty/takoyaki/releases/latest)

A GraalVM Native Image OCI container runtime, written in Java + Panama FFM. Implements the [OCI Runtime Specification](https://github.com/opencontainers/runtime-spec).

## Install

Prebuilt static binaries are published on the [GitHub Releases](https://github.com/ternbusty/takoyaki/releases) page for each tag. Pick the asset that matches your host architecture.

```sh
ARCH=$(uname -m)                            # aarch64 or x86_64
BASE=https://github.com/ternbusty/takoyaki/releases/latest/download

sudo curl -sSL -o /usr/local/bin/takoyaki "$BASE/takoyaki-linux-$ARCH"
sudo chmod +x /usr/local/bin/takoyaki

# Verify checksum
curl -sSL "$BASE/takoyaki-linux-$ARCH.sha256" | sha256sum -c

# AppArmor profile (Ubuntu 24.04+)
sudo curl -sSL -o /etc/apparmor.d/takoyaki "$BASE/apparmor-profile"
sudo apparmor_parser -r /etc/apparmor.d/takoyaki
```

The AppArmor profile is required on Ubuntu 24.04 and later. Ubuntu restricts unprivileged user namespace creation by default (`kernel.apparmor_restrict_unprivileged_userns=1`). Without a profile that permits `userns`, container workloads calling `unshare(CLONE_NEWUSER)` receive zero capabilities in the new namespace and rootless operation fails entirely. System-packaged runtimes (runc, crun, podman, ...) ship the same kind of profile in their packages.

If you installed the binary to a path other than `/usr/local/bin/takoyaki`, edit the path in the profile before loading it.

### Runtime requirements

- Linux 5.12+ (for idmap mount; older kernels still work for simpler bundles)
- libseccomp 2.x (`libseccomp2` on Debian/Ubuntu, `libseccomp` on Fedora). The binary loads `libseccomp.so.2` at runtime
- cgroup v2 mounted at `/sys/fs/cgroup` (cgroup v1 is not supported)

## Usage

```sh
takoyaki create   --bundle ./bundle  my-container
takoyaki start    my-container
takoyaki state    my-container
takoyaki kill     my-container TERM
takoyaki delete   --force my-container
```

A pidfile path can be supplied with `--pid-file`, and console PTY support is wired through `--console-socket`. See `takoyaki <subcommand> --help` for the full flag list.

## Build from source

You need GraalVM Community 25 and libseccomp-dev installed.

```sh
./gradlew nativeCompile
# Produces build/native/nativeCompile/takoyaki
```

Pass `-Pquick` for a fast development image:

```sh
./gradlew nativeCompile -Pquick
```

Unit tests run in any JVM:

```sh
./gradlew test
```

Contest-style integration tests (modelled on youki's `tests/contest/`) drive the real binary. They require root on Linux:

```sh
sudo -E env "TAKOYAKI_BIN=$PWD/build/native/nativeCompile/takoyaki" ./gradlew contestTest
```

## Releases

Releases are managed by [release-please](https://github.com/googleapis/release-please) using conventional-commit messages. Merging a release PR tags `vX.Y.Z`, and the `release` workflow then native-image-builds the binaries for both linux/aarch64 and linux/x86_64 and attaches them to the GitHub Release.

Commit message format follows [Conventional Commits](https://www.conventionalcommits.org/):

- `feat: ...` triggers a minor bump
- `fix: ...` triggers a patch bump
- `perf: ...` and `deps: ...` trigger a patch bump
- `feat!: ...` or `BREAKING CHANGE:` triggers a major bump
- `chore: ...`, `docs: ...`, `refactor: ...`, `test: ...`, `ci: ...`, `build: ...`, `style: ...`, `revert: ...` are kept in git history but do not appear in the changelog and do not bump the version

## License

takoyaki is licensed under the [Apache License 2.0](LICENSE). See `NOTICE` for attributions.
