#!/usr/bin/env bash
set -euo pipefail

# Build the static libraries the fully static (musl) native image links:
# libseccomp, and zlib for java.util.zip. Pass the prefix to Gradle with
# -Pmusl -PmuslDepsDir=<PREFIX>.
#
# Prerequisites: musl-tools, linux-libc-dev, gperf, curl, make, gcc
#
# Usage: ./scripts/build-musl-deps.sh [PREFIX]   (default $HOME/musl-deps/prefix)

PREFIX="${1:-$HOME/musl-deps/prefix}"
BUILD="$(dirname "$PREFIX")/build"

# libseccomp matches the libseccomp-dev headers jextract reads on Ubuntu 24.04.
LIBSECCOMP_VERSION=2.5.5
LIBSECCOMP_SHA256=248a2c8a4d9b9858aa6baf52712c34afefcf9c9e94b76dce02c1c9aa25fb3375
ZLIB_VERSION=1.3.1
ZLIB_SHA256=9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23

mkdir -p "$PREFIX/include" "$BUILD"

# musl-gcc does not search the system include dirs, so link the kernel
# headers into the prefix. asm/ lives under the multiarch dir on Debian/Ubuntu.
for d in linux asm-generic; do
    ln -sfn "/usr/include/$d" "$PREFIX/include/$d"
done
ln -sfn "/usr/include/$(gcc -print-multiarch)/asm" "$PREFIX/include/asm"

# fetch <url> <sha256>: download and unpack into $BUILD unless already there.
fetch() {
    local tarball="$BUILD/${1##*/}"
    [ -d "${tarball%.tar.gz}" ] && return
    curl -fsSL -o "$tarball" "$1"
    echo "$2  $tarball" | sha256sum -c --quiet
    tar xzf "$tarball" -C "$BUILD"
}

fetch "https://github.com/madler/zlib/releases/download/v$ZLIB_VERSION/zlib-$ZLIB_VERSION.tar.gz" "$ZLIB_SHA256"
(
    cd "$BUILD/zlib-$ZLIB_VERSION"
    CC=musl-gcc ./configure --prefix="$PREFIX" --static > /dev/null
    make -j"$(nproc)" install > /dev/null
)

fetch "https://github.com/seccomp/libseccomp/releases/download/v$LIBSECCOMP_VERSION/libseccomp-$LIBSECCOMP_VERSION.tar.gz" "$LIBSECCOMP_SHA256"
(
    cd "$BUILD/libseccomp-$LIBSECCOMP_VERSION"
    CC=musl-gcc CFLAGS="-isystem $PREFIX/include" \
        ./configure --prefix="$PREFIX" --enable-static --disable-shared \
                    --host="$(uname -m)-linux-musl" > /dev/null
    make -j"$(nproc)" install > /dev/null
)

echo "musl deps installed to $PREFIX"
