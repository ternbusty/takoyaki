#!/usr/bin/env bash
set -euo pipefail

# Build static libraries (libseccomp) against musl-gcc for the fully-static
# native-image build.  The resulting prefix is passed to Gradle via
# -PmuslDepsDir=<PREFIX>.
#
# Prerequisites: musl-tools, curl, make, gcc, linux-libc-dev
#
# Usage:
#   ./scripts/build-musl-deps.sh [PREFIX]
#   PREFIX defaults to $HOME/musl-deps/prefix

PREFIX="${1:-$HOME/musl-deps/prefix}"
BUILD="$(dirname "$PREFIX")/build"
LIBSECCOMP_VERSION=2.5.5
ARCH="$(uname -m)"

mkdir -p "$PREFIX/lib" "$PREFIX/include" "$BUILD"

# --- kernel headers (musl-gcc needs them for asm/unistd.h etc.) ---
# linux-libc-dev provides /usr/include/linux and /usr/include/asm-generic;
# asm/ lives under the multiarch directory on Debian/Ubuntu.
for d in linux asm-generic; do
  [ -d "/usr/include/$d" ] && ln -sfn "/usr/include/$d" "$PREFIX/include/$d"
done
MULTIARCH="$(gcc -print-multiarch 2>/dev/null || true)"
if [ -n "$MULTIARCH" ] && [ -d "/usr/include/$MULTIARCH/asm" ]; then
  ln -sfn "/usr/include/$MULTIARCH/asm" "$PREFIX/include/asm"
elif [ -d "/usr/include/asm" ]; then
  ln -sfn "/usr/include/asm" "$PREFIX/include/asm"
else
  echo "ERROR: cannot find asm/ kernel headers; install linux-libc-dev" >&2
  exit 1
fi

# --- libseccomp ---
cd "$BUILD"
if [ ! -d "libseccomp-$LIBSECCOMP_VERSION" ]; then
  curl -sL "https://github.com/seccomp/libseccomp/releases/download/v$LIBSECCOMP_VERSION/libseccomp-$LIBSECCOMP_VERSION.tar.gz" | tar xz
fi
cd "libseccomp-$LIBSECCOMP_VERSION"
CC=musl-gcc CFLAGS="-isystem $PREFIX/include" \
  ./configure --prefix="$PREFIX" --enable-static --disable-shared \
              --host="${ARCH}-linux-musl" > /dev/null
make clean > /dev/null 2>&1 || true
make -j"$(nproc)" > /dev/null
make install > /dev/null

echo "musl-deps installed to $PREFIX"
ls -lh "$PREFIX/lib/libseccomp.a"
