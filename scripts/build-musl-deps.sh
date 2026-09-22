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

mkdir -p "$PREFIX/lib" "$PREFIX/include" "$BUILD"

# --- kernel headers (musl-gcc needs them for asm/unistd.h etc.) ---
for d in linux asm-generic; do
  ln -sfn "/usr/include/$d" "$PREFIX/include/$d"
done
# asm/ is under the arch-specific multiarch directory on Debian/Ubuntu
MULTIARCH="$(gcc -print-multiarch 2>/dev/null || true)"
if [ -d "/usr/include/$MULTIARCH/asm" ]; then
  ln -sfn "/usr/include/$MULTIARCH/asm" "$PREFIX/include/asm"
elif [ -d "/usr/include/asm" ]; then
  ln -sfn "/usr/include/asm" "$PREFIX/include/asm"
fi

# --- libseccomp ---
cd "$BUILD"
if [ ! -d "libseccomp-$LIBSECCOMP_VERSION" ]; then
  curl -sL "https://github.com/seccomp/libseccomp/releases/download/v$LIBSECCOMP_VERSION/libseccomp-$LIBSECCOMP_VERSION.tar.gz" | tar xz
fi
cd "libseccomp-$LIBSECCOMP_VERSION"
CC=musl-gcc CFLAGS="-isystem $PREFIX/include" \
  ./configure --prefix="$PREFIX" --enable-static --disable-shared \
              --host=x86_64-linux-musl >/dev/null 2>&1
make -j"$(nproc)" >/dev/null 2>&1
make install >/dev/null 2>&1

echo "musl-deps installed to $PREFIX"
ls -lh "$PREFIX/lib/libseccomp.a"
