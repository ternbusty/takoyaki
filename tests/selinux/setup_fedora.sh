#!/bin/bash
# Install takoyaki build dependencies on Fedora (Lima VM).
# Called from the SELinux CI workflow.
set -eux -o pipefail

DNF=(dnf -y --setopt=install_weak_deps=False --setopt=tsflags=nodocs --exclude="kernel,kernel-core")

# Retry wrapper for flaky mirrors.
for i in $(seq 0 2); do
    sleep "$i"
    "${DNF[@]}" update && break
done

RPMS=(
    bats
    container-selinux
    curl
    gcc
    glibc-devel
    glibc-static
    golang
    jq
    libseccomp-devel
    make
    policycoreutils
    unzip
    zip
    zlib-devel
)
"${DNF[@]}" install "${RPMS[@]}"
dnf clean all

# SDKMAN (for GraalVM + jextract)
export SDKMAN_DIR="/opt/sdkman"
curl -s "https://get.sdkman.io" | bash
echo "sdkman_auto_answer=true" >> "$SDKMAN_DIR/etc/config"
# shellcheck disable=SC1091
source "$SDKMAN_DIR/bin/sdkman-init.sh"

sdk install java 25-graalce
sdk install jextract

# Make SDKMAN available for login shells (sudo -i).
cat > /etc/profile.d/sdkman.sh << 'PROFILE'
export SDKMAN_DIR="/opt/sdkman"
if [ -s "$SDKMAN_DIR/bin/sdkman-init.sh" ]; then
    # shellcheck disable=SC1091
    source "$SDKMAN_DIR/bin/sdkman-init.sh"
fi
PROFILE

# Smoke-test the toolchain.
java -version
native-image --version
jextract --version || true

# Verify SELinux is enforcing.
sestatus
getenforce
