#!/bin/sh
# Run only inside the pinned disposable Alpine builder documented beside this file.
set -eu
TASK_OUTPUT=${1:?absolute output directory required}
case "$TASK_OUTPUT" in /*) ;; *) exit 2 ;; esac
[ "$(uname -s)" = Linux ]
apk add --no-cache build-base curl ca-certificates xz file pkgconf zlib-dev zlib-static \
  curl-dev curl-static openssl-dev openssl-libs-static brotli-dev brotli-static \
  zstd-dev zstd-static nghttp2-dev nghttp2-static libidn2-dev libidn2-static \
  libpsl-dev libpsl-static libunistring-dev libunistring-static c-ares-dev
TASK_BUILD=$(mktemp -d)
trap 'rm -rf "$TASK_BUILD"' EXIT
mkdir -p "$TASK_OUTPUT"
cd "$TASK_BUILD"
curl --fail --location --proto '=https' https://www.kernel.org/pub/software/scm/git/git-2.50.1.tar.xz -o git.tar.xz
printf '%s  %s\n' '7e3e6c36decbd8f1eedd14d42db6674be03671c2204864befa2a41756c5c8fc4' git.tar.xz | sha256sum -c -
tar -xf git.tar.xz
cd git-2.50.1
make -j2 prefix=/opt/merge-proof-git CFLAGS='-O2 -fno-omit-frame-pointer' LDFLAGS=-static \
  CURL_LDFLAGS="$(pkg-config --libs --static libcurl)" NO_GETTEXT=YesPlease NO_TCLTK=YesPlease \
  NO_REGEX=NeedsStartEnd NO_PERL=YesPlease NO_PYTHON=YesPlease NO_EXPAT=YesPlease all install
for TASK_BINARY in /opt/merge-proof-git/bin/git /opt/merge-proof-git/libexec/git-core/git-remote-https; do
  file "$TASK_BINARY"
  if readelf -l "$TASK_BINARY" | grep -q INTERP; then exit 3; fi
  if readelf -d "$TASK_BINARY" | grep -q NEEDED; then exit 3; fi
done
/opt/merge-proof-git/bin/git --version > "$TASK_OUTPUT/git-version.txt"
sha256sum /opt/merge-proof-git/bin/git /opt/merge-proof-git/libexec/git-core/git-remote-https > "$TASK_OUTPUT/git-sha256.txt"
apk info -vv > "$TASK_OUTPUT/builder-packages.txt"
cp COPYING "$TASK_OUTPUT/git-COPYING.txt"
tar -czf "$TASK_OUTPUT/git-runtime.tar.gz" -C /opt merge-proof-git
# Test TLS/remote helper and object transport with an existing public synthetic repo.
/opt/merge-proof-git/bin/git -c credential.helper= ls-remote https://github.com/ohcaygo/merge-proof-l3-lab-classic.git HEAD > "$TASK_OUTPUT/remote-smoke.txt"
