#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TPC_ROOT="$ROOT/vendor/paraswap/two-party computation"
DEPS_ROOT="$ROOT/.deps"
RELIC_SOURCE="$DEPS_ROOT/relic-src"
RELIC_BUILD="$DEPS_ROOT/relic-build"
LOCAL_DEPS="$TPC_ROOT/.local-deps"

# Historical development checkouts may contain a tracked .local-deps symlink
# that points at a machine-local absolute path.  A fresh artifact checkout must
# never depend on that path: remove the stale link/file and create the pinned
# repo-local dependency prefix instead.  Existing real directories are kept so
# repeated bootstrap runs remain incremental.
if [[ -L "$LOCAL_DEPS" || -f "$LOCAL_DEPS" ]]; then
  rm -f "$LOCAL_DEPS"
fi
INSTALL_PREFIX="$LOCAL_DEPS/usr/local"
RELIC_COMMIT=e8b13783dbbe120cff5a68ff460f3bb9bec69666

if [[ $(uname -s) != Linux ]]; then
  echo "error: the pinned native artifact currently supports Linux" >&2
  exit 1
fi

if command -v apt-get >/dev/null 2>&1; then
  PACKAGES=(
    build-essential ca-certificates cmake git libgmp-dev libpari-dev
    libssl-dev libzmq3-dev openssl pkg-config python3 python3-matplotlib
    python3-scipy strace tcpdump tshark
  )
  MISSING=()
  for package in "${PACKAGES[@]}"; do
    if ! dpkg-query -W -f='${db:Status-Abbrev}' "$package" 2>/dev/null |
        grep -q '^ii '; then
      MISSING+=("$package")
    fi
  done

  if (( ${#MISSING[@]} > 0 )); then
    SUDO=()
    if [[ $EUID -ne 0 ]]; then
      if ! command -v sudo >/dev/null 2>&1; then
        echo "error: missing Ubuntu packages: ${MISSING[*]}" >&2
        echo "error: sudo is required to install them" >&2
        exit 1
      fi
      SUDO=(sudo)
    fi
    "${SUDO[@]}" apt-get update
    "${SUDO[@]}" env DEBIAN_FRONTEND=noninteractive apt-get install -y \
      "${MISSING[@]}"
  else
    echo "Ubuntu build packages already installed"
  fi
else
  echo "error: install CMake, Git, GMP, PARI, ZeroMQ, OpenSSL, and Python 3" >&2
  exit 1
fi

mkdir -p "$DEPS_ROOT" "$INSTALL_PREFIX"
if [[ ! -d "$RELIC_SOURCE/.git" ]]; then
  git clone https://github.com/relic-toolkit/relic.git "$RELIC_SOURCE"
fi
git -C "$RELIC_SOURCE" fetch --tags --force origin
git -C "$RELIC_SOURCE" checkout --detach "$RELIC_COMMIT"

cmake -S "$RELIC_SOURCE" -B "$RELIC_BUILD" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX" \
  -DARCH=X64 \
  -DARITH=gmp \
  -DALLOC=AUTO \
  -DFP_PRIME=256 \
  -DFP_METHD="INTEG;INTEG;INTEG;MONTY;MONTY;JMPDS;SLIDE" \
  -DEP_METHD="PROJC;LWNAF;COMBS;INTER;SSWUM" \
  -DEC_METHD=PRIME \
  -DMD_METHD=SH256 \
  -DRAND=HASHD \
  -DSEED=UDEV \
  -DWITH="DV;BN;FP;FPX;EP;EPX;PP;PC;EC;BC;CP;MD" \
  -DBENCH=0 \
  -DTESTS=0
cmake --build "$RELIC_BUILD" -j "${BUILD_JOBS:-2}"
cmake --install "$RELIC_BUILD"

echo "Native dependencies installed under: $TPC_ROOT/.local-deps"
