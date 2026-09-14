#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 ROLE" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/results/cloud/metadata_${1}.txt"
TPC="$ROOT/vendor/paraswap/two-party computation"

version_or_unknown() {
  local output
  if command -v "$1" >/dev/null 2>&1; then
    shift
    output=$("$@" 2>&1 || true)
    printf '%s\n' "${output%%$'\n'*}"
  else
    printf 'unknown\n'
  fi
}

imds_value() {
  local path=$1 token
  token=$(curl -fsS --max-time 1 -X PUT \
    -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' \
    http://169.254.169.254/latest/api/token 2>/dev/null || true)
  if [[ -z $token ]]; then
    printf 'unavailable\n'
    return
  fi
  curl -fsS --max-time 1 \
    -H "X-aws-ec2-metadata-token: $token" \
    "http://169.254.169.254/latest/meta-data/$path" 2>/dev/null || \
    printf 'unavailable'
  printf '\n'
}

mkdir -p "$(dirname "$OUT")"
{
  printf 'role=%s\n' "$1"
  printf 'utc='; date -u +%Y-%m-%dT%H:%M:%SZ
  printf 'hostname='; hostname
  printf 'aws_instance_id='; imds_value instance-id
  printf 'aws_instance_type='; imds_value instance-type
  printf 'aws_availability_zone='; imds_value placement/availability-zone
  printf 'aws_region='; imds_value placement/region
  printf 'kernel='; uname -srmo
  printf 'nproc='; nproc
  printf 'c_compiler='; version_or_unknown cc cc --version
  printf 'cmake='; version_or_unknown cmake cmake --version
  printf 'zeromq='; pkg-config --modversion libzmq 2>/dev/null || printf 'unknown\n'
  printf 'libsodium='; pkg-config --modversion libsodium 2>/dev/null || printf 'unknown\n'
  printf 'transport=ZeroMQ CURVE over TCP with ZAP initiator-key allowlist\n'
  printf 'tls_cipher=not-applicable\n'
  printf 'python='; python3 --version
  printf 'soft_nofile='; ulimit -Sn
  printf 'hard_nofile='; ulimit -Hn
  printf 'host_cpu_snapshot='; head -n 1 /proc/stat
  printf '%s\n' 'cgroup_cpu_snapshot_begin'
  cat /sys/fs/cgroup/cpu.stat 2>/dev/null || printf 'unavailable\n'
  printf '%s\n' 'cgroup_cpu_snapshot_end'
  CMAKE_BUILD_TYPE=$(sed -n 's/^CMAKE_BUILD_TYPE:[^=]*=//p' "$TPC/build-full/CMakeCache.txt")
  if [[ -z $CMAKE_BUILD_TYPE ]] && grep -Eq \
      'set\(CMAKE_BUILD_TYPE[[:space:]]+Release\)' "$TPC/CMakeLists.txt"; then
    CMAKE_BUILD_TYPE=Release
    CMAKE_BUILD_TYPE_SOURCE='project default in CMakeLists.txt'
  else
    CMAKE_BUILD_TYPE_SOURCE=CMakeCache.txt
  fi
  printf 'cmake_build_type=%s\n' "$CMAKE_BUILD_TYPE"
  printf 'cmake_build_type_source=%s\n' "$CMAKE_BUILD_TYPE_SOURCE"
  printf 'cmake_c_flags='; sed -n 's/^CMAKE_C_FLAGS:[^=]*=//p' "$TPC/build-full/CMakeCache.txt"
  printf 'cmake_release_c_flags='; sed -n 's/^CMAKE_C_FLAGS_RELEASE:[^=]*=//p' "$TPC/build-full/CMakeCache.txt"
  lscpu
  free -b
  sha256sum \
    "$TPC/include/preswap_protocol.h" \
    "$TPC/include/completion_journal.h" \
    "$TPC/include/transport_auth.h" \
    "$TPC/src/preswap_common.c" \
    "$TPC/src/preswap_joint.c" \
    "$TPC/src/batch_verifier.c" \
    "$TPC/src/preswap_client_v4.c" \
    "$TPC/src/preswap_server_v4.c" \
    "$TPC/src/preswap_gateway.c" \
    "$TPC/src/completion_journal.c" \
    "$TPC/src/transport_auth.c" \
    "$TPC/bin/preswap_client" \
    "$TPC/bin/preswap_server" \
    "$TPC/bin/preswap_gateway"
} > "$OUT"
echo "cloud_metadata=$OUT"
