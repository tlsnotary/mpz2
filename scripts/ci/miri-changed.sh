#!/usr/bin/env bash
# Prints "true" when the diff from <base> to HEAD touches code covered by the
# Miri job, "false" otherwise.
#
# Covered: the packages the Miri job tests (clmul, matrix-transpose,
# mpz-fields) and mpz-core, the only path dependency of mpz-fields. Manifests
# and the lockfile are included so dependency changes re-run Miri; this script
# and the workflow are included so editing the gate re-runs it.
#
# Falls back to "true" when the base revision is unknown (new branch, force
# push, shallow clone), so a missing base never silently skips Miri.
#
# Usage: miri-changed.sh [base-rev]   # default: origin/dev
set -euo pipefail

root=$(git rev-parse --show-toplevel)
base="${1:-origin/dev}"

if [ -z "$base" ] || ! git -C "$root" rev-parse --verify --quiet "${base}^{commit}" >/dev/null; then
    echo true
    exit 0
fi

paths=(
    crates/clmul
    crates/matrix-transpose
    crates/fields
    crates/core
    Cargo.toml
    Cargo.lock
    scripts/ci/miri-changed.sh
    .github/workflows/rust.yml
)

if [ -n "$(git -C "$root" diff --name-only "$base"...HEAD -- "${paths[@]}")" ]; then
    echo true
else
    echo false
fi
