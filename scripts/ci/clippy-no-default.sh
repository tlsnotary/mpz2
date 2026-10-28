#!/usr/bin/env bash
# Clippy every workspace crate that declares features, with its default
# features turned off.
#
# The workspace-wide clippy run uses --all-features, which compiles every
# positive `cfg(feature = "...")` branch but never the
# `cfg(not(feature = "..."))` ones. This lane covers the latter.
#
# One cargo invocation per crate is required: cargo unifies features across
# every package selected in a single invocation, so a multi-package
# --no-default-features build is not minimal for any of them.
#
# Usage:
#   clippy-no-default.sh              # discover every feature-bearing crate
#   clippy-no-default.sh -p a -p b    # (or positional names) limit the run
#
# mpz-wasm-bench is excluded: it is wasm-target-only and has its own lane.
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

if (($#)); then
    packages=("$@")
else
    mapfile -t packages < <(
        cargo metadata --no-deps --format-version 1 |
            python3 -c '
import json
import sys

for pkg in json.load(sys.stdin)["packages"]:
    if pkg["features"] and pkg["name"] != "mpz-wasm-bench":
        print(pkg["name"])
'
    )
fi

if ((${#packages[@]} == 0)); then
    echo "clippy-no-default: no feature-bearing crates found" >&2
    exit 1
fi

failed=()
for pkg in "${packages[@]}"; do
    if [[ -n ${GITHUB_ACTIONS:-} ]]; then
        echo "::group::clippy -p $pkg --no-default-features"
    else
        echo "== clippy -p $pkg --no-default-features"
    fi
    if ! cargo +nightly clippy -p "$pkg" --no-default-features --lib -- -D warnings; then
        failed+=("$pkg")
    fi
    if [[ -n ${GITHUB_ACTIONS:-} ]]; then
        echo "::endgroup::"
    fi
done

if ((${#failed[@]})); then
    echo >&2
    echo "clippy-no-default: failed for ${failed[*]}" >&2
    exit 1
fi

echo "clippy-no-default: ${#packages[@]} crate(s) clean"
