#!/bin/sh
set -eu

version=$(tr -d ' \n\r' < VERSION)
cargo_version=$(awk -F'"' '/^version = / { print $2; exit }' Cargo.toml)
package_version=$(sed -n 's/^[[:space:]]*"version":[[:space:]]*"\([^"]*\)".*/\1/p' package.json | head -1)
rust_version=$(awk -F'"' '/^rust-version = / { print $2; exit }' Cargo.toml)
toolchain_version=$(awk -F'"' '/^channel = / { print $2; exit }' rust-toolchain.toml)
bun_version=$(tr -d ' \n\r' < .bun-version)
package_manager=$(sed -n 's/^[[:space:]]*"packageManager":[[:space:]]*"bun@\([^"]*\)".*/\1/p' package.json | head -1)

check_equal() {
    label=$1
    actual=$2
    expected=$3

    if [ "$actual" != "$expected" ]; then
        echo "$label mismatch: expected $expected, got $actual" >&2
        exit 1
    fi
}

case "$version" in
    [0-9]*.[0-9]*.[0-9]*) ;;
    *)
        echo "VERSION must be semver without a v prefix: $version" >&2
        exit 1
        ;;
esac

check_equal "Cargo workspace version" "$cargo_version" "$version"
check_equal "JavaScript workspace version" "$package_version" "$version"
check_equal "Rust toolchain" "$toolchain_version" "$rust_version"
check_equal "Bun packageManager" "$package_manager" "$bun_version"

retired_name='agent''kit'
if grep -R -n -i \
    --exclude-dir=.git \
    --exclude-dir=target \
    --exclude=check-repository.sh \
    "$retired_name" .; then
    echo "retired working name found in repository" >&2
    exit 1
fi

echo "repository checks passed: gearwit $version (rust $rust_version)"
