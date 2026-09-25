#!/usr/bin/env bash
# JsOwl build script (bash).
# Usage:
#   ./build/build.sh                      # vet + test + build (current platform)
#   ./build/build.sh --skip-test          # skip vet and tests
#   ./build/build.sh --version v1.2.3     # stamp a release version
#   ./build/build.sh --all-platforms      # cross-compile windows/linux/darwin
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=""
SKIP_TEST=0
ALL_PLATFORMS=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-test) SKIP_TEST=1; shift ;;
        --all-platforms) ALL_PLATFORMS=1; shift ;;
        --version) VERSION="$2"; shift 2 ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
done

if [[ -z "$VERSION" ]]; then
    if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        tag="$(git describe --tags --abbrev=0 2>/dev/null || true)"
        commit="$(git rev-parse --short HEAD 2>/dev/null || true)"
        if [[ -n "$tag" ]]; then
            VERSION="$tag"
        else
            VERSION="dev-${commit:-unknown}"
        fi
    else
        VERSION="dev"
    fi
fi

LDFLAGS="-X main.version=${VERSION} -s -w"
mkdir -p bin

echo "== JsOwl build: version ${VERSION} =="

if [[ "$SKIP_TEST" -eq 0 ]]; then
    echo "-> go vet ./..."
    go vet ./...
    echo "-> go test ./..."
    go test ./...
fi

build_target() {
    local goos="$1" goarch="$2" out="$3"
    local mcp="$out-mcp"
    case "$out" in
        *.exe) mcp="${out%.exe}-mcp.exe" ;;
    esac
    echo "-> build ${out} (${goos}/${goarch})"
    GOOS="$goos" GOARCH="$goarch" go build -trimpath -ldflags "$LDFLAGS" \
        -o "bin/${out}" ./cmd/jsowl
    GOOS="$goos" GOARCH="$goarch" go build -trimpath -ldflags "$LDFLAGS" \
        -o "bin/${mcp}" ./cmd/jsowl-mcp
}

if [[ "$ALL_PLATFORMS" -eq 1 ]]; then
    build_target windows amd64 jsowl-windows-amd64.exe
    build_target windows arm64 jsowl-windows-arm64.exe
    build_target linux amd64 jsowl-linux-amd64
    build_target linux arm64 jsowl-linux-arm64
    build_target darwin amd64 jsowl-darwin-amd64
    build_target darwin arm64 jsowl-darwin-arm64
else
    case "$(uname -s)" in
        MINGW*|MSYS*|CYGWIN*) build_target windows "$(go env GOHOSTARCH)" jsowl.exe ;;
        Linux*) build_target linux "$(go env GOHOSTARCH)" jsowl ;;
        Darwin*) build_target darwin "$(go env GOHOSTARCH)" jsowl ;;
        *) echo "unsupported platform: $(uname -s)" >&2; exit 1 ;;
    esac
fi

echo "== done: bin/ =="
ls -lh bin
