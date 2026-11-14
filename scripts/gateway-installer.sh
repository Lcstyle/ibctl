#!/bin/sh
# A self-hosted store of IB Gateway installers, keyed by version.
#
# IB serves only each channel's *current* installer, at a URL that never names
# a version. The image build needs a pinned, checksummed file, and the upgrade
# soak needs builds IB has already replaced. So every build is archived the
# first time it is seen, in a generic package store (any HTTP server that
# accepts PUT uploads, e.g. a Gitea or Forgejo generic package registry):
#
#   $STORE/<version>/ibgateway-<version>-standalone-linux-x64.sh
#   $STORE/<version>/ibgateway-<version>-standalone-linux-x64.sh.sha256
#
# Reading the store is anonymous (the Dockerfile downloads from it); writing
# needs STORE_USER and STORE_TOKEN.
#
#   gateway-installer.sh archive <stable|latest>
#       Store the channel's current build if the store lacks it.
#       Prints "<version> <sha256>".
#   gateway-installer.sh ensure <version> <sha256>
#       Succeed if the store has <version> with that checksum. If it lacks
#       it, store it from IB — only when IB still serves exactly <version>
#       and the download has exactly that checksum.
#
# POSIX sh + curl + sha256sum, for the alpine CI images.
set -eu

# The store's base URL: $STORE, else the one line of .gateway-store at the
# repo root (the same file the Dockerfile reads).
STORE="${STORE:-$(tr -d ' \t\r\n' 2>/dev/null < "$(dirname "$0")/../.gateway-store" || true)}"
IB="${IB:-https://download2.interactivebrokers.com/installers/ibgateway}"
WORK="${WORK:-$(mktemp -d)}"

die() { echo "gateway-installer: $*" >&2; exit 1; }
[ -n "$STORE" ] || die "no store: set STORE or put its base URL in .gateway-store"
file_for() { echo "ibgateway-$1-standalone-linux-x64.sh"; }

# IB's version.json is JSONP: ibgateway<channel>_callback({"buildVersion":"10.50.1f",...});
ib_version() {
    curl -fsS --max-time 30 "$IB/$1-standalone/version.json" \
        | sed -n 's/.*"buildVersion":"\([^"]*\)".*/\1/p'
}

store_sha() {  # the stored checksum for <version>, empty if not stored
    curl -fsS --max-time 30 "$STORE/$1/$(file_for "$1").sha256" 2>/dev/null | cut -d' ' -f1 || true
}

upload() {  # upload <version> <path>
    [ -n "${STORE_USER:-}" ] && [ -n "${STORE_TOKEN:-}" ] || die "STORE_USER/STORE_TOKEN are needed to store $1"
    name=$(file_for "$1")
    sha=$(sha256sum "$2" | cut -d' ' -f1)
    printf '%s  %s\n' "$sha" "$name" > "$WORK/$name.sha256"
    # The installer first, its checksum last: a reader that finds the .sha256
    # can rely on the installer being there.
    curl -fsS --max-time 900 --user "$STORE_USER:$STORE_TOKEN" --upload-file "$2" "$STORE/$1/$name" >/dev/null \
        || die "upload of $name failed"
    curl -fsS --max-time 60 --user "$STORE_USER:$STORE_TOKEN" --upload-file "$WORK/$name.sha256" "$STORE/$1/$name.sha256" >/dev/null \
        || die "upload of $name.sha256 failed"
}

# Download <channel>'s current installer and print the path, but only if IB
# still names <version> as current both before and after the download (IB can
# publish a new build mid-download, and the file itself carries no version).
download_current() {
    channel=$1 version=$2
    [ "$(ib_version "$channel")" = "$version" ] || return 1
    out="$WORK/$(file_for "$version")"
    curl -fsS --max-time 900 -o "$out" "$IB/$channel-standalone/ibgateway-$channel-standalone-linux-x64.sh" \
        || die "download of the $channel installer failed"
    [ "$(ib_version "$channel")" = "$version" ] || die "IB's $channel build changed during the download; try again"
    echo "$out"
}

cmd_archive() {
    channel=$1
    case "$channel" in stable|latest) ;; *) die "channel must be stable or latest, not '$channel'" ;; esac
    version=$(ib_version "$channel")
    [ -n "$version" ] || die "could not read IB's $channel version"
    sha=$(store_sha "$version")
    if [ -z "$sha" ]; then
        path=$(download_current "$channel" "$version") || die "IB's $channel build moved on from $version"
        upload "$version" "$path"
        sha=$(store_sha "$version")
        [ -n "$sha" ] || die "stored $version but cannot read its checksum back"
        echo "stored $version ($channel) $sha" >&2
    fi
    echo "$version $sha"
}

cmd_ensure() {
    version=$1 want=$2
    have=$(store_sha "$version")
    if [ -n "$have" ]; then
        [ "$have" = "$want" ] || die "the store has $version with checksum $have, but the pin is $want"
        echo "$version is in the store with the pinned checksum"
        return 0
    fi
    for channel in stable latest; do
        if path=$(download_current "$channel" "$version"); then
            got=$(sha256sum "$path" | cut -d' ' -f1)
            [ "$got" = "$want" ] || die "IB's $channel $version has checksum $got, but the pin is $want"
            upload "$version" "$path"
            echo "stored $version from IB's $channel channel"
            return 0
        fi
    done
    die "$version is not in the store and IB no longer serves it on either channel"
}

case "${1:-}" in
    archive) [ $# -eq 2 ] || die "usage: $0 archive <stable|latest>"; cmd_archive "$2" ;;
    ensure)  [ $# -eq 3 ] || die "usage: $0 ensure <version> <sha256>"; cmd_ensure "$2" "$3" ;;
    *) die "usage: $0 archive <channel> | ensure <version> <sha256>" ;;
esac
