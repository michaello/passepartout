#!/bin/sh
set -eu

: "${BUILT_PRODUCTS_DIR:?Missing build products directory}"
: "${PRODUCT_NAME:?Missing product name}"
: "${PLATFORM_NAME:?Missing platform}"
: "${CONFIGURATION:?Missing configuration}"

fail() {
    echo "embed-extensions.sh: $*" >&2
    exit 1
}

case "$BUILT_PRODUCTS_DIR" in
    /*) ;;
    *) fail "BUILT_PRODUCTS_DIR must be absolute" ;;
esac
case "$PRODUCT_NAME" in
    .|..|*/*) fail "Invalid product name" ;;
esac

app_root="${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.app"
login_src="${BUILT_PRODUCTS_DIR}/PassepartoutLoginItem.app"
appex_src="${BUILT_PRODUCTS_DIR}/PassepartoutTunnel.appex"
platform_mac="macosx"
sysex_cfg="ReleaseMac"
embed_guard="${CFG_EMBED_NETWORK_GUARD:-NO}"

case "$embed_guard" in
    YES|NO) ;;
    *) fail "CFG_EMBED_NETWORK_GUARD must be YES or NO" ;;
esac

if [ "$embed_guard" = YES ] && { [ "$PLATFORM_NAME" != "$platform_mac" ] || [ "$CONFIGURATION" != "$sysex_cfg" ]; }; then
    fail "Network guard packaging requires macOS ReleaseMac"
fi

require_bundle() {
    [ -d "$1" ] || fail "Missing bundle: $1"
}

copy_bundle() {
    # Replace only this generated bundle so incremental builds cannot retain
    # files removed from the new extension version.
    mkdir -p "$(dirname "$2")"
    rm -rf "$2"
    /usr/bin/ditto "$1" "$2"
}

if [ "$PLATFORM_NAME" = "$platform_mac" ]; then
    require_bundle "$login_src"
fi

if [ "$PLATFORM_NAME" = "$platform_mac" ] && [ "$CONFIGURATION" = "$sysex_cfg" ]; then
    : "${CFG_APP_ID:?Missing application identifier}"
    : "${CFG_TUNNEL_ID:?Missing tunnel identifier}"
    for identifier in "$CFG_APP_ID" "$CFG_TUNNEL_ID"; do
        case "$identifier" in
            *[!A-Za-z0-9.-]*|.*|*.|*..*) fail "Invalid bundle identifier" ;;
        esac
    done
    guard_id="${CFG_APP_ID}.NetworkGuard"
    [ "${CFG_GUARD_ID:-$guard_id}" = "$guard_id" ] || fail "Guard identifier must derive from CFG_APP_ID"
    sysex_src="${BUILT_PRODUCTS_DIR}/${CFG_TUNNEL_ID}.systemextension"
    guard_src="${BUILT_PRODUCTS_DIR}/${guard_id}.systemextension"
    sysex_dst="${app_root}/Contents/Library/SystemExtensions"
    require_bundle "$sysex_src"
    if [ "$embed_guard" = YES ]; then
        require_bundle "$guard_src"
        actual_guard_id=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$guard_src/Contents/Info.plist")
        [ "$actual_guard_id" = "$guard_id" ] || fail "Guard bundle identifier does not match build configuration"
    fi

    copy_bundle "$login_src" "${app_root}/Contents/Library/LoginItems/PassepartoutLoginItem.app"
    copy_bundle "$sysex_src" "${sysex_dst}/${CFG_TUNNEL_ID}.systemextension"
    if [ "$embed_guard" = YES ]; then
        copy_bundle "$guard_src" "${sysex_dst}/${guard_id}.systemextension"
    else
        # Switching the packaging flag off must not leave a previous guard behind.
        rm -rf "${sysex_dst}/${guard_id}.systemextension"
    fi
    exit 0
fi

require_bundle "$appex_src"
if [ "$PLATFORM_NAME" = "$platform_mac" ]; then
    copy_bundle "$login_src" "${app_root}/Contents/Library/LoginItems/PassepartoutLoginItem.app"
    appex_dst="${app_root}/Contents/PlugIns"
else
    appex_dst="${app_root}/PlugIns"
fi
copy_bundle "$appex_src" "${appex_dst}/PassepartoutTunnel.appex"
