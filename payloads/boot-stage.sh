#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# One-shot downloadmanager / volatile.cache boot stage. No command polling.
{{CONFIG}}

report() {
    curl -fsS --connect-timeout 4 -m 8 --data-binary "$1" "$RESULT_URL" >/dev/null 2>&1
}

fetch_checked() {
    curl -fsS --connect-timeout 4 -m 20 -o "$2" "$1" || return 1
    actual="$(sha256sum "$2" 2>/dev/null | awk '{print $1}')"
    [ "$actual" = "$3" ] || { rm -f "$2"; return 1; }
}

if [ "$(id -u 2>/dev/null)" != 0 ]; then
    report 'BOOT_NOT_ROOT' || true
    exit 1
fi

# Delete/replace only this run's staged file; never remove a later staging run.
if ! grep -Fq "$SIGNATURE" "$CACHE_FILE" 2>/dev/null; then
    report 'CACHE_IDENTITY_MISMATCH' || true
    exit 1
fi

# Restore before any long-running work. Without a supplied original backup,
# remove this stage so it cannot execute again. The previous bytes are unknown.
if [ -n "$RESTORE_URL" ]; then
    isolated="$CACHE_FILE.disabled-$RUN_ID"
    if [ -e "$isolated" ] || ! mv "$CACHE_FILE" "$isolated"; then
        report 'CACHE_ISOLATION_FAILED' || true
        exit 1
    fi
    restored="$CACHE_FILE.restore-$RUN_ID"
    if ! fetch_checked "$RESTORE_URL" "$restored" "$RESTORE_SHA256"; then
        report 'CACHE_RESTORE_FAILED' || true
        exit 1
    fi
    chmod 644 "$restored" || exit 1
    # ln creates the destination atomically and refuses an existing new stage.
    # No -f: a cache arriving during the network wait must remain untouched.
    if ! ln "$restored" "$CACHE_FILE"; then
        rm -f "$restored"
        report 'CACHE_IDENTITY_MISMATCH' || true
        exit 1
    fi
    rm -f "$restored" "$isolated"
else
    rm -f "$CACHE_FILE" || exit 1
fi

printf 'uid=0(root)\nmode=%s\nrun=%s\n' "$MODE" "$RUN_ID" > "$PROOF_FILE"

# The network may not be ready when populate-volatile executes this file.
# A bounded background worker lets boot continue after successful cache cleanup.
# Failed backup downloads/hash checks leave only a non-boot .disabled copy for
# inspection; they never leave this stage at the boot consumer's cache path.
(
    attempt=0
    while [ "$attempt" -lt 24 ]; do
        if report 'BOOT_ROOT_OK uid=0(root)'; then break; fi
        attempt=$((attempt + 1))
        sleep 5
    done
    [ "$MODE" = ssh ] || exit 0

    install_dir="$HOME_DIR/.local/libexec/lg-webos-c4-root"
    mkdir -p "$HOME_DIR/.ssh" "$install_dir" || exit 1
    chmod 700 "$HOME_DIR/.ssh" "$install_dir" || exit 1
    keys="$HOME_DIR/.ssh/authorized_keys"
    touch "$keys" || exit 1
    chmod 600 "$keys" || exit 1
    if ! grep -Fxq "$PUBLIC_KEY" "$keys" 2>/dev/null; then
        # An existing authorized_keys file need not end in a newline.
        [ ! -s "$keys" ] || printf '\n' >> "$keys"
        printf '%s\n' "$PUBLIC_KEY" >> "$keys"
    fi

    binary="$install_dir/dropbear-$DROPBEAR_SHA256"
    if ! fetch_checked "$DROPBEAR_URL" "$binary.part-$RUN_ID" "$DROPBEAR_SHA256"; then
        report 'SSH_BINARY_FAILED' || true
        exit 1
    fi
    chmod 700 "$binary.part-$RUN_ID" || exit 1
    mv -f "$binary.part-$RUN_ID" "$binary" || exit 1
    mkdir -p "$COMPAT_SSH_DIR" 2>/dev/null || true
    # -s disables all password authentication; only the user's public key is added.
    # -R host-key locations depend on the user-supplied compatible Dropbear build.
    "$binary" -R -s -p "$SSH_PORT" -P "$SSH_PID_FILE" > "$SSH_LOG_FILE" 2>&1
    result=$?
    if [ "$result" = 0 ]; then
        report "SSH_PROCESS_STARTED port=$SSH_PORT" || true
    else
        report "SSH_PROCESS_FAILED rc=$result" || true
    fi
) >/dev/null 2>&1 &
