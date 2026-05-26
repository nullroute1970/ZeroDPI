#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="zerodpi"
UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

info() {
    printf '%s\n' "$*"
}

print_relevant_systemd_output() {
    local output="$1"
    local line

    [ -n "$output" ] || return 0

    while IFS= read -r line; do
        case "$line" in
            *"$SERVICE_NAME.service"*|*"$UNIT_PATH"*|*"$tmp_unit"*)
                printf '%s\n' "$line" >&2
                ;;
        esac
    done <<< "$output"
}

run_systemd_command() {
    local output

    if ! output="$("$@" 2>&1)"; then
        printf '%s\n' "$output" >&2
        return 1
    fi

    print_relevant_systemd_output "$output"
}

validate_systemd_path() {
    local value="$1"
    local label="$2"

    case "$value" in
        *[[:space:]\"\'\\%]*)
            die "$label must not contain whitespace, quotes, backslashes, or percent signs for systemd unit compatibility: $value"
            ;;
    esac
}

resolve_script_dir() {
    local source="${BASH_SOURCE[0]}"
    while [ -L "$source" ]; do
        local dir
        dir="$(cd -P "$(dirname "$source")" >/dev/null 2>&1 && pwd)"
        source="$(readlink "$source")"
        [[ "$source" != /* ]] && source="$dir/$source"
    done
    cd -P "$(dirname "$source")" >/dev/null 2>&1 && pwd
}

find_zerodpi_binary() {
    local dir="$1"

    if [ -f "$dir/zerodpi" ]; then
        printf '%s\n' "$dir/zerodpi"
        return 0
    fi

    local candidate
    while IFS= read -r -d '' candidate; do
        case "$(basename "$candidate")" in
            zerodpi|zerodpi-*) printf '%s\n' "$candidate"; return 0 ;;
        esac
    done < <(find "$dir" -maxdepth 1 -type f -perm -111 -print0)

    return 1
}

[ "${EUID:-$(id -u)}" -eq 0 ] || die "Run this installer as root."
command -v systemctl >/dev/null 2>&1 || die "systemctl was not found."
[ -d /run/systemd/system ] || die "systemd does not appear to be running."

APP_DIR="$(resolve_script_dir)"
BINARY_PATH="$(find_zerodpi_binary "$APP_DIR")" || die "Could not find a ZeroDPI executable in $APP_DIR."
CONFIG_PATH="$APP_DIR/config.toml"

validate_systemd_path "$APP_DIR" "Application directory"
validate_systemd_path "$BINARY_PATH" "Executable path"
validate_systemd_path "$CONFIG_PATH" "Configuration path"

[ -f "$CONFIG_PATH" ] || die "Could not find config.toml in $APP_DIR."
[ -f "$APP_DIR/sni_list.txt" ] || info "Warning: sni_list.txt was not found in $APP_DIR."
[ -f "$APP_DIR/ip_list.txt" ] || info "Warning: ip_list.txt was not found in $APP_DIR."

chmod 0755 "$BINARY_PATH"

tmp_dir="$(mktemp -d)"
tmp_unit="$tmp_dir/${SERVICE_NAME}.service"
trap 'rm -rf "$tmp_dir"' EXIT

cat > "$tmp_unit" <<EOF
[Unit]
Description=ZeroDPI DPI bypass proxy
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$APP_DIR
ExecStart=$BINARY_PATH --config $CONFIG_PATH --auto-select --no-tui
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=info
StandardInput=null
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

if command -v systemd-analyze >/dev/null 2>&1; then
    run_systemd_command systemd-analyze verify "$tmp_unit" || die "Generated systemd unit did not pass validation."
fi

install -m 0644 "$tmp_unit" "$UNIT_PATH"

run_systemd_command systemctl daemon-reload || die "systemctl daemon-reload failed."
run_systemd_command systemctl enable --now "$SERVICE_NAME.service" || die "Could not enable and start $SERVICE_NAME.service."

info "Installed and started $SERVICE_NAME.service"
info "Application directory: $APP_DIR"
info "Executable: $BINARY_PATH"
info "Configuration: $CONFIG_PATH"
info "Check status with: systemctl status $SERVICE_NAME.service"
info "View logs with: journalctl -u $SERVICE_NAME.service -f"
