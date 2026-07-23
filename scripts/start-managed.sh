#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
config_path=${CONFIG_PATH:-$project_dir/config.toml}
admin_listen=${ADMIN_LISTEN:-0.0.0.0:9080}
token_file=${ADMIN_TOKEN_FILE:-$project_dir/.admin-token}
binary=${BINARY_PATH:-$project_dir/target/release/sing-box-ser-mini}

if [ ! -f "$token_file" ]; then
    umask 077
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' >"$token_file"
fi

exec "$binary" \
    --config "$config_path" \
    --admin-listen "$admin_listen" \
    --admin-token-file "$token_file"
