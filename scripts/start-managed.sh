#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
config_path=${CONFIG_PATH:-$project_dir/config.toml}
admin_listen=${ADMIN_LISTEN:-0.0.0.0:9080}
credentials_file=${ADMIN_CREDENTIALS_FILE:-$project_dir/.admin-credentials.toml}
binary=${BINARY_PATH:-$project_dir/target/release/sing-box-ser-mini}

exec "$binary" \
    --config "$config_path" \
    --admin-listen "$admin_listen" \
    --admin-credentials-file "$credentials_file"
