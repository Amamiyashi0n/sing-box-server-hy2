#!/bin/sh
IFS= read -r request_line || exit 0
carriage_return=$(printf '\r')
while IFS= read -r header; do
    [ "$header" = "$carriage_return" ] && break
done
size=${LOAD_RESPONSE_MIB:-1}
length=$((size * 1048576))
printf 'HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %s\r\nConnection: close\r\n\r\n' "$length"
dd if=/dev/zero bs=1048576 count="$size" 2>/dev/null
