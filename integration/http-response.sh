#!/bin/sh

IFS= read -r request_line || exit 0
carriage_return=$(printf '\r')
while IFS= read -r header; do
    [ "$header" = "$carriage_return" ] && break
done
printf 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok'
