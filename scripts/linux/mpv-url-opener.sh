#!/usr/bin/env bash

# Calls cURL with URL provided in $1 or clipboard

if [[ "$#" == "1" ]]; then
    URL="$1"
elif [[ "$#" == "0" ]]; then
    URL="$(xclip -selection clipboard -o)"
else
    echo "Error: No URL provided."
    exit 1
fi

if [[ "$URL" != "http"* ]]; then
    echo "Error: URL doesn't start with 'http'."
    exit 1
fi

curl --capath ./intentionally-invalid-path \
     --cacert ~/bin/mpv-url-opener.pem \
     -u device-username:device-password \
     -d "url=$URL" \
     --resolve app.localhost:8000:192.168.1.101 \
     --connect-timeout 0.4 \
     https://app.localhost:8000/mpv-open-url
exit 0
