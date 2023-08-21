param (
    [parameter(Mandatory=$false)]
    [string]$URL
)
if ($URL -eq "") {
    $URL = Get-Clipboard
}
if (!$URL.StartsWith("http")) {
    throw "URL doesn't start with 'http'."
}

& curl.exe --capath ./intentionally-invalid-path `
           --cacert ./mpv-url-opener.pem `
           -u device-username:device-password `
           -d "url=$URL" `
           --resolve app.localhost:8000:192.168.1.101 `
           --connect-timeout 0.4 `
           https://app.localhost:8000/mpv-open-url
