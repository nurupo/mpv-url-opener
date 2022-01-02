# mpv url opener https server

A small https server that listens for requests to open YouTube URLs in mpv.

## Why

I wanted an easy way to share videos from [NewPipe](https://newpipe.net) on my Android phone with [mpv](https://mpv.io/)+[youtube-dl](https://github.com/yt-dlp/yt-dlp) on my Linux PC.

## How

### Phone-side (client-side)

While I could have gone all out and written an Android application that implements [the share API](https://developer.android.com/training/sharing/receive), so that I could share a video link with the app from NewPipe, and the app would send it over to the PC, it sounded like an over-engineering to write an app whose entire purpose is to send a single HTTP POST request, a lot of an unnecessary complexity for something so simple.

Instead I decided on using [Termux](https://termux.com), which I already have installed and use often.
Termux is an Android terminal emulator and Linux environment app.
You can run bash and various command line programs in it, including `curl`!
In addition, Termux [allows other apps to share URLs with it](https://wiki.termux.com/wiki/Intents_and_Hooks), which it then passes to a user-provided shell script as an argument.
You probably can already see where I'm going with this.

The way it works, you share a video URL in NewPipe with Termux app, Termux executes our shell script with the URL as an argument, which runs `curl` to send a POST request containing the video URL as a payload to the PC.
Everything happens automatically after you select Termux in the list of apps to share the video with, there is no extra input or interaction required and it all happens in a blink of an eye: Termux pops up, runs the `curl` command, and immediately disappears, bringing you back to NewPipe.

Writing a single `curl` command is sure easier than writing an Android app!

### PC-side (server-side)

On PC we run a simple https server app that listens for POST requests and opens links in mpv.

## Setup

### PC-side

Create a home directory for the server, e.g.:

```sh
mkdir "${XDG_DATA_HOME:-$HOME/.local/share}/mpv-url-opener"
```

Since the server would need to spawn mpv processes with our user's privileges, it's easier to do so if it runs under our user to begin with.
So we do a user-local install of the server/daemon.

Put `mpv-url-opener.py` in there:

```sh
cp mpv-url-opener.py "${XDG_DATA_HOME:-$HOME/.local/share}/mpv-url-opener"
```

Edit the config file for your needs and install it:

```sh
cp config.json "${XDG_DATA_HOME:-$HOME/.local/share}/mpv-url-opener"
editor "${XDG_DATA_HOME:-$HOME/.local/share}/mpv-url-opener/config.json"
```

Change the default `device-username` and `device-password` placeholders to something else.
The password would get replaced by its hash once you start the server.

Generate an SSL cert with:

```sh
sudo apt install openssl
openssl req -x509 -nodes -newkey rsa:4096 -days 3650 \
            -subj '/CN=app.localhost' -addext "subjectAltName=DNS:app.localhost" \
            -keyout "${XDG_DATA_HOME:-$HOME/.local/share}/mpv-url-opener/key.pem" \
            -out    "${XDG_DATA_HOME:-$HOME/.local/share}/mpv-url-opener/cert.pem"
```

This will create a self-signed certificate for `app.localhost` expiring in about 10 years and the corresponding private key.
Keep `app.localhost` as it is, don't worry that doesn't resolve to anything, we will address that later.

Create a python virtual environment for the server:

```sh
sudo apt install python3-virtualenv
python3 -m virtualenv "${XDG_DATA_HOME:-$HOME/.local/share}/mpv-url-opener/env"
"${XDG_DATA_HOME:-$HOME/.local/share}/mpv-url-opener/env/bin/pip3" install -r requirements.txt
```

Edit the service file for your needs (paths, IP, port, etc.), install it and start the service:

```sh
mkdir -p "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
cp mpv-url-opener.service "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
editor "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/mpv-url-opener.service"
systemctl --user daemon-reload
systemctl --user enable mpv-url-opener.service
systemctl --user start mpv-url-opener.service
```

Note that you can make the server listen on multiple IP addresses, even on addresses that doesn't yet exist (it sets `IP_FREEBIND`).
Just specify more ip:port pairs to `--ip-port`, e.g. `--ip-port 192.168.1.101:8000 192.168.1.102:8000`.

Check to see if the server is running properly:

```sh
systemctl --user status mpv-url-opener.service
journalctl --user -u mpv-url-opener.service
```

Fix any issues if it fails to start.

Print the SSL certificate fingerprint:

```sh
openssl x509 -noout -sha256 -fingerprint \
             -in "${XDG_DATA_HOME:-$HOME/.local/share}/mpv-url-opener/cert.pem"
```

Take a note of it, will need it for later.

### Phone-side

Install [Termux](https://termux.com).

Run Termux and install the required packages:

```sh
pkg upgrade
pkg install curl openssl-tool
```

Create `~/bin` and download the server SSL certificate into it:

```sh
mkdir -p ~/bin
echo -n | openssl s_client -connect 192.168.1.101:8000 | openssl x509 > ~/bin/mpv-url-opener.pem
```

Change the IP address and port to those of the server.

Check that the certificate fingerprint matches the one we got on PC earlier:

```sh
openssl x509 -noout -sha256 -fingerprint -in ~/bin/mpv-url-opener.pem
```

If they don't match, you have downloaded the certificate for the wrong server.

Create `termux-url-opener`:

```sh
echo '#!/data/data/com.termux/files/usr/bin/sh
curl --capath ./intentionally-invalid-path \
     --cacert ~/bin/mpv-url-opener.pem \
     -u device-username:device-password \
     -d "url=$1" \
     --resolve app.localhost:8000:192.168.1.101 \
     https://app.localhost:8000/mpv-open-url
' > ~/bin/termux-url-opener
editor ~/bin/termux-url-opener
chmod +x ~/bin/termux-url-opener
```

Change the IP address and port to those of the server and change `device-username` and `device-password` to the ones you have set on the server.

`--capath`, `--cacert` and `https://` make sure that curl refuses to connect to anything other than our server (SSL certificate authentication).

`--resolve` tells curl to resolve `app.localhost` for port 8000 as `192.168.1.101`, which is needed for the certificate verification to work as our certificate is for `app.localhost`.

If your server might be using a couple of different IPs, e.g. the server is running on your laptop that you take with you somewhere else, as long as you know the IPs beforehand, you could list them in `--resolve` with a comma, e.g. `--resolve app.localhost:8000:192.168.1.101,192.168.1.102,192.168.1.103`, from the most probable to the least, and also set `--connect-timeout` to some small value so that curl doesn't wait too long when trying to use the wrong IP, e.g. `--connect-timeout 0.2`.
`curl` will try to connect to the IPs in the order they are listed.

## Security

While intended to run on a secure home LAN, I have added some security measures in case I run the server on a laptop and would want to use it while on someone ease's LAN.

- The server is HTTPS only, so the communication is SSL encrypted.
- The server relies on Python providing secure SSL defaults, [which it does](https://docs.python.org/3/library/ssl.html#cipher-selection), as long as you keep python up-to-date enough.
- Since it's intended for home LAN usage, the server uses a self-signed SSL certificate.
- The server authenticates the client via username:password Basic HTTP Authentication, preventing unauthorized parties from opening videos on your PC. Failed attempts are rate limited to 5/hour by the sender IP.
- The client authenticates the server against the pre-downloaded SSL certificate file, preventing MITM and sharing the username:password, along with the video URL, with unintended parties in general.
- The server validates that the input it receives from the client is exactly a YouTube URL, no more and no less, avoiding any command injections. Additionally, it executes the mpv binary directly, without any shell interpreter, which also helps protect against command injections.

## Running behind a proxy

The server is a Flask app that uses Waitress WSGI server.
Waitress was chosen because it's easy to set socket options using it.
I don't run a proxy server on my PC, so I wrote the application with the idea that it won't be running behind a proxy and made it handle everything on it's own: SSL, Basic HTTP Authentication, etc.

As such, running behind a proxy server is not supported, though it could be done with some minimal modifications.
Some of the modifications would be: removing the SSL support from the app, delegating SSL handling to the proxy instead, and modifying the rate limiting code, as it would see the requests as coming from the IP of the proxy server (e.g. 127.0.0.1), instead of users' IP addresses.

## Zombie processes

mpv processes spawned by the server will remain as zombies after mpv is closed.
There is no real harm in them remaining, they don't use up RAM or other resources.

The zombie processes get removed whenever the server spawns mpv (at least in [the CPython implementation](https://github.com/python/cpython/blob/3.9/Lib/subprocess.py#L244-L261)) or when the server is restarted (`systemctl --user restart mpv-url-opener.service`).

## License

AGPL-3.0-only
