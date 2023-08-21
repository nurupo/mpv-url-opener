# -*- coding: utf-8 -*-
#
# This file is part of the mpv-url-opener, mpv url opener https server.
#
# Copyright (C) 2021-2023 Maxim Biro <nurupo.contributions@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License version 3,
# as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import argparse
import json
import logging
import os
import re
import socket
import ssl
import subprocess
import sys

import waitress
from flask import Flask, abort, request
from flask_httpauth import HTTPBasicAuth
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from paste.translogger import TransLogger
from werkzeug.security import check_password_hash, generate_password_hash

root_logger = logging.getLogger()
root_logger.setLevel(logging.DEBUG)

# On Windows, log to a rotating file under ./logs/
if os.name == 'nt':
    # We disable TransLogger's console handler because it sets propagate=False, which prevents us from writing everything to a file
    translogger_setup_console_handler = False

    from logging.handlers import TimedRotatingFileHandler

    if not os.path.isdir('logs'):
        os.mkdir('logs')
    file_handler = TimedRotatingFileHandler('logs/mpv-url-opener.log', when='D', interval=7, backupCount=4)
    root_logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    root_logger.addHandler(console_handler)
else:
    translogger_setup_console_handler = True

app = Flask(__name__)
auth = HTTPBasicAuth()
config = None
limiter = Limiter(
    app,
    key_func=get_remote_address
)

@auth.verify_password
def verify_password(username, password):
    if username in config['HTTP_AUTH_DB'] and check_password_hash(config['HTTP_AUTH_DB'][username], password):
        return username
    else:
        logging.warning('{}: Failed auth from {} for {}'.format(request.host, request.remote_addr, username))

@app.route('/mpv-open-url', methods=['POST'])
@limiter.limit("5/hour", deduct_when=lambda response: response.status_code == 401)
@auth.login_required
def mpv_open_url():
    url = request.form.get('url', type=str)
    if not re.fullmatch(r'https://(www\.youtube\.com/watch\?v=|youtu.be/)[0-9a-zA-Z-_]{,16}', url):
        abort(400)
    logging.debug('{}: {} ({}) has requested {}'.format(request.host, auth.current_user(), request.remote_addr, url))
    logging.debug('Running "{}"'.format(' '.join([config['MPV_BIN_PATH'], url] + config['MPV_EXTRA_ARGS'])))
    subprocess.Popen([config['MPV_BIN_PATH'], url] + config['MPV_EXTRA_ARGS'], start_new_session=True,
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return '', 200

def config_hash_plaintext_passwords(config_path):
    hashed_password = False
    for user, password in config['HTTP_AUTH_DB'].items():
        if not re.fullmatch(r'.+\$.+\$.+', password):
            logging.info(f'Overwriting the password for user "{user}" with its hash')
            config['HTTP_AUTH_DB'][user] = generate_password_hash(password)
            hashed_password = True
    if hashed_password:
        with open(config_path, 'w') as f:
            logging.info('Updating the config file')
            json.dump(config, f, sort_keys=True, indent=4)

def parse_args():
    parser = argparse.ArgumentParser(description='mpv url opener https server')
    parser.add_argument('--ip-port', required=True, nargs='+', help='IPv4:port address to listen on')
    parser.add_argument('--ssl-cert', required=True, default='cert.pem', help='SSL/TLS public certificate file path')
    parser.add_argument('--ssl-key', required=True, default='key.pem', help='SSL/TLS private key file path')
    parser.add_argument('--config', required=True, default='config.json', help='Config file path')
    args = parser.parse_args()

    ip_ports = []
    for ip_port in args.ip_port:
        if ip_port.count(':') != 1:
            logging.error(f'Error: IP_PORT {ip_port} should contain one colon ":"')
            sys.exit(1)
        (ip, port) = tuple(ip_port.split(':'))
        port = int(port)
        ip_ports.append((ip, port))

    return ip_ports, args.ssl_cert, args.ssl_key, args.config

def fix_waitress_ssl_accept_error():
    # Waitress doesn't support SSL, so it doesn't handle ssl.SSLError
    # exceptions and spams the log with stack traces. Let's fix that.
    waitress.wasyncore.dispatcher._accept = waitress.wasyncore.dispatcher.accept
    def my_accept(self, *args, **kwargs):
        try:
            return self._accept(*args, **kwargs)
        except ssl.SSLError:
            return None
    waitress.wasyncore.dispatcher.accept = my_accept

if __name__ == '__main__':
    ip_ports, cert, key, config_path = parse_args()

    with open(config_path, 'r') as f:
        config = json.load(f)
    config_hash_plaintext_passwords(config_path)

    sockets = []
    for (ip, port) in ip_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if os.name != 'nt':
            s.setsockopt(socket.IPPROTO_IP, 15, 1) # IP_FREEBIND=15
        s.bind((ip, port))
        s = ssl.wrap_socket(s, keyfile=key, certfile=cert, server_side=True)
        sockets.append(s)

    fix_waitress_ssl_accept_error()
    logging.info('Listening for requests on: {}'.format(', '.join([f'https://{ip}:{port}/mpv-open-url' for (ip, port) in ip_ports])))
    waitress.serve(TransLogger(app, setup_console_handler=translogger_setup_console_handler), sockets=sockets, threads=4, url_scheme='https')
    s.close()
