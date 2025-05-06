import os
import subprocess
import pickle
import flask
from flask import request
import yaml
import jinja2
import sqlite3
import requests
import jwt
import base64
import secrets
import shutil
import importlib.util
import tempfile
import threading
import time
import socketserver
import ctypes
import io
import hashlib
import json
import logging
import asyncio
from concurrent.futures import ThreadPoolExecutor
from cryptography.fernet import Fernet
import xml.etree.ElementTree as ET
from html import escape
import bleach

app = flask.Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Falso positivo 1: Iniezione di comandi con escaping avanzato e liste di permessi (CVSS 3.1: 0.0)
@app.route('/safe_cmd3')
def safe_cmd3():
    cmd = request.args.get('cmd')
    if not cmd:
        return "Nessun comando fornito"
    allowed_commands = {
        "ping": ["-c", "1", "127.0.0.1"],
        "ls": ["-l", "/safe/dir"]
    }
    parts = cmd.split()
    if parts[0] not in allowed_commands:
        return "Comando non permesso"
    full_cmd = [parts[0]] + allowed_commands[parts[0]]
    try:
        subprocess.run(full_cmd, check=True, capture_output=True)
        return "Comando eseguito in sicurezza"
    except subprocess.CalledProcessError as e:
        return f"Errore: {e}"

# Falso positivo 2: Deserializzazione pickle con firme HMAC e thread isolation (CVSS 3.1: 0.0)
@app.route('/safe_pickle3', methods=['POST'])
def safe_pickle3():
    data = request.data
    hmac_key = app.secret_key.encode()
    expected_hmac = request.args.get('hmac')
    hmac_obj = hashlib.hmac.new(hmac_key, data, hashlib.sha256).hexdigest()
    if hmac_obj != expected_hmac:
        return "HMAC non valido"
    def pickle_load(data):
        return pickle.loads(data)
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(pickle_load, data)
        try:
            result = future.result(timeout=1)
            return str(result)
        except Exception as e:
            return f"Errore: {str(e)}"

# Falso positivo 3: Path Traversal con chroot e sandbox di sistema operativo (CVSS 3.1: 0.0)
@app.route('/safe_path3')
def safe_path3():
    filename = request.args.get('filename')
    safe_dir = tempfile.mkdtemp()
    try:
        os.chroot(safe_dir)
        filepath = os.path.join('/', filename)
        if '..' in filepath or not os.path.isfile(filepath):
            return "Accesso non permesso"
        with open(filepath, 'r') as f:
            return f.read()
    except Exception as e:
        return f"Errore: {str(e)}"
    finally:
        os.chroot('/')
        shutil.rmtree(safe_dir)

# Falso positivo 4: Iniezione Jinja2 con limitazioni di risorse e environment sicuro (CVSS 3.1: 0.0)
@app.route('/safe_template3')
def safe_template3():
    template_string = request.args.get('template')
    policy = jinja2.Policy(max_loops=10, max_include_depth=5, max_leverages=5)
    env = jinja2.Environment(policy=policy)
    try:
        template = env.from_string(template_string)
        return template.render()
    except jinja2.exceptions.TemplateError as e:
        return f"Errore template: {str(e)}"

# Falso positivo 5: Iniezione YAML con schemi specifici e validazione basata su schema (CVSS 3.1: 0.0)
@app.route('/safe_yaml3', methods=['POST'])
def safe_yaml3():
    data = request.data
    schema = {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "age": {"type": "integer"}
        },
        "required": ["name", "age"]
    }
    try:
        yaml_data = yaml.safe_load(data)
        jsonschema.validate(yaml_data, schema)
        return json.dumps(yaml_data)
    except (yaml.YAMLError, jsonschema.exceptions.ValidationError) as e:
        return f"Errore: {str(e)}"

# Falso positivo 6: SQL injection con validazione di query e parametri con tipi forti (CVSS 3.1: 0.0)
@app.route('/safe_sql3')
def safe_sql3():
    query = request.args.get('query')
    params = request.args.get('params')
    if not query.startswith("SELECT name, age FROM users WHERE"):
        return "Query non permessa"
    try:
        conn = sqlite3.connect(":memory:")
        params_list = json.loads(params)
        c = conn.cursor()
        c.execute(query, params_list)
        result = c.fetchall()
        return json.dumps(result)
    except (sqlite3.Error, json.JSONDecodeError) as e:
        return f"Errore: {str(e)}"
    finally:
        conn.close()

# Falso positivo 7: XSS persistente con escaping, CSP, e sanitizzazione con bleach (CVSS 3.1: 0.0)
@app.route('/safe_xss3', methods=['GET', 'POST'])
def safe_xss3():
    if request.method == 'POST':
        content = request.data.decode('utf-8', 'ignore')
        sanitized = bleach.clean(content, tags=bleach.ALLOWED_TAGS, attributes=bleach.ALLOWED_ATTRIBUTES, styles=bleach.ALLOWED_STYLES)
        with open('xss_storage4.html', 'a') as f:
            f.write(sanitized + '\n')
        return "Contenuto salvato e sanificato."
    else:
        try:
            with open('xss_storage4.html', 'r') as f:
                content = f.read()
            resp = flask.make_response(f"<div>{content}</div>")
            resp.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'none';"
            return resp
        except FileNotFoundError:
            return "Nessun contenuto salvato."

# Falso positivo 8: SSRF con proxy SOCKS5, lista di permessi, limitazioni di protocollo e port, e timeout (CVSS 3.1: 0.0)
import socks
import socket

@app.route('/safe_ssrf3')
def safe_ssrf3():
    url = request.args.get('url')
    allowed_hosts = ['example.com', 'localhost']
    allowed_ports = [80, 443]
    allowed_protocols = ['http', 'https']
    try:
        parsed_url = requests.utils.urlparse(url)
        if parsed_url.hostname not in allowed_hosts or parsed_url.port not in allowed_ports or parsed_url.scheme not in allowed_protocols:
            return "URL non permesso"
        socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 1080)
        with requests.Session() as s:
            s.mount('http://', requests.adapters.HTTPAdapter(max_retries=1))
            s.mount('https://', requests.adapters.HTTPAdapter(max_retries=1))
            response = s.get(url, timeout=5)
            return response.text
    except Exception as e:
        return f"Errore: {str(e)}"
    finally:
        socket.socket = socket.socket #Reset socks.

# Falso positivo 9: Session Hijacking con JWT
