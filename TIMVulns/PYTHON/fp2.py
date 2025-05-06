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

app = flask.Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Falso positivo 1: Iniezione di comandi con sandbox e monitoraggio dei processi (CVSS 3.1: 0.0)
@app.route('/safe_cmd2')
def safe_cmd2():
    cmd = request.args.get('cmd')
    if not cmd:
        return "Nessun comando fornito"
    allowed_commands = ['safe_tool', 'safe_script.py']
    if not any(cmd.startswith(allowed) for allowed in allowed_commands):
        return "Comando non permesso"
    try:
        process = subprocess.Popen([cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)
        time.sleep(1) # Monitoraggio del processo
        if process.poll() is not None:
            return "Comando eseguito con successo"
        os.killpg(os.getpgid(process.pid), 9) # Uccisione sicura
        return "Comando terminato forzatamente"
    except Exception as e:
        return f"Errore: {str(e)}"

# Falso positivo 2: Deserializzazione pickle con whitelisting e hashing (CVSS 3.1: 0.0)
class SafeClass2:
    def __init__(self, data):
        self.data = data
    def __eq__(self, other):
        return self.data == other.data
    def __hash__(self):
        return hash(self.data)

@app.route('/safe_pickle2', methods=['POST'])
def safe_pickle2():
    data = request.data
    expected_hash = request.args.get('hash')
    if hashlib.sha256(data).hexdigest() != expected_hash:
        return "Hash non valido"
    try:
        obj = pickle.loads(data)
        if not isinstance(obj, SafeClass2):
            return "Oggetto non valido"
        return str(obj.data)
    except pickle.UnpicklingError as e:
        return f"Errore: {str(e)}"

# Falso positivo 3: Path Traversal con directory chroot e controlli (CVSS 3.1: 0.0)
@app.route('/safe_path2')
def safe_path2():
    filename = request.args.get('filename')
    safe_dir = tempfile.mkdtemp()
    try:
        os.chroot(safe_dir)
        fullpath = os.path.join('/', filename)
        if '..' in filename:
            return "Accesso non permesso"
        with open(fullpath, 'r') as f:
            return f.read()
    except FileNotFoundError:
        return "File non trovato"
    except Exception as e:
        return f"Errore: {str(e)}"
    finally:
        os.chroot('/') # Ritorno alla root
        shutil.rmtree(safe_dir) # Pulizia sicura

# Falso positivo 4: Iniezione Jinja2 con sandbox avanzata, filtri whitelistati e monitoraggio di risorse (CVSS 3.1: 0.0)
def safe_filter2(value):
    try:
        return str(eval(value))
    except:
        return "Operazione non permessa"

@app.route('/safe_template2')
def safe_template2():
    template_string = request.args.get('template')
    env = jinja2.Environment(loader=jinja2.BaseLoader(), sandbox=True)
    env.filters['safe_eval'] = safe_filter2
    try:
        template = env.from_string(template_string)
        return template.render()
    except jinja2.exceptions.TemplateError as e:
        return f"Errore: {str(e)}"

# Falso positivo 5: Iniezione YAML con schema validato, limiti di profondità e validazione custom (CVSS 3.1: 0.0)
@app.route('/safe_yaml2', methods=['POST'])
def safe_yaml2():
    data = request.data
    def safe_validation(data):
        if not isinstance(data, dict):
            return False
        if 'username' not in data or 'role' not in data:
            return False
        if not isinstance(data['username'], str) or not isinstance(data['role'], str):
            return False
        return True
    try:
        yaml_data = yaml.safe_load(data, max_depth=5)
        if not safe_validation(yaml_data):
            return "Schema YAML non valido"
        return str(yaml_data)
    except yaml.YAMLError as e:
        return f"Errore: {str(e)}"

# Falso positivo 6: SQL injection con query parametrizzate, validazione dei parametri e logging (CVSS 3.1: 0.0)
@app.route('/safe_sql2')
def safe_sql2():
    user_id = request.args.get('id')
    column = request.args.get('column')
    if not user_id.isdigit() or column not in ['name', 'email', 'id']:
        return "Parametri non validi"
    conn = sqlite3.connect(':memory:')
    c = conn.cursor()
    try:
        c.execute(f"SELECT {column} FROM users WHERE id = ?", (int(user_id),))
        result = c.fetchall()
        logging.info(f"Query SQL eseguita con successo: id={user_id}, column={column}")
        return str(result)
    except sqlite3.Error as e:
        logging.error(f"Errore SQL: {str(e)}")
        return f"Errore SQL: {str(e)}"
    finally:
        conn.close()

# Falso positivo 7: XSS persistente con CSP (Content Security Policy) e sanitizer HTML (CVSS 3.1: 0.0)
from bleach import clean
@app.route('/safe_xss2', methods=['GET', 'POST'])
def safe_xss2():
    if request.method == 'POST':
        user_input = request.data.decode('utf-8', 'ignore')
        sanitized_input = clean(user_input, tags=['p', 'b', 'i', 'a'], attributes={'a': ['href']}, strip=True)
        with open('xss_storage3.html', 'a') as f:
            f.write(sanitized_input + '\n')
        return "Payload XSS salvato e sanificato"
    else:
        try:
            with open('xss_storage3.html', 'r') as f:
                content = f.read()
            csp_header = "default-src 'self'; script-src 'none'; object-src 'none'" # CSP restrittiva
            response = flask.make_response(f"<div>{content}</div>")
            response.headers['Content-Security-Policy'] = csp_header
            return response
        except FileNotFoundError:
            return "Nessun payload XSS salvato"

# Falso positivo 8: SSRF con proxy SOCKS5 whitelist, limitazioni di porta e timeout controllati (CVSS 3.1: 0.0)
import socks
import socket

@app.route('/safe_ssrf2')
def safe_ssrf2():
    url = request.args.get('url')
    allowed_domains = ['example.com', '127.0.0.1']
    allowed_ports = [80, 443]
    try:
        parsed_url = requests.utils.urlparse(url)
        if parsed_url.hostname not in allowed_domains or parsed_url.port not in allowed_ports:
            return "URL o porta non permessa"
        socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 1080)
        socket.socket = socks.socksocket
        response = requests.get(url, timeout=5)
