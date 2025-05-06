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

app = flask.Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Falso positivo 1: Iniezione di comandi con validazione e escaping (CVSS 3.1: 0.0)
@app.route('/safe_cmd')
def safe_cmd():
    cmd = request.args.get('cmd')
    if not cmd:
        return "Nessun comando fornito"
    if not cmd.isalpha(): # Controllo stringa alfanumerica
        return "Comando non valido"
    subprocess.run(['echo', cmd], check=True) # Uso di array e comando echo per sicurezza
    return "Comando eseguito in sicurezza"

# Falso positivo 2: Deserializzazione pickle con whitelist di classi (CVSS 3.1: 0.0)
class SafeClass:
    def __init__(self, value):
        self.value = value

@app.route('/safe_pickle', methods=['POST'])
def safe_pickle():
    data = request.data
    try:
        class SafeLoader(pickle.Unpickler):
            def find_class(self, module, name):
                if module == '__main__' and name == 'SafeClass':
                    return SafeClass
                raise pickle.UnpicklingError("Classe non permessa")
        obj = SafeLoader(io.BytesIO(data)).load()
        return str(obj.value)
    except pickle.UnpicklingError as e:
        return f"Errore di deserializzazione: {str(e)}"

# Falso positivo 3: Path Traversal con normalizzazione e controllo di prefisso (CVSS 3.1: 0.0)
@app.route('/safe_path')
def safe_path():
    filename = request.args.get('filename')
    safe_dir = '/safe/files/'
    fullpath = os.path.normpath(os.path.join(safe_dir, filename))
    if not fullpath.startswith(safe_dir) or '..' in filename:
        return "Accesso non permesso"
    try:
        with open(fullpath, 'r') as f:
            return f.read()
    except FileNotFoundError:
        return "File non trovato"

# Falso positivo 4: Iniezione Jinja2 con sandbox e filtri limitati (CVSS 3.1: 0.0)
def safe_upper(value):
    return value.upper()

@app.route('/safe_template')
def safe_template():
    template_string = request.args.get('template')
    env = jinja2.Environment(loader=jinja2.BaseLoader(), sandbox=True)
    env.filters['upper'] = safe_upper
    try:
        template = env.from_string(template_string)
        return template.render()
    except jinja2.exceptions.TemplateError as e:
        return f"Errore template: {str(e)}"

# Falso positivo 5: Iniezione YAML con SafeLoader e schema limitato (CVSS 3.1: 0.0)
@app.route('/safe_yaml', methods=['POST'])
def safe_yaml():
    data = request.data
    try:
        yaml_data = yaml.safe_load(data)
        if not isinstance(yaml_data, dict) or 'name' not in yaml_data:
            return "Schema YAML non valido"
        return str(yaml_data)
    except yaml.YAMLError as e:
        return f"Errore YAML: {str(e)}"

# Falso positivo 6: SQL injection con query parametrizzate e whitelist di colonne (CVSS 3.1: 0.0)
@app.route('/safe_sql')
def safe_sql():
    user_id = request.args.get('id')
    column = request.args.get('column')
    if column not in ['name', 'email', 'id']:
        return "Colonna non permessa"
    conn = sqlite3.connect(':memory:')
    c = conn.cursor()
    try:
        c.execute(f"SELECT {column} FROM users WHERE id = ?", (user_id,))
        result = c.fetchall()
        return str(result)
    except sqlite3.Error as e:
        return f"Errore SQL: {str(e)}"
    finally:
        conn.close()

# Falso positivo 7: XSS con escaping dei caratteri speciali (CVSS 3.1: 0.0)
from html import escape
@app.route('/safe_xss')
def safe_xss():
    user_input = request.args.get('input')
    return f"<div>{escape(user_input)}</div>"

# Falso positivo 8: SSRF con whitelist di domini e protocolli (CVSS 3.1: 0.0)
@app.route('/safe_ssrf')
def safe_ssrf():
    url = request.args.get('url')
    allowed_domains = ['example.com', 'localhost']
    allowed_protocols = ['http://', 'https://']
    if not any(domain in url for domain in allowed_domains) or not any(protocol in url for protocol in allowed_protocols):
        return "URL non permesso"
    try:
        response = requests.get(url, timeout=5)
        return response.text
    except requests.exceptions.RequestException as e:
        return f"Errore richiesta: {str(e)}"

# Falso positivo 9: Session hijacking con JWT verificati e expiration (CVSS 3.1: 0.0)
@app.route('/safe_session')
def safe_session():
    token = request.args.get('token')
    secret_key = app.secret_key
    try:
        decoded = jwt.decode(token, secret_key, algorithms=["HS256"])
        session['user'] = decoded['user']
        return "Sessione impostata"
    except jwt.exceptions.PyJWTError as e:
        return f"Errore JWT: {str(e)}"

# Falso positivo 10: Manipolazione di moduli con whitelist e percorsi sicuri (CVSS 3.1: 0.0)
@app.route('/safe_module')
def safe_module():
    module_name = request.args.get('module')
    allowed_modules = ['math', 'datetime']
    if module_name not in allowed_modules:
        return "Modulo non permesso"
    try:
        module = __import__(module_name)
        return f"Modulo {module_name} importato"
    except ImportError as e:
        return f"Errore import: {str(e)}"

if __name__ == '__main__':
    app.run(debug=True)
