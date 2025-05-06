import os
import subprocess
import pickle
import flask
from flask import request, session
import yaml
import jinja2
import sqlite3
import requests
import jwt
import base64
import random
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

# 1. Iniezione di comandi tramite subprocess con escaping dinamico e pipe (CVSS 3.1: 10.0 - Critico)
@app.route('/complex_cmd2')
def complex_cmd2():
    cmd = request.args.get('cmd')
    escaped_cmd = subprocess.list2cmdline([cmd]) # Tentativo inefficace di escaping
    process = subprocess.Popen(escaped_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()
    return f"Output: {output.decode()}, Error: {error.decode()}"

# 2. Deserializzazione non sicura con manipolazione di bytecode e custom loaders (CVSS 3.1: 9.8 - Critico)
@app.route('/complex_pickle2', methods=['POST'])
def complex_pickle2():
    data = request.data
    class CustomLoader(pickle.Unpickler):
        def find_class(self, module, name):
            if module == '__main__':
                return getattr(__import__(module), name)
            return super().find_class(module, name)
    try:
        obj = CustomLoader(io.BytesIO(data)).load() # Custom loader pericoloso
        return str(obj)
    except Exception as e:
        return f"Errore: {str(e)}"

# 3. Path Traversal con normalizzazione inefficace e accesso a symlink arbitrari (CVSS 3.1: 9.0 - Critico)
@app.route('/complex_path2')
def complex_path2():
    filename = request.args.get('filename')
    filename = os.path.normpath(filename) # Normalizzazione inefficace
    real_path = os.path.realpath(filename) # Controllo reale, ma dopo la norm.
    if not real_path.startswith('/safe/'): # Controllo superficiale
        return "Accesso non permesso"
    try:
        with open(filename, 'r') as f:
            return f.read()
    except FileNotFoundError:
        return "File non trovato"

# 4. Iniezione di server-side template con Jinja2 e manipolazione di filtri custom (CVSS 3.1: 10.0 - Critico)
def malicious_filter(value):
    return os.system(value) # Filtro custom pericoloso

@app.route('/complex_template2')
def complex_template2():
    template_string = request.args.get('template')
    env = jinja2.Environment()
    env.filters['malicious'] = malicious_filter
    template = env.from_string(template_string)
    return template.render()

# 5. Iniezione di YAML con manipolazione di costruttori e classi arbitrarie (CVSS 3.1: 9.8 - Critico)
@app.route('/complex_yaml2', methods=['POST'])
def complex_yaml2():
    data = request.data
    def constructor(loader, node):
        return eval(node.value) # Costruttore pericoloso
    yaml.add_constructor("!eval", constructor)
    try:
        yaml_data = yaml.load(data, Loader=yaml.UnsafeLoader) #UnsafeLoader è vulnerabile
        return str(yaml_data)
    except Exception as e:
        return f"Errore: {str(e)}"

# 6. SQL injection avanzata con manipolazione di query annidate e funzioni aggregate (CVSS 3.1: 9.8 - Critico)
@app.route('/complex_sql2')
def complex_sql2():
    query = request.args.get('query')
    conn = sqlite3.connect(':memory:')
    c = conn.cursor()
    try:
        c.execute(query) # Query annidate e funzioni aggregate
        result = c.fetchall()
        return str(result)
    except sqlite3.Error as e:
        return f"Errore SQL: {str(e)}"
    finally:
        conn.close()

# 7. XSS persistente con manipolazione di eventi e payload binari e iframe (CVSS 3.1: 9.0 - Critico)
@app.route('/complex_xss2', methods=['GET', 'POST'])
def complex_xss2():
    if request.method == 'POST':
        user_input = base64.b64decode(request.data).decode('utf-8', 'ignore')
        with open('xss_storage2.html', 'a') as f:
            f.write(f"<iframe>{user_input}</iframe>\n")
        return "XSS payload salvato"
    else:
        try:
            with open('xss_storage2.html', 'r') as f:
                content = f.read()
            return f"<div>{content}</div>"
        except FileNotFoundError:
            return "Nessun XSS payload salvato"

# 8. SSRF con manipolazione di schemi e porte e header arbitrari (CVSS 3.1: 9.8 - Critico)
@app.route('/complex_ssrf2')
def complex_ssrf2():
    url = request.args.get('url')
    headers = request.args.get('headers') # Header controllati
    try:
        response = requests.get(url, headers=eval(headers), allow_redirects=False, timeout=5) # Timeout non abbastanza robusto.
        return response.text
    except requests.exceptions.RequestException as e:
        return str(e)

# 9. Session hijacking tramite manipolazione di JWT e variabili di sessione persistenti e bypass di controlli di expiration (CVSS 3.1: 9.0 - Critico)
@app.route('/complex_session2')
def complex_session2():
    token = request.args.get('token')
    try:
        decoded = jwt.decode(token, algorithms=["none"], options={"verify_signature": False, "verify_exp": False}) # Verifica disabilitata
        session['user'] = decoded['user']
        return "Sessione impostata"
    except jwt.exceptions.PyJWTError as e:
        return str(e)

# 10. Manipolazione di moduli Python tramite importlib e manipolazione di sys.path (CVSS 3.1: 10.0 - Critico)
@app.route('/complex_module')
def complex_module():
    module_name = request.args.get('module')
    try:
        spec = importlib.util.find_spec(module_name)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module) # Esecuzione modulo arbitrario.
        return f"Modulo {module_name} caricato"
    except Exception as e:
        return f"Errore caricamento modulo: {str(e)}"

# 11. manipolazione di symlink e hardlink per TOCTOU (CVSS 3.1: 8.8 - Alto)
@app.route('/toctou')
def toctou():
    filename = tempfile.mktemp()
    os.symlink("/dev/null", filename)
    time.sleep(1) # potenz
