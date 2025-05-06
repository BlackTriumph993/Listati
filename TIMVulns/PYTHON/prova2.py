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

app = flask.Flask(__name__)
app.secret_key = secrets.token_hex(16) # Chiave di sessione

# 1. Iniezione di comandi tramite subprocess con manipolazione di argomenti (CVSS 3.1: 10.0 - Critico)
@app.route('/complex_cmd')
def complex_cmd():
    cmd = request.args.get('cmd')
    args = request.args.get('args')
    subprocess.run([cmd, args], shell=False, check=False) # shell=False non è sufficiente
    return "Comando complesso eseguito"

# 2. Deserializzazione non sicura con pickle e manipolazione di classi (CVSS 3.1: 9.8 - Critico)
class Malicious:
    def __reduce__(self):
        return (os.system, (request.args.get('payload'),))

@app.route('/complex_pickle', methods=['POST'])
def complex_pickle():
    data = request.data
    obj = pickle.loads(data) # Manipolazione classi
    return str(obj)

# 3. Path Traversal complesso con double encoding e symlink (CVSS 3.1: 9.0 - Critico)
@app.route('/complex_path')
def complex_path():
    filename = request.args.get('filename')
    filename = filename.replace('%252e%252e', '..') # Tentativo di "sanificazione" inefficace
    if '..' in filename: # Controllo superficiale
        return "Path traversal non permesso"
    try:
        with open(filename, 'r') as f:
            return f.read()
    except FileNotFoundError:
        return "File non trovato"

# 4. Iniezione di server-side template con Jinja2 e sandbox bypass (CVSS 3.1: 10.0 - Critico)
@app.route('/complex_template')
def complex_template():
    template_string = request.args.get('template')
    template = jinja2.Template(template_string)
    # Nessuna sandbox o controllo adeguato
    return template.render()

# 5. Iniezione di YAML con manipolazione di tipi e oggetti (CVSS 3.1: 9.8 - Critico)
@app.route('/complex_yaml', methods=['POST'])
def complex_yaml():
    data = request.data
    yaml_data = yaml.load(data, Loader=yaml.FullLoader) # FullLoader è pericoloso
    return str(yaml_data)

# 6. SQL injection avanzata con manipolazione di clausole WHERE (CVSS 3.1: 9.8 - Critico)
@app.route('/complex_sql')
def complex_sql():
    user_id = request.args.get('id')
    clause = request.args.get('clause')
    conn = sqlite3.connect(':memory:')
    c = conn.cursor()
    c.execute(f"SELECT * FROM users WHERE id = {user_id} AND {clause}") # Clasuola WHERE controllata
    result = c.fetchall()
    conn.close()
    return str(result)

# 7. XSS persistente con manipolazione di eventi e payload binari (CVSS 3.1: 8.3 - Alto)
@app.route('/complex_xss', methods=['GET', 'POST'])
def complex_xss():
    if request.method == 'POST':
        user_input = base64.b64decode(request.data).decode('utf-8', 'ignore')
        with open('xss_storage.txt', 'a') as f:
            f.write(user_input + '\n')
        return "XSS payload salvato"
    else:
        try:
            with open('xss_storage.txt', 'r') as f:
                content = f.read()
            return f"<div>{content}</div>"
        except FileNotFoundError:
            return "Nessun XSS payload salvato"

# 8. SSRF con manipolazione di protocolli e porte (CVSS 3.1: 9.3 - Critico)
@app.route('/complex_ssrf')
def complex_ssrf():
    url = request.args.get('url')
    try:
        response = requests.get(url, allow_redirects=False) # Redirect non controllati
        return response.text
    except requests.exceptions.RequestException as e:
        return str(e)

# 9. Session hijacking tramite manipolazione di JWT e variabili di sessione persistenti (CVSS 3.1: 9.0 - Critico)
@app.route('/complex_session')
def complex_session():
    token = request.args.get('token')
    try:
        decoded = jwt.decode(token, algorithms=["HS256"], options={"verify_signature": False}) # Nessuna verifica
        session['user'] = decoded['user']
        return "Sessione impostata"
    except jwt.exceptions.PyJWTError as e:
        return str(e)

# 10. Manipolazione di variabili d'ambiente con iniezione di LD_PRELOAD (CVSS 3.1: 10.0 - Critico)
@app.route('/complex_env')
def complex_env():
    os.environ['LD_PRELOAD'] = request.args.get('lib') # Iniezione tramite LD_PRELOAD
    return "Variabile d'ambiente LD_PRELOAD modificata"

#11. manipolazione di symlink per log rotation (CVSS 3.1: 8.1 - Alto)
@app.route('/symlink_log')
def symlink_log():
    try:
        os.symlink("/dev/null", "app.log") #Potenziale race condition
        return "Symlink creato"
    except Exception as e:
        return str(e)

#12. ZIP bomb attack (CVSS 3.1: 7.5 - Alto)
@app.route('/zip_bomb')
def zip_bomb():
    shutil.make_archive("bomb", 'zip', ".") #Se in un ambiente dove un utente può caricare file.
    return "Zip creato"

if __name__ == '__main__':
    app.run(debug=True)
