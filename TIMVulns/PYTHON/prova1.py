import os
import subprocess
import pickle
import flask
from flask import request
import yaml
import jinja2

app = flask.Flask(__name__)

# 1. Iniezione di comandi tramite subprocess (CVSS 3.1: 9.8 - Critico)
@app.route('/cmd_injection')
def cmd_injection():
    command = request.args.get('cmd')
    subprocess.run(command, shell=True)
    return "Comando eseguito"

# 2. Deserializzazione non sicura con pickle (CVSS 3.1: 9.8 - Critico)
@app.route('/pickle_deserialize', methods=['POST'])
def pickle_deserialize():
    data = request.data
    obj = pickle.loads(data)
    return str(obj)

# 3. Path Traversal (CVSS 3.1: 7.5 - Alto)
@app.route('/read_file')
def read_file():
    filename = request.args.get('filename')
    with open(filename, 'r') as f:
        return f.read()

# 4. Iniezione di server-side template con Jinja2 (CVSS 3.1: 9.8 - Critico)
@app.route('/template')
def template():
    template_string = request.args.get('template')
    template = jinja2.Template(template_string)
    return template.render()

# 5. Iniezione di YAML (CVSS 3.1: 9.8 - Critico)
@app.route('/yaml', methods=['POST'])
def yaml_injection():
  data = request.data
  yaml_data = yaml.safe_load(data)
  return str(yaml_data)

# 6. SQL injection (CVSS 3.1: 9.8 - Critico)
@app.route('/sql')
def sql_injection():
    user_id = request.args.get('id')
    import sqlite3 #In un ambiente di produzione sarebbe più complesso.
    conn = sqlite3.connect(':memory:') # Database in memoria, per semplificare l'esempio
    c = conn.cursor()
    c.execute(f"SELECT * FROM users WHERE id = {user_id}")
    result = c.fetchall()
    conn.close()
    return str(result)

# 7. XSS (Cross-site scripting) (CVSS 3.1: 6.1 - Medio)
@app.route('/xss')
def xss():
    user_input = request.args.get('input')
    return f"<div>{user_input}</div>"

# 8. SSRF (Server-side request forgery) (CVSS 3.1: 9.0 - Critico)
import requests
@app.route('/ssrf')
def ssrf():
    url = request.args.get('url')
    response = requests.get(url)
    return response.text

# 9. Gestione non sicura delle sessioni (CVSS 3.1: 8.1 - Alto)
@app.route('/session')
def session_insecure():
    flask.session['data'] = request.args.get('data') #Cookie senza HttpOnly e Secure.
    return "Sessione impostata"

# 10. Manipolazione variabili d'ambiente (CVSS 3.1: 7.8 - Alto)
@app.route('/env')
def env_manipulation():
    variable = request.args.get('variable')
    value = request.args.get('value')
    os.environ[variable] = value
    return "Variabile d'ambiente modificata"

if __name__ == '__main__':
    app.run(debug=True)
