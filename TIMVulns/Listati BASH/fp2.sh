#!/bin/bash

# Falso positivo: Deserializzazione di oggetti con firma digitale e whitelist (CVSS 3.1: 0.0 - Nessuno)
function safe_deserialize() {
  local serialized="$1"
  local signature=$(echo "$serialized" | cut -d':' -f2)
  local data=$(echo "$serialized" | cut -d':' -f1)
  local secret_key="my_secret_key"
  local expected_signature=$(echo "$data" | openssl dgst -sha256 -hmac "$secret_key" -binary | base64)
  if [[ "$signature" == "$expected_signature" ]]; then
    echo "$data" | base64 -d | jq -c '.data' # Supponiamo dati JSON
  else
    echo "Firma non valida."
  fi
}

serialized_data="eyJkYXRhIjogeyJ1c2VybmFtZSI6ICJ0ZXN0In19:$(echo '{"data": {"username": "test"}}' | openssl dgst -sha256 -hmac "my_secret_key" -binary | base64)"
safe_deserialize "$serialized_data"

# Falso positivo: Inclusione di file con sandbox e namespace virtuale (CVSS 3.1: 0.0 - Nessuno)
function safe_include() {
  local file="$1"
  local sanitized_file=$(echo "$file" | sed 's/[^a-zA-Z0-9_\-\.]//g')
  local full_path="/sandbox/pages/$sanitized_file.sh"
  if [[ -f "$full_path" ]]; then
    (
      export SANDBOX_VAR="safe_value"
      /usr/bin/env PATH=/bin bash "$full_path"
    )
  else
    echo "File non trovato."
  fi
}

safe_include "script.sh" # Supponiamo /sandbox/pages/script.sh esista

# Falso positivo: Esecuzione di comandi con parametri JSON e ambiente limitato (CVSS 3.1: 0.0 - Nessuno)
function safe_execute() {
  local command="$1"
  local params_json="$2"
  local allowed_commands=("ping" "traceroute")
  if [[ ! " ${allowed_commands[*]} " =~ " ${command} " ]]; then
    echo "Comando non consentito."
    return 1
  fi
  local params=$(echo "$params_json" | jq -r '.[]' | sed 's/\\/\\\\/g; s/"/\\"/g')
  /usr/bin/env PATH=/bin "$command" $params
}

safe_execute "ping" '["-c", "1", "127.0.0.1"]'

# Falso positivo: Manipolazione di file di configurazione con controllo di checksum (CVSS 3.1: 0.0 - Nessuno)
config_file="/tmp/config.ini"
echo "option1=value1" > "$config_file"
checksum=$(sha256sum "$config_file" | cut -d' ' -f1)
export CONFIG_CHECKSUM="$checksum"
source "$config_file"
if [[ "$(sha256sum "$config_file" | cut -d' ' -f1)" != "$CONFIG_CHECKSUM" ]]; then
  echo "File di configurazione modificato."
fi
echo "$option1"

# Falso positivo: Utilizzo di xmllint con validazione XSD e namespace limitato (CVSS 3.1: 0.0 - Nessuno)
xml_input="<root xmlns:safe='http://safe.namespace'><safe:element>data</safe:element></root>"
xsd_schema="<xs:schema xmlns:xs='http://www.w3.org/2001/XMLSchema' targetNamespace='http://safe.namespace'><xs:element name='element' type='xs:string'/></xs:schema>"
echo "$xsd_schema" > /tmp/schema.xsd
echo "$xml_input" | xmllint --noout --schema /tmp/schema.xsd -

# Falso positivo: Utilizzo di cronjob con ambiente limitato e parametri con hash (CVSS 3.1: 0.0 - Nessuno)
command="echo 'Hello, cron!'"
secret_key="cron_secret"
hash=$(echo "$command" | openssl dgst -sha256 -hmac "$secret_key" -binary | base64)
(crontab -l 2>/dev/null; echo "* * * * * if [[ \"\$(echo '$command' | openssl dgst -sha256 -hmac '$secret_key' -binary | base64)\" == '$hash' ]]; then $command; fi") | crontab -
