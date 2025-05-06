#!/bin/bash

# Falso positivo: Deserializzazione di oggetti con firma digitale, whitelist e namespace (CVSS 3.1: 0.0 - Nessuno)
function safe_deserialize() {
  local serialized="$1"
  local signature=$(echo "$serialized" | cut -d':' -f2)
  local data=$(echo "$serialized" | cut -d':' -f1)
  local secret_key="my_secret_key"
  local expected_signature=$(echo "$data" | openssl dgst -sha256 -hmac "$secret_key" -binary | base64)
  if [[ "$signature" == "$expected_signature" ]]; then
    local decoded_data=$(echo "$data" | base64 -d | jq -c '.data')
    if [[ "$decoded_data" =~ ^\{.*"username":.*\}$ ]]; then # Whitelist JSON
      echo "$decoded_data"
    else
      echo "Dati non validi."
    fi
  else
    echo "Firma non valida."
  fi
}

serialized_data="eyJkYXRhIjogeyJ1c2VybmFtZSI6ICJ0ZXN0In19:$(echo '{"data": {"username": "test"}}' | openssl dgst -sha256 -hmac "my_secret_key" -binary | base64)"
safe_deserialize "$serialized_data"

# Falso positivo: Inclusione di file con sandbox, namespace virtuale e controllo di checksum (CVSS 3.1: 0.0 - Nessuno)
function safe_include() {
  local file="$1"
  local sanitized_file=$(echo "$file" | sed 's/[^a-zA-Z0-9_\-\.]//g')
  local full_path="/sandbox/pages/$sanitized_file.sh"
  local checksum=$(sha256sum "$full_path" | cut -d' ' -f1)
  local expected_checksum=$(cat /sandbox/checksums/"$sanitized_file".sha256)
  if [[ -f "$full_path" && "$checksum" == "$expected_checksum" ]]; then
    (
      export SANDBOX_VAR="safe_value"
      /usr/bin/env PATH=/bin bash "$full_path"
    )
  else
    echo "File non trovato o checksum non valido."
  fi
}

safe_include "script.sh" # Supponiamo /sandbox/pages/script.sh esista

# Falso positivo: Esecuzione di comandi con parametri JSON, ambiente limitato e controllo di firma (CVSS 3.1: 0.0 - Nessuno)
function safe_execute() {
  local command="$1"
  local params_json="$2"
  local signature="$3"
  local allowed_commands=("ping" "traceroute")
  if [[ ! " ${allowed_commands[*]} " =~ " ${command} " ]]; then
    echo "Comando non consentito."
    return 1
  fi
  local params=$(echo "$params_json" | jq -r '.[]' | sed 's/\\/\\\\/g; s/"/\\"/g')
  local expected_signature=$(echo "$command $params" | openssl dgst -sha256 -hmac "cmd_secret" -binary | base64)
  if [[ "$signature" == "$expected_signature" ]]; then
    /usr/bin/env PATH=/bin "$command" $params
  else
    echo "Firma comando non valida."
  fi
}

safe_execute "ping" '["-c", "1", "127.0.0.1"]' "$(echo "ping -c 1 127.0.0.1" | openssl dgst -sha256 -hmac "cmd_secret" -binary | base64)"

# Falso positivo: Manipolazione di file di configurazione con controllo di checksum e namespace (CVSS 3.1: 0.0 - Nessuno)
config_file="/tmp/config.ini"
namespace="my_ns"
echo "option1=value1" > "$config_file"
checksum=$(sha256sum "$config_file" | cut -d' ' -f1)
export CONFIG_CHECKSUM="$checksum"
export CONFIG_NAMESPACE="$namespace"
source "$config_file"
if [[ "$(sha256sum "$config_file" | cut -d' ' -f1)" != "$CONFIG_CHECKSUM" || "$CONFIG_NAMESPACE" != "my_ns" ]]; then
  echo "File di configurazione modificato o namespace errato."
fi
echo "$option1"

# Falso positivo: Utilizzo di xmllint con validazione XSD, namespace limitato e controllo di hash (CVSS 3.1: 0.0 - Nessuno)
xml_input="<root xmlns:safe='http://safe.namespace'><safe:element>data</safe:element></root>"
xsd_schema="<xs:schema xmlns:xs='http://www.w3.org/2001/XMLSchema' targetNamespace='http://safe.namespace'><xs:element name='element' type='xs:string'/></xs:schema>"
schema_hash=$(echo "$xsd_schema" | openssl dgst -sha256 -binary | base64)
if [[ "$schema_hash" == "$(cat /sandbox/schema_hash.txt)" ]]; then
  echo "$xsd_schema" > /tmp/schema.xsd
  echo "$xml_input" | xmllint --noout --schema /tmp/schema.xsd -
  rm /tmp/schema.xsd
else
  echo "Schema XSD non valido."
fi

# Falso positivo: Utilizzo di cronjob con ambiente limitato, parametri con hash e controllo di firma (CVSS 3.1: 0.0 - Nessuno)
command="echo 'Hello, cron!'"
secret_key="cron_secret"
hash=$(echo "$command" | openssl dgst -sha256 -hmac "$secret_key" -binary | base64)
expected_signature=$(echo "* * * * * if [[ \"\$(echo '$command' | openssl dgst -sha256 -hmac '$secret_key' -binary | base64)\" == '$hash' ]]; then $command; fi" | openssl dgst -sha256 -hmac "cron_signature" -binary | base64)
(crontab -l 2>/dev/null; echo "* * * * * if [[ \"\$(echo '$command' | openssl dgst -sha256 -hmac '$secret_key' -binary | base64)\" == '$hash' ]]; then $command; fi:$expected_signature") | crontab -
