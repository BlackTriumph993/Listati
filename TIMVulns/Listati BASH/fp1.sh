#!/bin/bash

# Falso positivo: Utilizzo di eval() con input controllato (CVSS 3.1: 0.0 - Nessuno)
command="echo 'Hello, world!'"
eval "$command"

# Falso positivo: Inclusione di file con validazione rigorosa (CVSS 3.1: 0.0 - Nessuno)
file="test.txt"
if [[ "$file" =~ ^[a-zA-Z0-9_\-\.]+$ ]]; then
  cat "$file"
else
  echo "Nome file non valido."
fi

# Falso positivo: Esecuzione di comandi con parametri sanificati (CVSS 3.1: 0.0 - Nessuno)
command="ping"
params=("-c 1" "127.0.0.1")
sanitized_params=()
for param in "${params[@]}"; do
  sanitized_params+=("$(printf '%q' "$param")")
done
"$command" "${sanitized_params[@]}"

# Falso positivo: Utilizzo di variabili di ambiente per configurazione (CVSS 3.1: 0.0 - Nessuno)
config_dir="/tmp/config"
mkdir -p "$config_dir"
echo "option1=value1" > "$config_dir/config.ini"
export CONFIG_FILE="$config_dir/config.ini"
source "$CONFIG_FILE"
echo "$option1"

# Falso positivo: Espansione di wildcard con controllo di esistenza file (CVSS 3.1: 0.0 - Nessuno)
pattern="*.txt"
for file in $pattern; do
  if [[ -f "$file" ]]; then
    cat "$file"
  fi
done

# Falso positivo: Utilizzo di xmllint con input validato (CVSS 3.1: 0.0 - Nessuno)
xml_input="<root><element>data</element></root>"
if [[ "$xml_input" =~ ^\<root\>\<element\>.*\</element\>\</root\>$ ]]; then
  echo "$xml_input" | xmllint --noout -
else
  echo "Input XML non valido."
fi

# Falso positivo: Utilizzo di cronjob con comando limitato (CVSS 3.1: 0.0 - Nessuno)
(crontab -l 2>/dev/null; echo "* * * * * echo 'Hello, cron!'") | crontab -
