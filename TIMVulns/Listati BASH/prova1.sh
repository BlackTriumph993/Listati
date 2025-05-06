#!/bin/bash

# Vulnerabilità di Iniezione di Comandi tramite Input dell'Utente (CVSS 3.1: 9.8 - Critico)
echo "Inserisci un comando:"
read comando
$comando

# Vulnerabilità di Path Traversal (CVSS 3.1: 7.5 - Alto)
echo "Inserisci un percorso di file:"
read percorso_file
cat $percorso_file

# Vulnerabilità di Espansione di Wildcard Non Sicura (CVSS 3.1: 8.8 - Alto)
echo "Inserisci un pattern di file:"
read pattern_file
rm $pattern_file

# Vulnerabilità di Race Condition (CVSS 3.1: 8.1 - Alto)
temp_file=$(mktemp)
echo "Scrivi qualcosa nel file temporaneo:"
read input_temp
echo "$input_temp" > "$temp_file"
sleep 1 # Simulazione di un ritardo
cat "$temp_file"
rm "$temp_file"

# Vulnerabilità di Utilizzo di eval() (CVSS 3.1: 9.8 - Critico)
echo "Inserisci un'espressione da valutare:"
read espressione
eval $espressione

# Vulnerabilità di Shellshock (CVSS 3.1: 10.0 - Critico, se presente)
env x='() { :;}; echo vulnerable' bash -c "echo this is a test"

# Vulnerabilità di Iniezione di Comandi tramite Variabili di Ambiente (CVSS 3.1: 9.8 - Critico)
export VAR_COMANDO="ls -l"
$VAR_COMANDO
