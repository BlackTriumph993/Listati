#!/bin/bash


echo "Inserisci un comando:"
read comando
$comando


echo "Inserisci un percorso di file:"
read percorso_file
cat $percorso_file


echo "Inserisci un pattern di file:"
read pattern_file
rm $pattern_file


temp_file=$(mktemp)
echo "Scrivi qualcosa nel file temporaneo:"
read input_temp
echo "$input_temp" > "$temp_file"
sleep 1 # Simulazione di un ritardo
cat "$temp_file"
rm "$temp_file"


echo "Inserisci un'espressione da valutare:"
read espressione
eval $espressione


env x='() { :;}; echo vulnerable' bash -c "echo this is a test"


export VAR_COMANDO="ls -l"
$VAR_COMANDO
