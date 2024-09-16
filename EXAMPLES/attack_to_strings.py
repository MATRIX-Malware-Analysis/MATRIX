import os
import yaml
import json

# Directory principale contenente le capa-rules
base_dir = os.path.expanduser("~/CyberGraphDB/CyberGraphDB/CAPEC/BUILDING_FOLDER/capa-rules/")

# Dizionario per contenere le associazioni ATT&CK -> Strings
attack_to_strings = {}

# Funzione per estrarre tecniche ATT&CK e stringhe da una capa-rule
def process_rule(rule):
    attack_techniques = rule.get('meta', {}).get('att&ck', [])
    features = rule.get('features', [])
    
    strings = set()
    
    def extract_strings(feature):
        if isinstance(feature, dict):
            for key, value in feature.items():
                if key == 'string':
                    strings.add(value)
                elif key in ['and', 'or', 'optional']:
                    if isinstance(value, list):
                        for item in value:
                            extract_strings(item)
                elif isinstance(value, dict):
                    extract_strings(value)
        elif isinstance(feature, list):
            for item in feature:
                extract_strings(item)
    
    for feature in features:
        extract_strings(feature)
    
    for technique in attack_techniques:
        technique_name = technique.split('[')[-1].split(']')[0].strip()
        if "." in technique_name:
            technique_name = technique_name.replace(".", "/")
        if technique_name not in attack_to_strings:
            attack_to_strings[technique_name] = set()
        attack_to_strings[technique_name].update(strings)

# Legge ricorsivamente tutti i file YAML nelle sottodirectory di base_dir
for root, dirs, files in os.walk(base_dir):
    for filename in files:
        if filename.endswith(".yml") or filename.endswith(".yaml"):
            filepath = os.path.join(root, filename)
            with open(filepath, 'r') as file:
                try:
                    rule = yaml.safe_load(file)
                    if 'rule' in rule:
                        process_rule(rule['rule'])
                except yaml.YAMLError as e:
                    print(f"Errore nel leggere il file {filepath}: {e}")

# Convertire i set di stringhe in liste e preparare il dizionario finale
final_attack_to_strings = {k: list(v) for k, v in attack_to_strings.items()}

# Scrivere il dizionario in un file JSON
output_filepath = os.path.expanduser("attack_to_strings.json")
with open(output_filepath, 'w') as json_file:
    json.dump(final_attack_to_strings, json_file, indent=4)

print(f"JSON creato con successo: {output_filepath}")
