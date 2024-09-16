import os
import yaml
import json
from collections import defaultdict

# Percorso alla directory contenente le regole Sigma
sigma_rules_dir = "/home/marcos/CyberGraphDB/CyberGraphDB/CAPEC/BUILDING_FOLDER/sigma/rules"

# Funzione per attraversare tutte le sottodirectory e file YAML
def parse_sigma_rules(directory):
    technique_commands = defaultdict(list)

    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".yml") or file.endswith(".yaml"):
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='utf-8') as f:
                    rule = yaml.safe_load(f)
                    
                    if 'tags' in rule:
                        for tag in rule['tags']:
                            if tag.startswith("attack.t"):
                                technique = tag.replace("attack.", "").replace(".", "/").replace("t", "T", 1)
                                if 'detection' in rule:
                                    detection = rule['detection']
                                    if 'selection' in detection:
                                        selection = detection['selection']
                                        if isinstance(selection, dict):
                                            for key, value in selection.items():
                                                if key in ["CommandLine|contains", "SourceImage|endswith", "TargetImage|endswith"]:
                                                    technique_commands[technique].append({
                                                        "rule": file_path,
                                                        "key": key,
                                                        "values": value
                                                    })

    return technique_commands

# Parsing delle regole Sigma
technique_commands = parse_sigma_rules(sigma_rules_dir)

# Creazione del file JSON con i comandi per ogni tecnica
output_file = "technique_commands_with_rules.json"
with open(output_file, 'w', encoding='utf-8') as f:
    json.dump(technique_commands, f, indent=4)

print(f"Results saved to {output_file}")
