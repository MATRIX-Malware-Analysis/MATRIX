import os
import yaml
import json

base_dir = os.path.expanduser("~/CyberGraphDB/CyberGraphDB/CAPEC/BUILDING_FOLDER/capa-rules/")

attack_to_apis = {}

def process_rule(rule):
    attack_techniques = rule.get('meta', {}).get('att&ck', [])
    features = rule.get('features', [])
    
    apis = set()
    
    def extract_apis(feature):
        if isinstance(feature, dict):
            for key, value in feature.items():
                if key == 'api':
                    apis.add(value)
                elif key in ['and', 'or', 'optional']:
                    if isinstance(value, list):
                        for item in value:
                            extract_apis(item)
                elif isinstance(value, dict):
                    extract_apis(value)
        elif isinstance(feature, list):
            for item in feature:
                extract_apis(item)
    
    for feature in features:
        extract_apis(feature)
    
    for technique in attack_techniques:
        technique_name = technique.split('[')[-1].split(']')[0].strip()
        if "." in technique_name:
            technique_name = technique_name.replace(".", "/")
        if technique_name not in attack_to_apis:
            attack_to_apis[technique_name] = set()
        attack_to_apis[technique_name].update(apis)

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

final_attack_to_apis = {k: list(v) for k, v in attack_to_apis.items()}

output_filepath = os.path.expanduser("attack_to_apis.json")
with open(output_filepath, 'w') as json_file:
    json.dump(final_attack_to_apis, json_file, indent=4)

print(f"JSON creato con successo: {output_filepath}")
