from elasticsearch import Elasticsearch
from collections import defaultdict, Counter
import json

# Connessione a Elasticsearch
es = Elasticsearch(
    hosts=[{
        'host': 'localhost',
        'port': 9200,
        'scheme': 'http'
    }]
)

# Query per ottenere documenti con tecniche MITRE ATT&CK e moduli caricati
query = {
    "query": {
        "bool": {
            "must": [
                {"exists": {"field": "data.attributes.mitre_attack_techniques.id"}},
                {"exists": {"field": "data.attributes.modules_loaded"}},
            ]
        }
    },
    "_source": ["data.id", "data.attributes.mitre_attack_techniques.id", "data.attributes.modules_loaded"]
}

# Esegui la query
response = es.search(index="malware_reports", body=query, size=10000)

# Analisi delle tecniche MITRE ATT&CK e moduli caricati
technique_to_modules_counter = defaultdict(Counter)

for hit in response['hits']['hits']:
    data_list = hit['_source'].get('data', [])
    for data_item in data_list:
        mitre_techniques = data_item.get('attributes', {}).get('mitre_attack_techniques', [])
        modules_loaded = data_item.get('attributes', {}).get('modules_loaded', [])
        
        for technique in mitre_techniques:
            technique_id = technique.get('id')
            if technique_id:
                for module in modules_loaded:
                    technique_to_modules_counter[technique_id].update([module])

# Calcolo delle percentuali
results = {}
for technique, counter in technique_to_modules_counter.items():
    total = sum(counter.values())
    percentages = {key: f"{(count / total) * 100:.2f}%" for key, count in counter.items()}
    results[technique] = percentages

# Stampa i risultati
print("MITRE ATT&CK Techniques e Modules Loaded correlati:")
print(json.dumps(results, indent=4))

# Salva i risultati in un file
with open("technique_to_modules_correlations.json", "w") as f:
    json.dump(results, f, indent=4)
