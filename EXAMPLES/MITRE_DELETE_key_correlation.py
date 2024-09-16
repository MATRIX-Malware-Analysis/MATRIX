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

# Query per ottenere documenti con tecniche MITRE ATT&CK e modifiche al registro
query = {
    "query": {
        "bool": {
            "must": [
                {"exists": {"field": "data.attributes.mitre_attack_techniques.id"}},
                {"exists": {"field": "data.attributes.registry_keys_deleted"}},
            ]
        }
    },
    "_source": ["data.id", "data.attributes.mitre_attack_techniques.id", "data.attributes.registry_keys_deleted"]
}

# Esegui la query
response = es.search(index="malware_reports", body=query, size=10000)

# Analisi delle tecniche MITRE ATT&CK e operazioni sul registro
technique_to_registry_counter = defaultdict(Counter)

for hit in response['hits']['hits']:
    data_list = hit['_source'].get('data', [])
    for data_item in data_list:
        mitre_techniques = data_item.get('attributes', {}).get('mitre_attack_techniques', [])
        registry_keys_deleted = data_item.get('attributes', {}).get('registry_keys_deleted', [])
        
        for technique in mitre_techniques:
            technique_id = technique.get('id')
            if technique_id:
                for registry_key in registry_keys_deleted:
                    key_str = json.dumps(registry_key)  # Converti il dict in una stringa univoca
                    technique_to_registry_counter[technique_id].update([key_str])

# Calcolo delle percentuali
results = {}
for technique, counter in technique_to_registry_counter.items():
    total = sum(counter.values())
    percentages = {key: f"{(count / total) * 100:.2f}%" for key, count in counter.items()}
    results[technique] = percentages

# Stampa i risultati
print("MITRE ATT&CK Techniques e Registry correlati:")
print(json.dumps(results, indent=4))

# Salva i risultati in un file
with open("technique_to_registry_deleted_correlations.json", "w") as f:
    json.dump(results, f, indent=4)
