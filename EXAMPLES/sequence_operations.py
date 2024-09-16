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

# Query per ottenere documenti con tecniche MITRE ATT&CK e almeno una delle operazioni sul registro
query = {
    "query": {
        "bool": {
            "must": [
                {"exists": {"field": "data.attributes.mitre_attack_techniques.id"}},
                {
                    "bool": {
                        "should": [
                            {"exists": {"field": "data.attributes.registry_keys_set"}},
                            {"exists": {"field": "data.attributes.registry_keys_deleted"}},
                            {"exists": {"field": "data.attributes.registry_keys_created"}}
                        ]
                    }
                }
            ]
        }
    },
    "_source": ["data.id", "data.attributes.mitre_attack_techniques.id", "data.attributes.registry_keys_set", "data.attributes.registry_keys_deleted", "data.attributes.registry_keys_created"]
}

# Esegui la query
response = es.search(index="malware_reports", body=query, size=10000)

# Raccogliere le sequenze di operazioni sul registro e le tecniche MITRE ATT&CK
sequences = []

for hit in response['hits']['hits']:
    data_list = hit['_source'].get('data', [])
    for data_item in data_list:
        techniques = data_item.get('attributes', {}).get('mitre_attack_techniques', [])
        registry_sets = data_item.get('attributes', {}).get('registry_keys_set', [])
        registry_deletes = data_item.get('attributes', {}).get('registry_keys_deleted', [])
        registry_creates = data_item.get('attributes', {}).get('registry_keys_created', [])
        
        for technique in techniques:
            technique_id = technique.get('id')
            if technique_id:
                sequence = {
                    "technique": technique_id,
                    "operations": []
                }
                for key in registry_sets:
                    sequence["operations"].append(f"SET {key}")
                for key in registry_deletes:
                    sequence["operations"].append(f"DELETE {key}")
                for key in registry_creates:
                    sequence["operations"].append(f"CREATE {key}")
                sequences.append(sequence)

# Salva le sequenze in un file JSON per ulteriori analisi
with open("mitre_technique_sequences.json", "w") as f:
    json.dump(sequences, f, indent=4)

# Analisi delle sequenze salvate
from collections import Counter

# Carica le sequenze salvate
with open("mitre_technique_sequences.json", "r") as f:
    sequences = json.load(f)

# Identifica le sequenze tipiche di operazioni sul registro
sequence_counter = Counter()

for sequence in sequences:
    seq_str = ' -> '.join(sequence["operations"])
    sequence_counter.update([seq_str])

# Filtra le sequenze che appaiono almeno 2 volte
common_sequences = {seq: count for seq, count in sequence_counter.items() if count >= 2}

# Stampa i risultati
print("Sequenze tipiche di operazioni sul registro:")
print(json.dumps(common_sequences, indent=4))

# Salva i risultati in un file
with open("common_registry_sequences.json", "w") as f:
    json.dump(common_sequences, f, indent=4)

# Visualizza le sequenze comuni
import matplotlib.pyplot as plt

# Carica le sequenze comuni salvate
with open("common_registry_sequences.json", "r") as f:
    common_sequences = json.load(f)

# Visualizza le sequenze comuni
sequences = list(common_sequences.keys())
counts = list(common_sequences.values())

plt.figure(figsize=(10, 8))
plt.barh(sequences, counts, color='skyblue')
plt.xlabel('Count')
plt.ylabel('Sequence')
plt.title('Common Registry Operation Sequences')
plt.show()
