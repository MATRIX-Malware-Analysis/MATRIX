from neo4j import GraphDatabase
from collections import defaultdict
import json
# Connessione a Neo4j
uri = "bolt://localhost:7688"
user = "neo4j"
password = "malware_profiler"

driver = GraphDatabase.driver(uri, auth=(user, password))

def extract_tactics(tx):
    query = """
    MATCH (b:MalwareBehavior)-[:related_to]->(i:MalwareObjective)
    RETURN b.external_references_0_external_id AS technique_id, i.name AS tactic_name
    """
    result = tx.run(query)
    technique_to_tactic = {}
    for record in result:
        technique_id = record["technique_id"]
        tactic_name = record["tactic_name"]
        technique_to_tactic[technique_id] = tactic_name
    return technique_to_tactic

with driver.session() as session:
    technique_to_tactic = session.read_transaction(extract_tactics)

print("Extracted Tactics:")
print(json.dumps(technique_to_tactic, indent=4))


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
tactic_to_registry_counter = defaultdict(Counter)

for hit in response['hits']['hits']:
    data_list = hit['_source'].get('data', [])
    for data_item in data_list:
        mitre_techniques = data_item.get('attributes', {}).get('mitre_attack_techniques', [])
        registry_keys_deleted = data_item.get('attributes', {}).get('registry_keys_deleted', [])
        
        for technique in mitre_techniques:
            technique_id = technique.get('id')
            tactic_name = technique_to_tactic.get(technique_id)
            if tactic_name:
                for registry_key in registry_keys_deleted:
                    key_str = registry_key #.get('key')  # Prendi solo la chiave del registro
                    if key_str:
                        main_key = key_str.split("\\")[0]  # Prendi solo la chiave principale
                        tactic_to_registry_counter[tactic_name].update([main_key])

# Calcolo delle percentuali
results = {}
for tactic, counter in tactic_to_registry_counter.items():
    total = sum(counter.values())
    percentages = {key: f"{(count / total) * 100:.2f}%" for key, count in counter.items()}
    results[tactic] = percentages

# Stampa i risultati
print("MITRE ATT&CK Tactics e Registry Keys correlati:")
print(json.dumps(results, indent=4))

# Salva i risultati in un file
with open("tactic_to_main_registry_deleted_correlations.json", "w") as f:
    json.dump(results, f, indent=4)
