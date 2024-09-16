from neo4j import GraphDatabase
from collections import defaultdict, Counter
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

# Query per ottenere documenti con tecniche MITRE ATT&CK e file aperti
query = {
    "query": {
        "bool": {
            "must": [
                {"exists": {"field": "data.attributes.mitre_attack_techniques.id"}},
                {"exists": {"field": "data.attributes.files_opened"}},
            ]
        }
    },
    "_source": ["data.id", "data.attributes.mitre_attack_techniques.id", "data.attributes.files_opened"]
}

# Esegui la query
response = es.search(index="malware_reports", body=query, size=10000)

# Analisi delle tattiche MITRE ATT&CK e file aperti
tactic_to_files_counter = defaultdict(Counter)

for hit in response['hits']['hits']:
    data_list = hit['_source'].get('data', [])
    for data_item in data_list:
        mitre_techniques = data_item.get('attributes', {}).get('mitre_attack_techniques', [])
        files_opened = data_item.get('attributes', {}).get('files_opened', [])
        
        for technique in mitre_techniques:
            technique_id = technique.get('id')
            tactic_name = technique_to_tactic.get(technique_id)
            if tactic_name:
                for file in files_opened:
                    tactic_to_files_counter[tactic_name].update([file])

# Calcolo delle percentuali
results = {}
for tactic, counter in tactic_to_files_counter.items():
    total = sum(counter.values())
    percentages = {key: f"{(count / total) * 100:.2f}%" for key, count in counter.items()}
    results[tactic] = percentages

# Stampa i risultati
print("MITRE ATT&CK Tactics e Files Opened correlati:")
print(json.dumps(results, indent=4))

# Salva i risultati in un file
with open("tactic_to_files_opened_correlations.json", "w") as f:
    json.dump(results, f, indent=4)
