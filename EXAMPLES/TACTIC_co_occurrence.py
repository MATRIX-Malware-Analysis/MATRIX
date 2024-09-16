from neo4j import GraphDatabase
from collections import defaultdict, Counter
import json

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
from collections import defaultdict
import json

es = Elasticsearch(
    hosts=[{
        'host': 'localhost',
        'port': 9200,
        'scheme': 'http'
    }]
)

query = {
    "query": {
        "exists": {"field": "data.attributes.mitre_attack_techniques.id"}
    },
    "_source": ["data.id", "data.attributes.mitre_attack_techniques.id"]
}

response = es.search(index="malware_reports", body=query, size=10000)

tactic_sequences = []

for hit in response['hits']['hits']:
    data_list = hit['_source'].get('data', [])
    for data_item in data_list:
        techniques = data_item.get('attributes', {}).get('mitre_attack_techniques', [])
        tactic_sequence = [technique_to_tactic.get(technique.get('id')) for technique in techniques if technique.get('id') in technique_to_tactic]
        if tactic_sequence:
            tactic_sequences.append(tactic_sequence)

co_occurrence_matrix = defaultdict(lambda: defaultdict(int))

for sequence in tactic_sequences:
    for i in range(len(sequence)):
        for j in range(i + 1, len(sequence)):
            co_occurrence_matrix[sequence[i]][sequence[j]] += 1
            co_occurrence_matrix[sequence[j]][sequence[i]] += 1

results = {}

for tactic, co_occurrences in co_occurrence_matrix.items():
    total = sum(co_occurrences.values())
    percentages = {key: (count / total) * 100 for key, count in co_occurrences.items()}
    sorted_percentages = dict(sorted(percentages.items(), key=lambda item: item[1], reverse=True))
    results[tactic] = sorted_percentages

print("MITRE ATT&CK Tactics e Tactics correlati:")
print(json.dumps(results, indent=4))

with open("tactic_to_tactic_correlations.json", "w") as f:
    json.dump(results, f, indent=4)
