from elasticsearch import Elasticsearch
from collections import defaultdict, Counter
import json
import networkx as nx
from neo4j import GraphDatabase
import matplotlib.pyplot as plt

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

technique_sequences = []

for hit in response['hits']['hits']:
    data_list = hit['_source'].get('data', [])
    for data_item in data_list:
        techniques = data_item.get('attributes', {}).get('mitre_attack_techniques', [])
        technique_sequence = [technique.get('id') for technique in techniques if technique.get('id')]
        if technique_sequence:
            technique_sequences.append(technique_sequence)

with open("technique_sequences.json", "w") as f:
    json.dump(technique_sequences, f, indent=4)

with open("technique_sequences.json", "r") as f:
    technique_sequences = json.load(f)

co_occurrence_matrix = defaultdict(lambda: defaultdict(int))

for sequence in technique_sequences:
    for i in range(len(sequence)):
        for j in range(i + 1, len(sequence)):
            co_occurrence_matrix[sequence[i]][sequence[j]] += 1
            co_occurrence_matrix[sequence[j]][sequence[i]] += 1

with open("co_occurrence_matrix.json", "w") as f:
    json.dump(co_occurrence_matrix, f, indent=4)

threshold = 5

rare_combinations = []
for tech1, co_occurrences in co_occurrence_matrix.items():
    for tech2, count in co_occurrences.items():
        if count < threshold:
            rare_combinations.append((tech1, tech2, count))

with open("rare_combinations.json", "w") as f:
    json.dump(rare_combinations, f, indent=4)

print("Rare combinations of MITRE ATT&CK techniques:")
print(json.dumps(rare_combinations, indent=4))

tech1_list, tech2_list, count_list = zip(*rare_combinations)
plt.figure(figsize=(12, 8))
plt.scatter(tech1_list, tech2_list, s=[count*10 for count in count_list], c='red', alpha=0.5)
plt.xlabel('Technique 1')
plt.ylabel('Technique 2')
plt.title('Rare Combinations of MITRE ATT&CK Techniques')
plt.xticks(rotation=90)
plt.show()

uri = "bolt://localhost:7688"
user = "neo4j"
password = "malware_profiler"
driver = GraphDatabase.driver(uri, auth=(user, password))

def extract_behaviors(tx):
    query = """
    MATCH (m:Malware)-[:uses]->(b:MalwareBehavior)
    RETURN m.name AS malware, b.external_references_0_external_id AS behavior_id
    """
    result = tx.run(query)
    behaviors = defaultdict(list)
    for record in result:
        malware = record["malware"]
        behavior_id = record["behavior_id"]
        behaviors[malware].append(behavior_id)
    return behaviors

with driver.session() as session:
    behaviors = session.read_transaction(extract_behaviors)

behavior_co_occurrence_matrix = defaultdict(lambda: defaultdict(int))

for malware, behavior_sequence in behaviors.items():
    for i in range(len(behavior_sequence)):
        for j in range(i + 1, len(behavior_sequence)):
            behavior_co_occurrence_matrix[behavior_sequence[i]][behavior_sequence[j]] += 1
            behavior_co_occurrence_matrix[behavior_sequence[j]][behavior_sequence[i]] += 1

with open("behavior_co_occurrence_matrix.json", "w") as f:
    json.dump(behavior_co_occurrence_matrix, f, indent=4)

rare_behavior_combinations = []
for beh1, co_occurrences in behavior_co_occurrence_matrix.items():
    for beh2, count in co_occurrences.items():
        if count < threshold:
            rare_behavior_combinations.append((beh1, beh2, count))

with open("rare_behavior_combinations.json", "w") as f:
    json.dump(rare_behavior_combinations, f, indent=4)

print("Rare combinations of Malware Behaviors:")
print(json.dumps(rare_behavior_combinations, indent=4))

common_rare_combinations = set(rare_combinations).intersection(set(rare_behavior_combinations))

with open("common_rare_combinations.json", "w") as f:
    json.dump(list(common_rare_combinations), f, indent=4)

print("Common rare combinations between MITRE ATT&CK techniques and Malware Behaviors:")
print(json.dumps(list(common_rare_combinations), indent=4))
