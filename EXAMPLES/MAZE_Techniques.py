from elasticsearch import Elasticsearch
from collections import Counter
import json
from neo4j import GraphDatabase
from tqdm import tqdm
import matplotlib.pyplot as plt

uri = "bolt://localhost:7688"
user = "neo4j"
password = "malware_profiler"

driver = GraphDatabase.driver(uri, auth=(user, password))

def extract_indicators(tx):
    query = """
    MATCH (m:Malware)<-[:indicates]-(b:Indicator)
    WHERE toLower(m.name) CONTAINS 'Lucifer'
    RETURN m.name AS malware, b.pattern AS PATTERN
    """
    result = tx.run(query)
    patterns = []
    for record in tqdm(result, desc="Retrieving Malware and Indicators ..."):
        pattern = record["PATTERN"]
        patterns.append(pattern)
    return patterns

with driver.session() as session:
    patterns = session.read_transaction(extract_indicators)

HASHES = [pattern.split('= ', 1)[1].replace(" ]", '').replace("'", "") for pattern in patterns]

es = Elasticsearch(
    hosts=[{
        'host': 'localhost',
        'port': 9200,
        'scheme': 'http'
    }]
)

query = {
    "query": {
        "match_all": {}
    },
    "_source": ["data.id", "data.attributes.mitre_attack_techniques.id"]
}

response = es.search(index="malware_reports", body=query, size=10000)

mitre_techniques_counter = Counter()

for hit in response['hits']['hits']:
    data_list = hit['_source'].get('data', [])
    for data_item in data_list:
        attributes = data_item.get('id', "")
        id = attributes.split("_")[0]
        if id in HASHES:
            mitre_techniques = data_item.get('attributes', {}).get('mitre_attack_techniques', [])
            for technique in mitre_techniques:
                technique_id = technique.get('id')
                if technique_id:
                    mitre_techniques_counter.update([technique_id])

top_10_mitre_techniques = mitre_techniques_counter.most_common(100)

print(json.dumps(top_10_mitre_techniques, indent=4))

with open("MITRE_MAZE.txt", "w") as f:
    f.write(json.dumps(top_10_mitre_techniques, indent=4))

def get_techniques(tx):
    query = """
    MATCH (m:Malware)-[:uses]->(b:MalwareBehavior)
    WHERE toLower(m.name) CONTAINS 'amadey'
    RETURN m.name AS malware, b.external_references_0_external_id AS Behavior
    """
    result = tx.run(query)
    behaviors = []
    for record in tqdm(result, desc="Retrieving Malware and Indicators ..."):
        behavior = record["Behavior"]
        behaviors.append(behavior)
    return behaviors

with driver.session() as session:
    behaviors = session.read_transaction(get_techniques)

mitre_official_techniques = behaviors
official_technique_counts = Counter(mitre_official_techniques)
total_official_counts = sum(official_technique_counts.values())
official_technique_importance = {technique: count / total_official_counts for technique, count in official_technique_counts.items()}

extracted_techniques_counts = Counter({technique: count for technique, count in top_10_mitre_techniques})
total_extracted_counts = sum(extracted_techniques_counts.values())
extracted_technique_importance = {technique: count / total_extracted_counts for technique, count in extracted_techniques_counts.items()}

extracted_techniques = [technique for technique in extracted_techniques_counts]
missing_techniques = set(mitre_official_techniques) - set(extracted_techniques)
additional_techniques = set(extracted_techniques) - set(mitre_official_techniques)

print("Techniche MITRE ATT&CK mancanti:", missing_techniques)
print("Techniche MITRE ATT&CK aggiuntive:", additional_techniques)

fig, ax = plt.subplots(figsize=(12, 8))

extracted_techniques_sorted = sorted(extracted_technique_importance.items(), key=lambda x: x[1], reverse=True)
techniques, importance = zip(*extracted_techniques_sorted)
ax.barh(techniques, importance, color='skyblue', label='Estratto dai rapporti')

official_importance_sorted = [official_technique_importance.get(technique, 0) for technique in techniques]
ax.barh(techniques, official_importance_sorted, color='orange', alpha=0.5, label='MITRE ufficiali')

ax.set_xlabel('Importanza')
ax.set_title('Importanza delle Tecniche MITRE ATT&CK: Estratte dai Rapporti vs Ufficiali')
ax.legend()
plt.gca().invert_yaxis()
plt.tight_layout()

plt.savefig("MITRE_Techniques_Importance_Comparison.png")

plt.show()

comparison_data = {
    "extracted_techniques": extracted_techniques_sorted,
    "official_importance": official_importance_sorted
}

with open("MITRE_Techniques_Comparison.json", "w") as f:
    json.dump(comparison_data, f, indent=4)
