from elasticsearch import Elasticsearch
from collections import defaultdict, Counter
from tqdm import tqdm
from neo4j import GraphDatabase
from sklearn.metrics import jaccard_score
import json

uri = "bolt://localhost:7688"
user = "neo4j"
password = "malware_profiler"
driver = GraphDatabase.driver(uri, auth=(user, password))

def extract_indicators(tx):
    query = """
    MATCH (m:Malware)<-[:indicates]-(b:Indicator)
    WHERE toLower(m.description) CONTAINS 'emotet'
    RETURN m.name AS malware, b.pattern AS PATTERN
    """
    result = tx.run(query)
    patterns = []
    for record in tqdm(result, desc="Retrieving Malware and Indicators ..."):
        pattern = record["PATTERN"]
        patterns.append(pattern)
    return patterns

with driver.session() as session:
    patterns = session.execute_read(extract_indicators)

HASHES = [pattern.split('= ', 1)[1].replace(" ]", '').replace("'", "") for pattern in tqdm(patterns, desc='Extract Hashes ...')]

es = Elasticsearch(
    hosts=[{
        'host': 'localhost',
        'port': 9200,
        'scheme': 'http'
    }]
)

query = {
    "query": {
        "bool": {
            "must": [
                {"exists": {"field": "data.attributes.mitre_attack_techniques.id"}},
                {"exists": {"field": "data.attributes.calls_highlighted"}}
            ]
        }
    },
    "_source": ["data.id", "data.attributes.mitre_attack_techniques.id", "data.attributes.calls_highlighted"]
}

response = es.search(index="malware_reports", body=query, size=10000)

hash_to_calls = {}

print(f"Total number of Results -> {len(response['hits']['hits'])}")
for hit in response['hits']['hits']:
    data_list = hit['_source'].get('data', [])
    for data_item in data_list:
        if '_CAPE Sandbox' in data_item.get('id', ""):
            doc_id = data_item.get('id', "").split("_")[0]  # Estrarre l'ID del documento
            if doc_id in HASHES:
                print(data_item)
                calls_highlighted = data_item.get('attributes', {}).get('calls_highlighted', [])
                if calls_highlighted:
                    hash_to_calls[doc_id] = set(calls_highlighted)  # Usare set per la similarità

def jaccard_similarity(set1, set2):
    if not set1 and not set2:
        return 1.0  # Se entrambi gli insiemi sono vuoti, sono identici
    return len(set1.intersection(set2)) / len(set1.union(set2))

hash_pairs_similarity = []
hashes = list(hash_to_calls.keys())

for i in range(len(hashes)):
    for j in range(i + 1, len(hashes)):
        hash1, hash2 = hashes[i], hashes[j]
        calls1, calls2 = hash_to_calls[hash1], hash_to_calls[hash2]
        similarity = jaccard_similarity(calls1, calls2)
        common_calls = calls1.intersection(calls2)
        hash_pairs_similarity.append((hash1, hash2, similarity, common_calls))

hash_pairs_similarity.sort(key=lambda x: x[2], reverse=True)

print("Top 10 most similar hash pairs based on calls_highlighted:")
for hash1, hash2, similarity, common_calls in hash_pairs_similarity[:10]:
    print(f"{hash1} - {hash2}: Similarity = {similarity:.2f}")
    print(f"Common calls_highlighted: {common_calls}\n")

results = []
for hash1, hash2, similarity, common_calls in hash_pairs_similarity:
    results.append({
        "hash1": hash1,
        "hash2": hash2,
        "similarity": similarity,
        "common_calls": list(common_calls)
    })

with open("emotet_hash_pairs_similarity_with_calls.json", "w") as f:
    json.dump(results, f, indent=4)
