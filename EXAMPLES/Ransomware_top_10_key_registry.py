from elasticsearch import Elasticsearch
from collections import Counter
import json
from neo4j import GraphDatabase
from tqdm import tqdm

uri = "bolt://localhost:7688"
user = "neo4j"
password = "malware_profiler"

driver = GraphDatabase.driver(uri, auth=(user, password))

def extract_indicators(tx):
    query = """
    MATCH (m:Malware)<-[:indicates]-(b:Indicator)
    WHERE toLower(m.description) CONTAINS 'spy'
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
        "exists": {
            "field": "data.attributes.registry_keys_set"
        }
    },
    "_source": ["data.id", "data.attributes.registry_keys_set"]
}

response = es.search(index="malware_reports", body=query, size=10000)

registry_keys_counter = Counter()

for hit in response['hits']['hits']:
    data_list = hit['_source'].get('data', [])
    for data_item in data_list:
        attributes = data_item.get('id', "")
        id = attributes.split("_")[0]
        if id in HASHES:
            registry_keys_set = data_item.get('attributes', {}).get('registry_keys_set', [])
            for registry_key in registry_keys_set:
                key = registry_key.get('key')
                if key and "ffffffffffffffffffffffffffffff" not in key:
                    registry_keys_counter.update([key])

top_10_registry_keys_set = registry_keys_counter.most_common(10)

print(json.dumps(top_10_registry_keys_set, indent=4))

with open('Top_10_Spyware_set_Registry.txt', 'w') as f:
    f.write(json.dumps(top_10_registry_keys_set, indent=4))
