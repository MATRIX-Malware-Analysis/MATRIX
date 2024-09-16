from elasticsearch import Elasticsearch
from collections import Counter
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
        "exists": {
            "field": "data.attributes.mitre_attack_techniques.id"
        }
    },
    "_source": ["data.attributes.mitre_attack_techniques.id"]
}

response = es.search(index="malware_reports", body=query, size=10000)

registry_keys_counter = Counter()

for hit in response['hits']['hits']:
    data_list = hit['_source'].get('data', [])
    for data_item in data_list:
        attributes = data_item.get('attributes', {})
        registry_keys_set = attributes.get('mitre_attack_techniques', [])
        for registry_key in registry_keys_set:
            key = registry_key.get('id')
            if key and "ffffffffffffffffffffffffffffff" not in key:
                registry_keys_counter.update([key])

top_10_registry_keys_set = registry_keys_counter.most_common(10)

print(json.dumps(top_10_registry_keys_set, indent=4))
