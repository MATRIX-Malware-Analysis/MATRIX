from elasticsearch import Elasticsearch
from collections import Counter
import json

# Connessione a Elasticsearch
es = Elasticsearch(
    hosts=[{
        'host': 'localhost',
        'port': 9200,
        'scheme': 'http'
    }]
)

# Query per ottenere alcuni documenti per verifica
query = {
    "query": {
        "exists": {
            "field": "data.attributes.registry_keys_opened"
        }
    },
    "_source": ["data.attributes.registry_keys_opened"]
}

# Esegui la query
response = es.search(index="malware_reports", body=query, size=10000)

# Conta le occorrenze di ogni chiave di registro impostata
registry_keys_counter = Counter()

for hit in response['hits']['hits']:
    data_list = hit['_source'].get('data', [])
    for data_item in data_list:
        attributes = data_item.get('attributes', {})
        registry_keys_set = attributes.get('registry_keys_opened', [])
        for registry_key in registry_keys_set:
            key = registry_key #.get('key')
            if key and "ffffffffffffffffffffffffffffff" not in key:
                registry_keys_counter.update([key])

# Ottieni le top 10 chiavi di registro impostate
top_10_registry_keys_set = registry_keys_counter.most_common(10)

# Stampa i risultati
print(json.dumps(top_10_registry_keys_set, indent=4))
